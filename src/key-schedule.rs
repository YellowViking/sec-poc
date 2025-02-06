use crate::enc_dec::TlsEncryptDecrypt;
use log::{debug, info};
use ring::agreement::EphemeralPrivateKey;
use ring::digest::SHA256;
use ring::hkdf;
use ring::hkdf::Salt;

pub(crate) struct HkdfLabel<'a> {
    length: u16,
    label: &'a str,
    context: &'a [u8],
}
impl<'a> HkdfLabel<'a> {
    pub fn new(length: u16, label: &'a str, context: &'a [u8]) -> Self {
        Self {
            length,
            label,
            context,
        }
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let tls13_label = format!("tls13 {}", self.label);
        bytes.extend_from_slice(&self.length.to_be_bytes());
        bytes.push(tls13_label.len() as u8);
        bytes.extend_from_slice(tls13_label.as_bytes());
        bytes.push(self.context.len() as u8);
        bytes.extend_from_slice(self.context);
        bytes
    }
}
pub(crate) struct HKDF {
    prk: hkdf::Prk,
}
struct CustomKeyType(usize);
impl hkdf::KeyType for CustomKeyType {
    fn len(&self) -> usize {
        self.0
    }
}

impl HKDF {
    pub fn extract(shared_secret: &[u8], salt: &[u8]) -> Self {
        debug!(
            "extract shared_secret: {:02X?}, salt: {:02X?}",
            shared_secret, salt
        );
        let salt = Salt::new(hkdf::HKDF_SHA256, salt);
        let prk = salt.extract(shared_secret);
        Self { prk }
    }

    pub fn new(secret: &[u8]) -> Self {
        debug!("new secret: {:02X?}", secret);
        let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret);
        Self { prk }
    }
    pub fn expand_label(&self, label: &HkdfLabel) -> anyhow::Result<Vec<u8>> {
        let mut output_keymaterial = vec![0u8; label.length as usize];
        let label = label.to_bytes();
        let info = vec![label.as_slice()];
        let hkdf = self
            .prk
            .expand(&info, CustomKeyType(output_keymaterial.len()))
            .map_err(|e| anyhow::anyhow!("expand failed: {:?}", e))?;
        hkdf.fill(&mut output_keymaterial)
            .map_err(|e| anyhow::anyhow!("fill failed: {:?}", e))?;
        debug!(
            "expand_label -> {:02X?} for label: {:02X?} context: {:02X?}",
            output_keymaterial, label, info
        );
        Ok(output_keymaterial)
    }

    pub fn derive_empty_secret() -> anyhow::Result<Vec<u8>> {
        let hkdf = HKDF::extract(&[0u8; 32], &[0u8; 32]);
        let empty_hash = ring::digest::digest(&SHA256, b"");
        debug!("empty_hash: {:02X?}", empty_hash);
        let label = HkdfLabel::new(32, "derived", empty_hash.as_ref());
        hkdf.expand_label(&label)
    }

    pub fn derive_master_secret(handshake_secret: &[u8]) -> anyhow::Result<Vec<u8>> {
        let hkdf = HKDF::extract(handshake_secret, &[0u8; 32]);
        let transcript_hash = ring::digest::digest(&SHA256, b"");
        let label = HkdfLabel::new(32, "derived", transcript_hash.as_ref());
        hkdf.expand_label(&label)
    }
}

pub(crate) struct ApplicationKeySchedule {
    pub(crate) server_application_traffic_secret: Vec<u8>,
    pub(crate) client_application_traffic_secret: Vec<u8>,
    pub(crate) server_write_key: Vec<u8>,
    pub(crate) server_write_iv: Vec<u8>,
    pub(crate) client_write_key: Vec<u8>,
    pub(crate) client_write_iv: Vec<u8>,
    pub(crate) transcript_hash_context: ring::digest::Context,
    pub(crate) read_seq_num: u64,
    pub(crate) write_seq_num: u64,
}

pub(crate) struct HandshakeKeySchedule {
    pub(crate) transcript_hash_context: ring::digest::Context,
    handshake_secret: Vec<u8>,
    master_secret: HKDF,
    server_handshake_traffic_secret: Vec<u8>,
    pub(crate) client_handshake_traffic_secret: Vec<u8>,
    pub(crate) client_write_key: Vec<u8>,
    pub(crate) client_write_iv: Vec<u8>,
    pub(crate) server_write_key: Vec<u8>,
    pub(crate) server_write_iv: Vec<u8>,
    my_private_key: Option<EphemeralPrivateKey>,
    my_public_key: ring::agreement::PublicKey,
    server_application_traffic_secret: Vec<u8>,
    client_application_traffic_secret: Vec<u8>,
    pub(crate) read_seq_num: u64,
    pub(crate) write_seq_num: u64,
}

impl HandshakeKeySchedule {
    pub fn into_application_key_schedule(self) -> anyhow::Result<ApplicationKeySchedule> {
        let hkdf_for_app_write = HKDF::new(self.client_application_traffic_secret.as_ref());
        let app_write_key = hkdf_for_app_write.expand_label(&HkdfLabel::new(16, "key", b""))?;
        let app_write_iv = hkdf_for_app_write.expand_label(&HkdfLabel::new(12, "iv", b""))?;
        let hkdf_for_app_read = HKDF::new(self.server_application_traffic_secret.as_ref());
        let app_read_key = hkdf_for_app_read.expand_label(&HkdfLabel::new(16, "key", b""))?;
        let app_read_iv = hkdf_for_app_read.expand_label(&HkdfLabel::new(12, "iv", b""))?;
        info!(
            "\napp_write_key: {:02X?}\
             \napp_write_iv: {:02X?}\
             \napp_read_key: {:02X?}\
             \napp_read_iv: {:02X?}",
            app_write_key, app_write_iv, app_read_key, app_read_iv
        );
        Ok(ApplicationKeySchedule {
            server_application_traffic_secret: self.server_application_traffic_secret,
            client_application_traffic_secret: self.client_application_traffic_secret,
            server_write_key: app_read_key,
            server_write_iv: app_read_iv,
            client_write_key: app_write_key,
            client_write_iv: app_write_iv,
            transcript_hash_context: self.transcript_hash_context,
            read_seq_num: 0,
            write_seq_num: 0,
        })
    }

    pub fn new() -> anyhow::Result<Self> {
        let transcript_hash_context = ring::digest::Context::new(&ring::digest::SHA256);
        let handshake_secret = Vec::new();
        let server_handshake_traffic_secret = Vec::new();
        let rng = ring::rand::SystemRandom::new();
        let my_private_key = EphemeralPrivateKey::generate(&ring::agreement::X25519, &rng)
            .map_err(|e| anyhow::anyhow!("generate failed: {:?}", e))?;
        let my_public_key = my_private_key
            .compute_public_key()
            .map_err(|e| anyhow::anyhow!("compute_public_key failed: {:?}", e))?;
        Ok(Self {
            transcript_hash_context,
            handshake_secret,
            server_handshake_traffic_secret,
            my_private_key: Some(my_private_key),
            my_public_key,
            server_write_key: Vec::new(),
            server_write_iv: Vec::new(),
            master_secret: HKDF::extract(&[0u8; 32], &[0u8; 32]),
            server_application_traffic_secret: Vec::new(),
            client_application_traffic_secret: Vec::new(),
            client_handshake_traffic_secret: Vec::new(),
            client_write_key: Vec::new(),
            client_write_iv: Vec::new(),
            read_seq_num: 0,
            write_seq_num: 0,
        })
    }
    pub fn update_handshake_secret(&mut self, server_pub: &[u8]) -> anyhow::Result<()> {
        let public_key =
            ring::agreement::UnparsedPublicKey::new(&ring::agreement::X25519, server_pub);
        ring::agreement::agree_ephemeral(
            self.my_private_key.take().unwrap(),
            &public_key,
            |key_material| {
                self.handshake_secret.extend_from_slice(key_material);
            },
        )
        .map_err(|e| anyhow::anyhow!("agree_ephemeral failed: {:?}", e))?;
        info!("handshake_secret: {:02X?}", self.handshake_secret);
        self.derive_server_handshake_traffic_secret()?;
        self.derive_client_handshake_traffic_secret()?;
        self.derive_server_write_key_and_iv()?;
        self.derive_client_write_key_and_iv()?;
        Ok(())
    }

    pub fn get_client_public_key(&self) -> Vec<u8> {
        Vec::from(self.my_public_key.as_ref())
    }

    pub fn on_server_finished(&mut self) -> anyhow::Result<()> {
        info!("on_finished, start derive_master_secret_and_traffic_secrets");
        self.derive_master_secret_and_traffic_secrets()
    }
    fn derive_master_secret_and_traffic_secrets(&mut self) -> anyhow::Result<()> {
        let empty_hash = ring::digest::digest(&SHA256, b"");
        let derived_secret = self
            .master_secret
            .expand_label(&HkdfLabel::new(32, "derived", empty_hash.as_ref()))?;
        let transcript_hash = self.transcript_hash_context.clone().finish();
        debug!(
            "\nderived_secret: {:02X?}\
             \ntranscript_hash: {:02X?}",
            derived_secret, transcript_hash.as_ref()
        );
        let hkdf = HKDF::extract([0u8; 32].as_ref(), derived_secret.as_ref());
        let label_server = HkdfLabel::new(32, "s ap traffic", transcript_hash.as_ref());
        self.server_application_traffic_secret = hkdf.expand_label(&label_server)?;
        let label_client = HkdfLabel::new(32, "c ap traffic", transcript_hash.as_ref());
        self.client_application_traffic_secret = hkdf.expand_label(&label_client)?;
        self.master_secret = hkdf;
        debug!(
            "\nserver_application_traffic_secret: {:02X?}\
             \nclient_application_traffic_secret: {:02X?}",
            self.server_application_traffic_secret, self.client_application_traffic_secret
        );
        Ok(())
    }

    fn derive_server_handshake_traffic_secret(&mut self) -> anyhow::Result<()> {
        let shared_secret = &self.handshake_secret;
        let salt = HKDF::derive_empty_secret()?;
        let hkdf = HKDF::extract(shared_secret, &salt);
        let digest = self.transcript_hash_context.clone().finish();
        let label = HkdfLabel::new(32, "s hs traffic", digest.as_ref());
        self.server_handshake_traffic_secret = hkdf.expand_label(&label)?;
        self.master_secret = hkdf;
        debug!(
            "\nserver_handshake_traffic_secret: {:02X?}\
             \nderived from shared_secret: {:02X?}\
             \nsalt: {:02X?}",
            self.server_handshake_traffic_secret, shared_secret, salt
        );
        Ok(())
    }

    fn derive_client_handshake_traffic_secret(&mut self) -> anyhow::Result<()> {
        let shared_secret = &self.handshake_secret;
        let salt = HKDF::derive_empty_secret()?;
        let hkdf = HKDF::extract(shared_secret, &salt);
        let digest = self.transcript_hash_context.clone().finish();
        let label = HkdfLabel::new(32, "c hs traffic", digest.as_ref());
        self.client_handshake_traffic_secret = hkdf.expand_label(&label)?;
        debug!(
            "\nclient_handshake_traffic_secret: {:02X?}\
             \nderived from shared_secret: {:02X?}\
             \nsalt: {:02X?}",
            self.client_handshake_traffic_secret, shared_secret, salt
        );
        Ok(())
    }

    fn derive_server_write_key_and_iv(&mut self) -> anyhow::Result<()> {
        let hkdf = HKDF::new(&self.server_handshake_traffic_secret);
        let label_key = HkdfLabel::new(16, "key", b"");
        let server_write_key = hkdf.expand_label(&label_key)?;
        self.server_write_key = server_write_key;
        let label_iv = HkdfLabel::new(12, "iv", b"");
        self.server_write_iv = hkdf.expand_label(&label_iv)?;
        debug!("server_write_key: {:02X?}", self.server_write_key);
        debug!("server_write_iv: {:02X?}", self.server_write_iv);
        Ok(())
    }

    fn derive_client_write_key_and_iv(&mut self) -> anyhow::Result<()> {
        let hkdf = HKDF::new(&self.client_handshake_traffic_secret);
        let label_key = HkdfLabel::new(16, "key", b"");
        let client_write_key = hkdf.expand_label(&label_key)?;
        self.client_write_key = client_write_key;
        let label_iv = HkdfLabel::new(12, "iv", b"");
        self.client_write_iv = hkdf.expand_label(&label_iv)?;
        debug!("client_write_key: {:02X?}", self.client_write_key);
        debug!("client_write_iv: {:02X?}", self.client_write_iv);
        Ok(())
    }
}
