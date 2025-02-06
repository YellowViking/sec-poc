use der::{Any, Decode};
use der::asn1::BitString;
use log::{debug, info};
use ring::digest::SHA256;
use rsa::{BigUint, Pss, RsaPublicKey};
use rsa::pkcs1::RsaPssParams;
use rsa::pkcs1::der::Encode;
use rsa::pkcs8::spki::{AlgorithmIdentifier, AlgorithmIdentifierOwned};
use signature::{Keypair, Signer};
use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::str::FromStr;
use std::sync::Arc;
use der::oid::db::rfc5912::{ID_RSASSA_PSS};
use rsa::traits::SignatureScheme;
use sha2::{Digest, Sha256};
use tss_esapi::constants::SessionType;
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{
    HashScheme, HashcheckTicket, RsaExponent, RsaScheme, SymmetricDefinition,
};
use tss_esapi::tcti_ldr::NetworkTPMConfig;
use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;
use x509_cert::builder::Builder;
use x509_cert::name::Name;
use x509_cert::spki::{DynSignatureAlgorithmIdentifier, SignatureBitStringEncoding};

pub fn get_client_cert() -> anyhow::Result<(Vec<u8>, TPMInfoSigning)> {
    let (csr, signer) = tpm_generate_csr()?;
    let local_addr = "localhost:8080";
    let mut stream = TcpStream::connect(local_addr)?;
    info!("Connected to server, writing CSR");
    stream.write_all(&csr.len().to_be_bytes())?;
    stream.write_all(&csr)?;
    stream.flush()?;
    let mut buf = Vec::new();
    info!("Reading signed cert from server");
    stream.read_to_end(&mut buf)?;
    info!("Received signed cert from server {:02X?}", buf);
    let cert = x509_cert::certificate::Certificate::from_der(&buf)?;
    debug!("Received signed cert from server: {:?}", cert);
    Ok((buf,signer))
}

fn tpm_generate_csr() -> anyhow::Result<(Vec<u8>, TPMInfoSigning)>{
    // Step 1: Set up the TCTI for TPM2 using a Unix socket
    let tcti = tss_esapi::TctiNameConf::Swtpm(NetworkTPMConfig::default());

    let mut context =
        tss_esapi::Context::new(tcti).map_err(|e| anyhow::anyhow!("new failed: {:?}", e))?;

    let public = tss_esapi::utils::create_unrestricted_signing_rsa_public(
        RsaScheme::RsaPss(HashScheme::new(HashingAlgorithm::Sha256)),
        RsaKeyBits::Rsa2048,
        RsaExponent::ZERO_EXPONENT,
    )
    .map_err(|e| anyhow::anyhow!("create_unrestricted_signing_rsa_public failed: {:?}", e))?;

    let auth_session = context.start_auth_session(
        None,
        None,
        None,
        SessionType::Hmac,
        SymmetricDefinition::Null,
        HashingAlgorithm::Sha256,
    )?;

    info!("auth_session: {:?}, public: {:?}", auth_session, public);
    let key_handle = context.execute_with_session(auth_session, |ctx| {
        ctx.create_primary(Hierarchy::Owner, public, None, None, None, None)
    })?;

    // Step 3: Extract the public key from TPM
    let public = context.read_public(key_handle.key_handle)?.0;
    info!("public: {:?}", public);
    let pub_key = if let tss_esapi::structures::Public::Rsa {
        unique,
        object_attributes,
        ..
    } = public
    {
        if !object_attributes.sign_encrypt() {
            panic!("Key does not have the SIGN attribute.");
        }
        unique
    } else {
        anyhow::bail!("expected Rsa public key");
    };
    let pub_key = pub_key.to_vec();
    debug!("pub_key({}): {:02X?}", pub_key.len(), pub_key);

    // Step 4: Generate CSR

    if let Some(auth_session) = auth_session {
        context.set_sessions((Some(auth_session), None, None));
    }
    let context = Arc::new(RefCell::new(context));
    let signing = TPMInfoSigning {
        tpm_context: context,
        tpm_rsa_pub_key: pub_key,
        tpm_rsa_key_handle: key_handle.key_handle,
    };

    let subject_name = Name::from_str("CN=SecPoC+O=fox+C=US")?;
    let csr_builder = x509_cert::builder::RequestBuilder::new(subject_name, &signing)?;

    // Step 5: Build & Sign the CSR
    let certification_request = csr_builder.build()?;
    debug!("certification_request: {:?}", certification_request);
    let mut der_vec = Vec::new();
    certification_request.encode(&mut der_vec)?;

    // write to a file
    std::fs::write("csr.der", &der_vec)?;
    Ok((der_vec, signing))
}

pub type TPMDigest = tss_esapi::structures::Digest;

pub(crate) struct TPMInfoSigning {
    pub tpm_context: Arc<RefCell<tss_esapi::Context>>,
    pub tpm_rsa_pub_key: Vec<u8>,
    pub tpm_rsa_key_handle: KeyHandle,
}
pub(crate) struct TPMSignature {
    pub signature: Vec<u8>,
}
impl SignatureBitStringEncoding for TPMSignature {
    fn to_bitstring(&self) -> der::Result<BitString> {
        BitString::from_bytes(&self.signature)
    }
}
impl Keypair for TPMInfoSigning {
    type VerifyingKey = RsaPublicKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        // e == 2^16 + 1
        let e = BigUint::from(65537u32);
        let n = BigUint::from_bytes_be(&self.tpm_rsa_pub_key);
        Self::VerifyingKey::new(n, e).unwrap()
    }
}
impl DynSignatureAlgorithmIdentifier for TPMInfoSigning {
    fn signature_algorithm_identifier(&self) -> rsa::pkcs8::spki::Result<AlgorithmIdentifierOwned> {
        // RSASSA-PSS-params ::= SEQUENCE {
        //     hashAlgorithm      [0] HashAlgorithm      DEFAULT sha1,
        //     maskGenAlgorithm   [1] MaskGenAlgorithm   DEFAULT mgf1SHA1,
        //     saltLength         [2] INTEGER            DEFAULT 20,
        //     trailerField       [3] TrailerField       DEFAULT trailerFieldBC
        // }
        let params = rsa::pkcs1::RsaPssParams::new::<sha2::OidSha256>(Sha256::output_size() as u8);
        let alg_id = AlgorithmIdentifier::<RsaPssParams> {
            oid: ID_RSASSA_PSS,
            parameters: Some(params),
        };
        Ok(AlgorithmIdentifierOwned {
            oid: alg_id.oid,
            parameters: alg_id.parameters.map(|p| Any::encode_from(&p).unwrap()),
        })
    }
}
impl Signer<TPMSignature> for TPMInfoSigning {
    fn try_sign(&self, msg: &[u8]) -> Result<TPMSignature, signature::Error> {
        let digest = ring::digest::digest(&SHA256, msg);
        let tpm_digest =
            TPMDigest::try_from(digest.as_ref()).map_err(signature::Error::from_source)?;
        let signature_scheme = tss_esapi::structures::SignatureScheme::RsaPss {
            hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
        };
        let hashcheck = TPMT_TK_HASHCHECK {
            tag: tss_esapi::constants::tss::TPM2_ST_HASHCHECK,
            hierarchy: tss_esapi::constants::tss::TPM2_RH_NULL,
            ..TPMT_TK_HASHCHECK::default()
        };
        let hashcheck_ticket =
            HashcheckTicket::try_from(hashcheck).map_err(signature::Error::from_source)?;

        let mut tpm_context = self.tpm_context.borrow_mut();
        let signature_from_tpm = tpm_context
            .sign(
                self.tpm_rsa_key_handle,
                tpm_digest,
                signature_scheme,
                hashcheck_ticket,
            )
            .map_err(signature::Error::from_source)?;
        info!(
            "signature_from_tpm: {:?} signing: {:02X?}",
            signature_from_tpm, msg
        );
        let signature_from_tpm = match signature_from_tpm {
            tss_esapi::structures::Signature::RsaPss(ref signature) => signature.signature(),
            _ => {
                return Err(signature::Error::from_source(anyhow::anyhow!(
                    "expected RsaPss"
                )));
            }
        };

        let data = signature_from_tpm.value();

        debug!("signature_from_tpm({}): {:02X?}", data.len(), data);
        let pss = Pss::new::<sha2::Sha256>();
        pss.verify(&self.verifying_key(), digest.as_ref(), data)?;
        info!("signature verified for msg({}) {:02X?}", msg.len(), msg);
        Ok(TPMSignature {
            signature: data.to_vec(),
        })
    }
}
