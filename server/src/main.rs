//! This is the simplest possible server using rustls that does something useful:
//! it accepts the default configuration, loads a server certificate and private key,
//! and then accepts a single client connection.
//!
//! Usage: cargo r --bin simpleserver <path/to/cert.pem> <path/to/privatekey.pem>
//!
//! Note that `unwrap()` is used to deal with networking errors; this is not something
//! that is sensible outside of example code.

use hickory_resolver::proto::rr::rdata::caa::Value::Issuer;
use log::{info, LevelFilter};
use rcgen::{Certificate, CertificateSigningRequestParams, KeyPair};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::sha2::Sha256;
use rsa::{sha2, RsaPrivateKey};
use rustls::pki_types::pem::{PemObject, SectionKind};
use rustls::pki_types::{CertificateSigningRequestDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::ServerConfig;
use std::error::{Error as StdError, Error};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{env, thread};
use x509_cert::builder::{Builder, Profile};
use x509_cert::der::{Decode, Encode};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

fn main() -> Result<(), Box<dyn StdError>> {
    let mut args = env::args();
    args.next();
    let mut builder = env_logger::Builder::from_default_env();
    builder.format(|buf, record| {
        writeln!(
            buf,
            "{} [{}:{}] - {}",
            record.level(),
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.args()
        )
    });
    builder
        .filter(None, LevelFilter::Trace)
        .init();
    let test_pki = Arc::new(TestPKI::new());
    let pki_clone = Arc::clone(&test_pki);
    start_cert_issuer(pki_clone);
    let private_key_file = "privatekey.pem";

    let certs = vec![test_pki.server_cert.der().clone()];
    let private_key = PrivateKeyDer::from_pem_file(private_key_file).unwrap();
    let result = rustls::crypto::ring::default_provider().install_default();
    let roots = test_pki.roots.clone().into();
    let verifier = WebPkiClientVerifier::builder(roots)
        .allow_unknown_revocation_status()
        .build()
        .unwrap();
    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, private_key)?;

    info!("Listening on [::]:4443");
    let listener = TcpListener::bind(format!("[::]:{}", 4443)).unwrap();

    loop {
        info!("waiting for client connection");
        let (mut stream, _) = listener.accept()?;
        let re = next_client(config.clone(), &mut stream);
        info!("client connection result: {:?}", re);
    }

    Ok(())
}

fn start_cert_issuer(pki_clone: Arc<TestPKI>) {
    thread::spawn(move || {
        let listener = TcpListener::bind("localhost:8080").unwrap();
        info!("Listening for CSR requests on localhost:8080");
        for stream in listener.incoming() {
            info!("Received connection from client");
            let mut stream = stream.unwrap();
            let mut buffer = Vec::new();
            let mut size_buf = 0usize.to_be_bytes();
            stream
                .read_exact(&mut size_buf)
                .unwrap();
            let size = usize::from_be_bytes(size_buf);
            buffer.resize(size, 0);
            stream.read_exact(&mut buffer).unwrap();
            info!("Received CSR from client({}) {:02X?}", size, buffer);
            let signed_csr = pki_clone.sign_csr(&buffer);
            match signed_csr {
                Ok(signed_csr) => {
                    info!("Signed CSR: {:02X?}", signed_csr);
                    stream.write_all(&signed_csr).unwrap();
                }
                Err(e) => {
                    info!("Error signing CSR: {:?}", e);
                }
            }
        }
    });
}

fn next_client(config: ServerConfig, mut stream: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    let mut conn = rustls::ServerConnection::new(Arc::new(config))?;
    conn.complete_io(&mut stream)?;

    info!("io completed, writing hello message");
    conn.writer()
        .write_all("Hello from the server\0".as_bytes())?;
    conn.complete_io(&mut stream)?;
    let mut buf = [0; 64];
    let len = conn.reader().read(&mut buf)?;
    println!("Received message from client: {:?}", &buf[..len]);
    Ok(())
}
struct TestPKI {
    pub roots: rustls::RootCertStore,
    pub server_cert: rcgen::Certificate,
    pub ca_key: rcgen::KeyPair,
    ca_cert: Certificate,
}

impl TestPKI {
    pub fn new() -> Self {
        let alg = &rcgen::PKCS_RSA_SHA256;
        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Sec-PoC-CA");
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "PoC CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        
        let path = Path::new("privatekey.pem");
        // if not exist create one
        if !path.exists() {
            let ca_key = rcgen::KeyPair::generate_for(alg).unwrap();
            let key_pem = ca_key.serialize_pem();
            std::fs::write("privatekey.pem", key_pem).unwrap();
        }
        
        let ca_key = PrivateKeyDer::from_pem_file(path).unwrap();
        let ca_key = KeyPair::try_from(&ca_key).unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let mut server_ee_params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        server_ee_params.is_ca = rcgen::IsCa::NoCa;
        server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::try_from(ca_key.serialize_der()).unwrap();
        let server_cert = server_ee_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();

        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(ca_cert.der().clone())
            .unwrap();
        Self {
            roots,
            server_cert,
            ca_key,
            ca_cert,
        }
    }

    pub fn sign_csr(&self, csr: &[u8]) -> anyhow::Result<Vec<u8>> {
        let cert_req = x509_cert::request::CertReq::from_der(csr)?;
        info!("Received CSR: {:?}", cert_req);
        let ca_cert = x509_cert::certificate::Certificate::from_der(self.ca_cert.der())?;
        let issuer = ca_cert.tbs_certificate.subject;
        let rsa_private_key = RsaPrivateKey::from_pkcs8_der(&self.ca_key.serialize_der())
            .map_err(|e| anyhow::anyhow!("Error decoding private key: {:?}", e))?;
        let cert_signer = rsa::pss::SigningKey::<sha2::Sha256>::new(rsa_private_key);
        let cert_builder = x509_cert::builder::CertificateBuilder::new(
            Profile::Leaf {issuer, enable_key_agreement:true, enable_key_encipherment:true},
            SerialNumber::from(1u8),
            Validity::from_now(Duration::from_secs(60 * 60 * 24 * 365))?,
            cert_req.info.subject,
            cert_req.info.public_key,
            &cert_signer,
        ).map_err(|e| anyhow::anyhow!("Error building certificate: {:?}", e))?;
        let cert = cert_builder.build::<rsa::pss::Signature>().map_err(|e| anyhow::anyhow!("Error signing certificate: {:?}", e))?;
        cert.to_der().map_err(|e| anyhow::anyhow!("Error encoding certificate: {:?}", e))
    }
}
