use crate::key_schedule::{ApplicationKeySchedule, HandshakeKeySchedule};
use der::Decode;
use enc_dec::TlsEncryptDecrypt;
use log::{debug, info};
use signature::Signer;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use tls_parser::KeyShare::{KeyShareClientHello, KeyShareServerHello};
use tls_parser::KeyShareEntry;
use tls_parser::NamedGroup;
use tls_parser::TLS_AES_128_GCM_SHA256;
use tls_parser::TlsEncrypted;
use tls_parser::TlsEncryptedContent;
use tls_parser::TlsMessageHandshake::Finished;
use tls_parser::TlsPlaintext;
use tls_parser::TlsServerHelloContents;
use tls_parser::nom::bytes::complete::take;
use tls_parser::parse_tls_message_handshake;
use tls_parser::{RawCertificate, TlsCertificateContents, TlsMessageHandshake, nom};
use tls_parser::{Serialize, SignatureScheme};
use tls_parser::{TlsExtension, TlsMessage, TlsRecordType};

#[path = "enc-dec.rs"]
mod enc_dec;
#[path = "key-schedule.rs"]
mod key_schedule;
mod tpm;

struct TLSRecordReader<'a> {
    buf_reader: BufReader<&'a TcpStream>,
    vec: Vec<u8>,
}

impl<'a> TLSRecordReader<'a> {
    pub fn new(stream: &'a TcpStream) -> Self {
        TLSRecordReader {
            buf_reader: BufReader::new(stream),
            vec: Vec::new(),
        }
    }

    pub fn read_tls_record(&mut self) -> anyhow::Result<TlsPlaintext> {
        let (plaintext, _) = self.read_tls_record_with_vec()?;

        Ok(plaintext)
    }

    pub fn read_tls_encrypted_record(&mut self) -> anyhow::Result<(TlsEncrypted, [u8; 5])> {
        let mut hdr_buf = [0u8; 5];
        self.buf_reader.read_exact(&mut hdr_buf)?;
        let (_, hdr) = tls_parser::parse_tls_record_header(&hdr_buf)
            .map_err(|e| anyhow::anyhow!("parse_tls_record_header failed: {:?}", e))?;
        debug!("hdr: {:?}", hdr);
        self.vec.resize(hdr.len as usize, 0);
        self.buf_reader.read_exact(&mut self.vec)?;
        let msg = TlsEncrypted {
            hdr,
            msg: TlsEncryptedContent { blob: &self.vec },
        };
        Ok((msg, hdr_buf))
    }

    pub fn read_tls_record_with_vec(&mut self) -> anyhow::Result<(TlsPlaintext, Vec<u8>)> {
        self.vec.resize(5, 0);
        self.buf_reader.read_exact(&mut self.vec)?;
        let (_, hdr) = tls_parser::parse_tls_record_header(&self.vec)
            .map_err(|e| anyhow::anyhow!("parse_tls_record_header failed: {:?}", e))?;
        debug!("hdr: {:?}", hdr);
        self.vec.resize(hdr.len as usize, 0);
        self.buf_reader
            .read_exact(&mut self.vec[0..hdr.len as usize])?;
        let (_, msg) = tls_parser::parse_tls_record_with_header(&self.vec, &hdr)
            .map_err(|e| anyhow::anyhow!("parse_tls_record_with_header failed: {:?}", e))?;
        let plaintext = TlsPlaintext { hdr, msg };
        Ok((plaintext, self.vec.clone()))
    }
}

fn main() -> anyhow::Result<()> {
    unsafe {
        std::env::set_var("RUST_BACKTRACE", "1");
    }
    init_logger();
    info!("Application started");
    let (client_cert, signer) = tpm::get_client_cert()?;
    // let google_addr = "8.8.8.8:443";
    let local_addr = "localhost:4443";
    // let stream = TcpStream::connect(google_addr)?;
    let stream = TcpStream::connect(local_addr)?;
    let mut tcp_writer = stream.try_clone()?;
    let mut tls_record_reader = TLSRecordReader::new(&stream);
    let key_schedule = key_schedule::HandshakeKeySchedule::new()?;
    let mut key_schedule = start_handshake(
        &mut tcp_writer,
        &mut tls_record_reader,
        key_schedule,
        client_cert,
        |data| Ok(signer.try_sign(data)?.signature),
    )?;
    info!("\n\n\n\n\nApplication finished\n\n\n\n\n");

    let next_blob = read_tls_encrypted(&mut tls_record_reader, &mut key_schedule)?;
    let app_string = unsafe { std::str::from_utf8(&next_blob[..next_blob.len() - 16])? };
    info!("app_blob: {:02X?}, app_string: {}", next_blob, app_string);
    Ok(())
}

fn start_handshake(
    tcp_writer: &mut TcpStream,
    tls_record_reader: &mut TLSRecordReader,
    mut key_schedule: HandshakeKeySchedule,
    client_cert: Vec<u8>,
    signer: impl Fn(&[u8]) -> anyhow::Result<Vec<u8>>,
) -> anyhow::Result<ApplicationKeySchedule> {
    send_client_hello(tcp_writer, &mut key_schedule)?;
    
    let (next_tls_record, raw_vec) = tls_record_reader.read_tls_record_with_vec()?;
    let server_hello = expect_server_hello(&next_tls_record)?;
    debug!("server_hello: {:?}", server_hello);
    key_schedule.add_transcript(&raw_vec);

    expect_key_share(&mut key_schedule, server_hello)?;

    let next_tls_record = tls_record_reader.read_tls_record()?;
    if next_tls_record.hdr.record_type != TlsRecordType::ChangeCipherSpec {
        anyhow::bail!("expected ChangeCipherSpec and more data");
    }

    let blob = read_tls_encrypted(tls_record_reader, &mut key_schedule)?;
    let p = parse_tls_extensions(&blob)?;
    let (cert_requested, p) = process_server_cert(p)?;
    process_finished(p, &mut key_schedule, &blob)?;

    if cert_requested {
        send_client_cert(tcp_writer, &mut key_schedule, &client_cert)?;
        send_cert_verify(tcp_writer, &mut key_schedule, signer)?;
    }

    let key_schedule = send_client_finished(tcp_writer, key_schedule)?;
    Ok(key_schedule)

}
fn process_finished(p: &[u8], key_schedule: &mut HandshakeKeySchedule, blob: &[u8]) -> anyhow::Result<()> {
    let (p, finished) = parse_tls_message_handshake(p)
        .map_err(|e| anyhow::anyhow!("parse_tls_message_handshake failed: {:?}", e))?;


    info!("finished: {:?}", finished);
    if let TlsMessage::Handshake(tls_parser::TlsMessageHandshake::Finished(finished)) = finished {
        key_schedule.add_transcript(&blob[..blob.len() - 17]);
        key_schedule.on_server_finished()?;
    } else {
        anyhow::bail!("expected Finished");
    }

    let (p, aead_tag) = take(16usize + 1usize)(p)
        .map_err(|e: nom::Err<nom::error::Error<_>>| anyhow::anyhow!("take failed: {:?}", e))?;

    info!("Application finished p = {:02X?}\n\n\n\n\n Writing Client Handshake Finish", p);
    if p.is_empty() { Ok(()) } else { Err(anyhow::anyhow!("expected empty")) }
}
fn parse_tls_extensions(blob: &[u8]) -> anyhow::Result<&[u8]> {
    let (p, tls_message_exts) = parse_tls_message_handshake(&blob)
        .map_err(|e| anyhow::anyhow!("parse_tls_extensions failed: {:?}", e))?;
    // parse server cert
    info!("exts: {:?}", tls_message_exts);
    Ok(p)
}

fn process_server_cert(p: &[u8]) -> anyhow::Result<(bool, &[u8])> {
    let mut cert_requested = false;
    let (p, cert_req) = parse_tls_message_handshake(p)
        .map_err(|e| anyhow::anyhow!("parse_tls_message_handshake failed: {:?}", e))?;
    if let TlsMessage::Handshake(tls_parser::TlsMessageHandshake::CertificateRequest(_)) = cert_req
    {
        cert_requested = true;
        info!("cert_req: {:?}", cert_req);
    }

    let (p, server_cert) = if cert_requested {
        parse_tls_message_handshake(p)
            .map_err(|e| anyhow::anyhow!("parse_tls_message_handshake failed: {:?}", e))?
    } else {
        (p, cert_req)
    };
    info!("server_cert: {:?}", server_cert);
    if let TlsMessage::Handshake(tls_parser::TlsMessageHandshake::Certificate(cert)) = server_cert {
        cert.cert_chain.iter().for_each(|cert| {
            x509_cert::certificate::Certificate::from_der(cert.data).unwrap();
        });
    }
    let (p, cert_verify) = parse_tls_message_handshake(p)
        .map_err(|e| anyhow::anyhow!("parse_tls_message_handshake failed: {:?}", e))?;
    info!("cert_verify: {:?}", cert_verify);
    Ok((cert_requested, p))
}

fn expect_key_share(key_schedule: &mut HandshakeKeySchedule, server_hello: &TlsServerHelloContents) -> anyhow::Result<()> {
    let first_ext = server_hello
        .ext
        .first()
        .ok_or(anyhow::anyhow!("no extensions"))?;
    if let TlsExtension::KeyShare(KeyShareServerHello { server_share }) = first_ext {
        key_schedule.update_handshake_secret(server_share.kx)?;
    }
    Ok(())
}

fn send_client_hello(tcp_writer: &mut TcpStream, key_schedule: &mut HandshakeKeySchedule) -> anyhow::Result<()> {
    let kx = key_schedule.get_client_public_key();
    let client_hello = gen_client_hello(&kx);
    {
        let buf = client_hello.serialize()?;
        key_schedule.add_transcript(&buf[5..]);
        debug!(
            "client_hello: {:?}, buf({}): {:02X?}",
            client_hello,
            buf.len(),
            buf
        );
        tcp_writer.write_all(&buf)?;
    };
    Ok(())
}

fn send_client_finished(tcp_writer: &mut TcpStream, mut key_schedule: HandshakeKeySchedule) -> anyhow::Result<ApplicationKeySchedule> {
    let verify_data = key_schedule.get_verify_client_data()?;
    let client_handshake_finished = Finished(&verify_data);
    send_handshake_tls_message(tcp_writer, &mut key_schedule, client_handshake_finished)?;

    let mut key_schedule = key_schedule.into_application_key_schedule()?;
    key_schedule.add_transcript(&verify_data);
    Ok(key_schedule)
}

fn read_tls_encrypted<T: TlsEncryptDecrypt>(
    tls_record_reader: &mut TLSRecordReader,
    key_schedule: &mut T,
) -> anyhow::Result<Vec<u8>> {
    let (next_tls_record, hdr_buf) = tls_record_reader.read_tls_encrypted_record()?;
    let mut blob = Vec::from(next_tls_record.msg.blob);
    key_schedule.decrypt_tls_encrypted(hdr_buf, &mut blob)?;
    info!("application_data: {:02X?}...", &blob[0..10]);
    Ok(blob)
}

fn init_logger() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            let level = match record.level() {
                log::Level::Error => "\x1b[31mERROR\x1b[0m",
                log::Level::Warn => "\x1b[33mWARN\x1b[0m",
                log::Level::Info => "\x1b[32mINFO\x1b[0m",
                log::Level::Debug => "\x1b[34mDEBUG\x1b[0m",
                log::Level::Trace => "\x1b[35mTRACE\x1b[0m",
            };
            writeln!(
                buf,
                "{} [./{}:{}] {} - {}",
                level,
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                chrono::Local::now().format("%Y-%m-%dT%H:%M:%S"),
                record.args()
            )
        })
        .init();
}

fn expect_server_hello<'a>(
    tls_record: &'a TlsPlaintext,
) -> anyhow::Result<&'a TlsServerHelloContents<'a>> {
    if tls_record.hdr.record_type == TlsRecordType::Handshake {
        let handshake = tls_record
            .msg
            .first()
            .ok_or(anyhow::anyhow!("no handshake"))?;
        if let TlsMessage::Handshake(tls_parser::TlsMessageHandshake::ServerHello(sh)) = handshake {
                return Ok(sh);
            }
        }
    anyhow::bail!("expected ServerHello");
}

const RANDOM32: [u8; 32] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32,
];
fn gen_client_hello(kx: &[u8]) -> TlsPlaintext {
    let hdr = tls_parser::TlsRecordHeader {
        record_type: TlsRecordType::Handshake,
        version: tls_parser::TlsVersion::Tls10,
        len: 0,
    };

    let named_group = NamedGroup::EcdhX25519;
    let supported_versions = TlsExtension::SupportedVersions(vec![tls_parser::TlsVersion::Tls13]);
    let signature_algorithms =
        TlsExtension::SignatureAlgorithms(vec![SignatureScheme::rsa_pss_rsae_sha256]);
    let elliptic_curves = TlsExtension::EllipticCurves(vec![named_group]);
    let key_share = TlsExtension::KeyShare(KeyShareClientHello {
        client_shares: vec![KeyShareEntry {
            group: named_group,
            kx,
        }],
    });
    let ext = vec![
        elliptic_curves,
        signature_algorithms,
        // ec_point_formats,
        supported_versions,
        key_share,
    ];

    let client_hello_contents = tls_parser::TlsClientHelloContents {
        version: tls_parser::TlsVersion::Tls12,
        random: &RANDOM32,
        session_id: None,
        ciphers: vec![
            tls_parser::TlsCipherSuiteID(TLS_AES_128_GCM_SHA256),
            // tls_parser::TlsCipherSuiteID(TLS_AES_256_GCM_SHA384),
            // tls_parser::TlsCipherSuiteID(TLS_CHACHA20_POLY1305_SHA256),
        ],
        comp: vec![tls_parser::TlsCompressionID(0)],
        ext,
    };
    let client_hello_handshake = tls_parser::TlsMessage::Handshake(
        tls_parser::TlsMessageHandshake::ClientHello(client_hello_contents),
    );
    tls_parser::TlsPlaintext {
        hdr,
        msg: vec![client_hello_handshake],
    }
}
fn send_client_cert(
    tcp_writer: &mut TcpStream,
    key_schedule: &mut HandshakeKeySchedule,
    client_cert: &[u8],
) -> anyhow::Result<()> {
    info!("Sending client cert");
    let client_req_tls_message = TlsMessageHandshake::Certificate(TlsCertificateContents {
        cert_chain: vec![RawCertificate { data: &client_cert }],
    });
    send_handshake_tls_message(tcp_writer, key_schedule, client_req_tls_message)
}

fn send_handshake_tls_message(
    tcp_writer: &mut TcpStream,
    key_schedule: &mut HandshakeKeySchedule,
    tls_message: TlsMessageHandshake,
) -> anyhow::Result<()> {
    let tls_message_buf = tls_message.serialize()?;
    let mut tls_encrypted_message_buf = tls_message_buf.clone();
    tls_encrypted_message_buf.push(u8::from(TlsRecordType::Handshake));
    let wrapped_hdr = tls_parser::TlsRecordHeader {
        record_type: TlsRecordType::ApplicationData,
        version: tls_parser::TlsVersion::Tls12,
        len: (tls_encrypted_message_buf.len() + ring::aead::MAX_TAG_LEN) as u16,
    };
    let mut hdr_buf = [0u8; 5];
    hdr_buf.copy_from_slice(&wrapped_hdr.serialize()?);
    let (encrypted, tag) =
        key_schedule.encrypt_tls_plaintext(hdr_buf, &mut tls_encrypted_message_buf)?;
    let tls_encrypted = TlsEncrypted {
        hdr: wrapped_hdr,
        msg: TlsEncryptedContent { blob: encrypted },
    };
    let mut encrypted_buf = tls_encrypted.serialize()?;
    encrypted_buf.extend_from_slice(tag.as_ref());
    debug!("tag size = {:02X?}", tag.as_ref());
    tcp_writer.write_all(&encrypted_buf)?;
    key_schedule.add_transcript(&tls_message_buf);
    debug!(
        "sent({}) encrypted_buf ({}) [0..5] {:02X?}",
        tls_message_buf.len(),
        encrypted_buf.len(),
        &encrypted_buf[0..5]
    );
    Ok(())
}

fn send_cert_verify(
    tcp_writer: &mut TcpStream,
    key_schedule: &mut HandshakeKeySchedule,
    signer: impl Fn(&[u8]) -> anyhow::Result<Vec<u8>>,
) -> anyhow::Result<()> {
    const CONTEXT_STRING: &[u8] = b"TLS 1.3, client CertificateVerify\0";
    let signing_input = [
        &[0x20; 64],
        CONTEXT_STRING,
        key_schedule
            .transcript_hash_context
            .clone()
            .finish()
            .as_ref(),
    ]
    .concat();
    let sig = signer(&signing_input)?;
    let certificate_verify_content = tls_parser::CertificateVerifyContent {
        scheme: SignatureScheme::rsa_pss_rsae_sha256,
        signature: &sig,
    };
    let client_cert_verify = TlsMessageHandshake::CertificateVerify(certificate_verify_content);
    send_handshake_tls_message(tcp_writer, key_schedule, client_cert_verify)
}
