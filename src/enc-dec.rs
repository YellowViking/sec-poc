use crate::key_schedule::{ApplicationKeySchedule, HandshakeKeySchedule};
use log::{debug, info};
use ring::aead::UnboundKey;

impl TlsEncryptDecrypt for ApplicationKeySchedule {
    fn get_read_seq_num_and_incr(&mut self) -> u64 {
        let seq_num = self.read_seq_num;
        self.read_seq_num += 1;
        seq_num
    }
    fn get_write_seq_num_and_incr(&mut self) -> u64 {
        let seq_num = self.write_seq_num;
        self.write_seq_num += 1;
        seq_num
    }
    fn encryption_key(&self) -> &[u8] {
        self.client_write_key.as_ref()
    }
    fn encryption_iv(&self) -> &[u8] {
        self.client_write_iv.as_ref()
    }
    fn decryption_key(&self) -> &[u8] {
        self.server_write_key.as_ref()
    }
    fn decryption_iv(&self) -> &[u8] {
        self.server_write_iv.as_ref()
    }

    fn client_traffic_secret(&self) -> &[u8] {
        self.client_application_traffic_secret.as_ref()
    }

    fn transcript_hash_context_mut(&mut self) -> &mut ring::digest::Context {
        &mut self.transcript_hash_context
    }

    fn transcript_hash_context(&self) -> &ring::digest::Context {
        &self.transcript_hash_context
    }
}

impl TlsEncryptDecrypt for HandshakeKeySchedule {
    fn get_read_seq_num_and_incr(&mut self) -> u64 {
        let seq_num = self.read_seq_num;
        self.read_seq_num += 1;
        seq_num
    }
    fn get_write_seq_num_and_incr(&mut self) -> u64 {
        let seq_num = self.write_seq_num;
        self.write_seq_num += 1;
        seq_num
    }
    fn encryption_key(&self) -> &[u8] {
        self.client_write_key.as_ref()
    }
    fn encryption_iv(&self) -> &[u8] {
        self.client_write_iv.as_ref()
    }
    fn decryption_key(&self) -> &[u8] {
        self.server_write_key.as_ref()
    }
    fn decryption_iv(&self) -> &[u8] {
        self.server_write_iv.as_ref()
    }
    fn client_traffic_secret(&self) -> &[u8] {
        self.client_handshake_traffic_secret.as_ref()
    }
    fn transcript_hash_context_mut(&mut self) -> &mut ring::digest::Context {
        &mut self.transcript_hash_context
    }
    fn transcript_hash_context(&self) -> &ring::digest::Context {
        &self.transcript_hash_context
    }
}

fn derive_nonce(iv: &[u8], seq_num: u64) -> Vec<u8> {
    let mut nonce = vec![0u8; 12];
    nonce[4..].copy_from_slice(&seq_num.to_be_bytes());
    nonce.iter_mut().zip(iv).for_each(|(a, b)| {
        *a ^= *b;
    });
    nonce
}

pub trait TlsEncryptDecrypt {
    fn add_transcript(&mut self, data: &[u8]) {
        debug!(
            "transcript_hash_context.update ({:?}): {:02X?}...",
            data.len(),
            &data[..10]
        );
        self.transcript_hash_context_mut().update(data);
        let hash = self.transcript_hash_context().clone().finish();
        debug!("transcript_hash_context.hash: {:02X?}", hash.as_ref());
    }

    fn get_read_seq_num_and_incr(&mut self) -> u64;
    fn get_write_seq_num_and_incr(&mut self) -> u64;
    fn encryption_key(&self) -> &[u8];
    fn encryption_iv(&self) -> &[u8];

    fn decryption_key(&self) -> &[u8];
    fn decryption_iv(&self) -> &[u8];

    fn client_traffic_secret(&self) -> &[u8];
    fn transcript_hash_context_mut(&mut self) -> &mut ring::digest::Context;
    fn transcript_hash_context(&self) -> &ring::digest::Context;

    fn get_verify_client_data(&self) -> anyhow::Result<Vec<u8>> {
        let digest = self.transcript_hash_context().clone().finish();
        let finished_key =
            crate::key_schedule::HKDF::new(self.client_traffic_secret()).expand_label(
                &crate::key_schedule::HkdfLabel::new(32, "finished", b""),
            )?;
        // The verify_data field is an HMAC over the transcript hash using finished_key.
        // The HMAC is computed as follows:
        // HMAC(finished_key, transcript_hash)
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &finished_key);
        let verify_data = ring::hmac::sign(&key, digest.as_ref());
        debug!(
            "verify_data: {:02X?} key: {:02X?} digest: {:02X?}",
            verify_data.as_ref(),
            finished_key,
            digest.as_ref()
        );
        Ok(verify_data.as_ref().to_vec())
    }
    fn decrypt_tls_encrypted<'a>(
        &mut self,
        hdr_buf: [u8; 5],
        tls_encrypted_content: &'a mut [u8],
    ) -> anyhow::Result<&'a mut [u8]> {
        let seq_num = self.get_read_seq_num_and_incr();
        let nonce = derive_nonce(self.decryption_iv(), seq_num);
        info!(
            "[decrypt_tls_encrypted] nonce: {:02X?} key:{:02X?} seq_num: {}",
            nonce,
            self.decryption_key(),
            seq_num
        );
        let nonce = ring::aead::Nonce::try_assume_unique_for_key(&nonce)
            .map_err(|e| anyhow::anyhow!("try_assume_unique_for_key failed: {:?}", e))?;
        if self.decryption_key().is_empty() {
            return Err(anyhow::anyhow!("server_write_key is empty"));
        }
        let server_write_key = UnboundKey::new(&ring::aead::AES_128_GCM, self.decryption_key())
            .map_err(|e| anyhow::anyhow!("UnboundKey failed: {:?}", e))?;
        let aad = ring::aead::Aad::from(&hdr_buf);
        ring::aead::LessSafeKey::new(server_write_key)
            .open_in_place(nonce, aad, tls_encrypted_content)
            .map_err(|e| anyhow::anyhow!("open_in_place failed: {:?}", e))
    }

    fn encrypt_tls_plaintext<'a>(
        &mut self,
        hdr_buf: [u8; 5],
        tls_plaintext: &'a mut [u8],
    ) -> anyhow::Result<(&'a [u8], ring::aead::Tag)> {
        let seq_num = self.get_write_seq_num_and_incr();
        let nonce = derive_nonce(self.encryption_iv(), seq_num);
        debug!(
            "[encrypt_tls_plaintext] nonce: {:02X?}, key:{:02X?}, seq_num: {} tls_plaintext({}): {:02X?}",
            nonce,
            self.encryption_key(),
            seq_num,
            tls_plaintext.len(),
            tls_plaintext
        );
        let nonce = ring::aead::Nonce::try_assume_unique_for_key(&nonce)
            .map_err(|e| anyhow::anyhow!("try_assume_unique_for_key failed: {:?}", e))?;
        if self.encryption_key().is_empty() {
            return Err(anyhow::anyhow!("server_write_key is empty"));
        }
        let server_write_key = UnboundKey::new(&ring::aead::AES_128_GCM, self.encryption_key())
            .map_err(|e| anyhow::anyhow!("UnboundKey failed: {:?}", e))?;
        let aad = ring::aead::Aad::from(&hdr_buf);
        let tag = ring::aead::LessSafeKey::new(server_write_key)
            .seal_in_place_separate_tag(nonce, aad, tls_plaintext)
            .map_err(|e| anyhow::anyhow!("seal_in_place failed: {:?}", e))?;
        Ok((tls_plaintext, tag))
    }
}
