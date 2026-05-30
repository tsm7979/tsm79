/// TLS 1.3 record layer — RFC 8446 §5.
///
/// Each TLS record consists of:
///   - 1 byte content type (outer: always 0x17 = application_data for TLS 1.3)
///   - 2 bytes legacy version (0x0303)
///   - 2 bytes length
///   - Encrypted payload (ciphertext + 16-byte AEAD tag)
///
/// The inner content type is the last byte of the decrypted plaintext.
///
/// Nonce construction (RFC 8446 §5.3):
///   Nonce = write_iv XOR (write_seq as u64 big-endian, zero-padded to 12 bytes)

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use super::keys::{TrafficKeys, CipherSuite};

// ── Content types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert            = 21,
    Handshake        = 22,
    ApplicationData  = 23,
    Unknown(u8),
}

impl ContentType {
    pub fn from_byte(b: u8) -> Self {
        match b {
            20 => ContentType::ChangeCipherSpec,
            21 => ContentType::Alert,
            22 => ContentType::Handshake,
            23 => ContentType::ApplicationData,
            _  => ContentType::Unknown(b),
        }
    }

    pub fn as_byte(self) -> u8 {
        match self {
            ContentType::ChangeCipherSpec => 20,
            ContentType::Alert            => 21,
            ContentType::Handshake        => 22,
            ContentType::ApplicationData  => 23,
            ContentType::Unknown(b)       => b,
        }
    }
}

// ── TLS errors ────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum TlsError {
    Truncated,
    AeadDecryptFailed,
    AeadEncryptFailed,
    RecordTooBig,
    UnexpectedContentType(u8),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsError::Truncated              => write!(f, "TLS record truncated"),
            TlsError::AeadDecryptFailed      => write!(f, "AEAD decrypt failed"),
            TlsError::AeadEncryptFailed      => write!(f, "AEAD encrypt failed"),
            TlsError::RecordTooBig           => write!(f, "TLS record too large"),
            TlsError::UnexpectedContentType(t) => write!(f, "unexpected content type: {}", t),
        }
    }
}

// ── Record layer ──────────────────────────────────────────────────────────────

pub struct RecordLayer {
    write_key: LessSafeKey,
    read_key:  LessSafeKey,
    write_iv:  [u8; 12],
    read_iv:   [u8; 12],
    write_seq: u64,
    read_seq:  u64,
}

impl RecordLayer {
    /// Construct from pre-derived traffic keys.
    pub fn new(
        suite:      CipherSuite,
        write_keys: &TrafficKeys,
        read_keys:  &TrafficKeys,
    ) -> Result<Self, TlsError> {
        let alg = suite.ring_algorithm();

        let write_unbound = UnboundKey::new(alg, &write_keys.key)
            .map_err(|_| TlsError::AeadEncryptFailed)?;
        let read_unbound  = UnboundKey::new(alg, &read_keys.key)
            .map_err(|_| TlsError::AeadDecryptFailed)?;

        let mut write_iv = [0u8; 12];
        let mut read_iv  = [0u8; 12];
        write_iv.copy_from_slice(&write_keys.iv);
        read_iv .copy_from_slice(&read_keys.iv);

        Ok(RecordLayer {
            write_key: LessSafeKey::new(write_unbound),
            read_key:  LessSafeKey::new(read_unbound),
            write_iv,
            read_iv,
            write_seq: 0,
            read_seq:  0,
        })
    }

    /// Seal a plaintext into a TLS 1.3 record.
    ///
    /// The inner content type is appended to `plain` before encryption.
    /// Returns the full wire-format record bytes.
    pub fn seal(&mut self, content_type: ContentType, plain: &[u8]) -> Result<Vec<u8>, TlsError> {
        // TLS 1.3 max plaintext length is 2^14 bytes (+ 1 for inner content type)
        if plain.len() > (1 << 14) {
            return Err(TlsError::RecordTooBig);
        }

        // Build plaintext = plain || inner_content_type
        let mut plaintext = plain.to_vec();
        plaintext.push(content_type.as_byte());

        // Build nonce: IV XOR seq (seq as 8-byte big-endian in the last 8 bytes)
        let nonce_bytes = self.build_nonce(self.write_seq, &self.write_iv);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        // AAD = outer TLS record header (type=23, version=0x0303, length)
        let encrypted_len = plaintext.len() + self.write_key.algorithm().tag_len();
        let aad_bytes = [
            0x17, 0x03, 0x03,
            (encrypted_len >> 8) as u8,
             encrypted_len       as u8,
        ];
        let aad = Aad::from(aad_bytes);

        // Encrypt in-place
        self.write_key.seal_in_place_append_tag(nonce, aad, &mut plaintext)
            .map_err(|_| TlsError::AeadEncryptFailed)?;

        self.write_seq += 1;

        // Build the full TLS record
        let mut record = Vec::with_capacity(5 + plaintext.len());
        record.push(0x17); // outer content type: ApplicationData
        record.push(0x03); // legacy version
        record.push(0x03);
        record.push((plaintext.len() >> 8) as u8);
        record.push(plaintext.len()        as u8);
        record.extend_from_slice(&plaintext);
        Ok(record)
    }

    /// Open (decrypt) one TLS 1.3 record from `record`.
    ///
    /// `record` must contain the full 5-byte header + ciphertext.
    /// Returns `(inner_content_type, plaintext_slice)`.  The slice borrows
    /// from a buffer internal to the call — callers should copy if needed.
    pub fn open<'a>(&mut self, record: &'a mut Vec<u8>) -> Result<(ContentType, &'a [u8]), TlsError> {
        if record.len() < 5 {
            return Err(TlsError::Truncated);
        }
        let payload_len = ((record[3] as usize) << 8) | record[4] as usize;
        if record.len() < 5 + payload_len {
            return Err(TlsError::Truncated);
        }

        let nonce_bytes = self.build_nonce(self.read_seq, &self.read_iv);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let aad_bytes = [record[0], record[1], record[2], record[3], record[4]];
        let aad = Aad::from(aad_bytes);

        let payload = &mut record[5..5 + payload_len];
        let plaintext = self.read_key
            .open_in_place(nonce, aad, payload)
            .map_err(|_| TlsError::AeadDecryptFailed)?;

        self.read_seq += 1;

        // Last byte of plaintext is the inner content type
        if plaintext.is_empty() {
            return Err(TlsError::Truncated);
        }
        let content_type = ContentType::from_byte(*plaintext.last().unwrap());
        let data         = &plaintext[..plaintext.len() - 1];

        // Safe: data is a sub-slice of the record buffer we own
        let data_len = data.len();
        Ok((content_type, &record[5..5 + data_len]))
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn build_nonce(&self, seq: u64, base_iv: &[u8; 12]) -> [u8; 12] {
        let mut nonce = *base_iv;
        // XOR the lower 8 bytes with the sequence number (big-endian)
        let seq_bytes = seq.to_be_bytes();
        for (n, s) in nonce[4..].iter_mut().zip(seq_bytes.iter()) {
            *n ^= s;
        }
        nonce
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::keys::{CipherSuite, TrafficKeys};

    fn make_layer(suite: CipherSuite) -> RecordLayer {
        let key_len = suite.key_len();
        let keys = TrafficKeys {
            key: vec![0x42u8; key_len],
            iv:  vec![0x00u8; 12],
        };
        // For test: same keys for write and read (loopback)
        RecordLayer::new(suite, &keys, &keys).unwrap()
    }

    #[test]
    fn seal_open_roundtrip_aes128() {
        let mut layer = make_layer(CipherSuite::Aes128Gcm);
        let plain = b"Hello, TLS 1.3!";
        let mut record = layer.seal(ContentType::ApplicationData, plain).unwrap();
        // Reset seq so we can open with same counter
        layer.write_seq = 0;
        let (ct, data) = layer.open(&mut record).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(data, plain);
    }

    #[test]
    fn seal_open_roundtrip_chacha20() {
        let mut layer = make_layer(CipherSuite::ChaCha20Poly1305);
        let plain = b"ChaCha20 test payload";
        let mut record = layer.seal(ContentType::Handshake, plain).unwrap();
        layer.write_seq = 0;
        let (ct, data) = layer.open(&mut record).unwrap();
        assert_eq!(ct, ContentType::Handshake);
        assert_eq!(data, plain);
    }

    #[test]
    fn tampered_record_fails_open() {
        let mut layer = make_layer(CipherSuite::Aes128Gcm);
        let plain = b"secret data";
        let mut record = layer.seal(ContentType::ApplicationData, plain).unwrap();
        // Flip a bit in the ciphertext
        let last = record.len() - 1;
        record[last] ^= 0xff;
        layer.write_seq = 0;
        assert!(matches!(layer.open(&mut record), Err(TlsError::AeadDecryptFailed)));
    }

    #[test]
    fn seq_number_increments() {
        let mut layer = make_layer(CipherSuite::Aes128Gcm);
        let _ = layer.seal(ContentType::ApplicationData, b"a").unwrap();
        let _ = layer.seal(ContentType::ApplicationData, b"b").unwrap();
        assert_eq!(layer.write_seq, 2);
    }
}
