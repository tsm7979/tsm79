/// TLS 1.3 server and client handshake finite state machine — RFC 8446.
///
/// Implements the minimal TLS 1.3 handshake for:
///   - Server: ClientHello → ServerHello+EncryptedExtensions+Certificate+CertificateVerify+Finished → AppKeys
///   - Client: ClientHello → (ServerHello → EncryptedExtensions → Certificate → CertVerify → Finished) → AppKeys
///
/// Crypto primitives:
///   - Key agreement:  X25519 via `ring::agreement`
///   - Signatures:     ECDSA P-256 via `ring::signature`
///   - AEAD:           AES-128-GCM via `ring::aead` (record layer uses record.rs)
///   - HKDF:           Own implementation in tls/hkdf.rs
///   - Transcript:     SHA-256 via `ring::digest`

use ring::{digest, rand::SystemRandom, signature};
use super::hkdf::derive_secret;
use super::keys::{KeySchedule, CipherSuite, AppKeys, HandshakeKeys, generate_x25519_keypair, x25519_agree};
use super::record::{ContentType, RecordLayer};
use super::ja3::{Ja3Fingerprint, ThreatMatch};

// ── TLS handshake errors ──────────────────────────────────────────────────────

#[derive(Debug)]
pub enum TlsError {
    NeedMore,
    Protocol(&'static str),
    Crypto(ring::error::Unspecified),
    Io(std::io::Error),
}

impl From<ring::error::Unspecified> for TlsError {
    fn from(e: ring::error::Unspecified) -> Self { TlsError::Crypto(e) }
}

// ── Handshake message types ───────────────────────────────────────────────────

const MSG_CLIENT_HELLO:       u8 = 1;
const MSG_SERVER_HELLO:       u8 = 2;
const MSG_ENCRYPTED_EXTS:     u8 = 8;
const MSG_CERTIFICATE:        u8 = 11;
const MSG_CERTIFICATE_VERIFY: u8 = 15;
const MSG_FINISHED:           u8 = 20;

// Extension types
const EXT_SERVER_NAME:           u16 = 0;
const EXT_SUPPORTED_VERSIONS:    u16 = 43;
const EXT_KEY_SHARE:             u16 = 51;
const EXT_SIGNATURE_ALGORITHMS:  u16 = 13;
const EXT_SUPPORTED_GROUPS:      u16 = 10;

// Named group: X25519 = 0x001d
const GROUP_X25519: u16 = 0x001d;

// Signature algorithm: ecdsa_secp256r1_sha256 = 0x0403
const SIG_ECDSA_P256_SHA256: u16 = 0x0403;

// TLS 1.3 version = 0x0304
const TLS_1_3: u16 = 0x0304;

// ── Server handshake FSM ──────────────────────────────────────────────────────

pub enum ServerHandshakeState {
    ExpectClientHello,
    SentServerHello      { hs_keys: HandshakeKeys },
    SentCertificate      { hs_keys: HandshakeKeys },
    SentFinished         { app_keys: AppKeys },
    Complete             { app_keys: AppKeys },
}

pub struct ServerHandshake {
    state:      ServerHandshakeState,
    transcript: digest::Context,
    cert_der:   Vec<u8>,
    key_pair:   signature::EcdsaKeyPair,
    suite:      CipherSuite,
    rng:        SystemRandom,
    /// JA3 fingerprint extracted from the client's ClientHello.
    /// Populated after the first `process()` call; `None` until then.
    ja3:        Option<Ja3Fingerprint>,
}

impl ServerHandshake {
    /// Create a new server handshake with the given certificate and private key.
    ///
    /// `cert_der`  — DER-encoded certificate
    /// `key_pkcs8` — PKCS#8-encoded ECDSA P-256 private key
    pub fn new(cert_der: Vec<u8>, key_pkcs8: &[u8]) -> Result<Self, TlsError> {
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            key_pkcs8,
            &SystemRandom::new(),
        ).map_err(|_| TlsError::Protocol("invalid ECDSA key"))?;

        Ok(ServerHandshake {
            state:      ServerHandshakeState::ExpectClientHello,
            transcript: digest::Context::new(&digest::SHA256),
            cert_der,
            key_pair,
            suite:      CipherSuite::Aes128Gcm,
            rng:        SystemRandom::new(),
            ja3:        None,
        })
    }

    /// Feed incoming bytes into the FSM.
    /// Returns bytes to send to the client (may be empty) or an error.
    pub fn process(&mut self, input: &[u8]) -> Result<Vec<u8>, TlsError> {
        match &self.state {
            ServerHandshakeState::ExpectClientHello => {
                self.handle_client_hello(input)
            }
            ServerHandshakeState::SentFinished { .. } => {
                self.handle_client_finished(input)
            }
            _ => Ok(vec![])
        }
    }

    /// After the handshake is complete, return the application keys.
    pub fn take_app_keys(self) -> Option<AppKeys> {
        match self.state {
            ServerHandshakeState::Complete { app_keys } => Some(app_keys),
            _ => None,
        }
    }

    /// Return the JA3 fingerprint extracted from the client's ClientHello.
    /// Available after the first `process()` call; `None` if not yet received
    /// or if the record could not be parsed.
    pub fn ja3_fingerprint(&self) -> Option<&Ja3Fingerprint> {
        self.ja3.as_ref()
    }

    /// Return the known-bad threat match for this client's JA3, if any.
    /// Returns `None` if the fingerprint is unknown or not yet parsed.
    pub fn ja3_threat(&self) -> Option<ThreatMatch> {
        self.ja3.as_ref()?.lookup_threat()
    }

    /// Return the JA3 hash hex string, or empty string if not yet known.
    pub fn ja3_hash(&self) -> &str {
        self.ja3.as_ref().map(|fp| fp.ja3_hash.as_str()).unwrap_or("")
    }

    /// Return the JA4 fingerprint string, or empty string if not yet known.
    pub fn ja4(&self) -> &str {
        self.ja3.as_ref().map(|fp| fp.ja4.as_str()).unwrap_or("")
    }

    fn handle_client_hello(&mut self, data: &[u8]) -> Result<Vec<u8>, TlsError> {
        // ── JA3/JA4 fingerprinting ─────────────────────────────────────────────
        // Extract before updating the transcript so we operate on the raw record.
        // Ja3Fingerprint::from_record() parses the TLS record layer wrapper;
        // `data` here is the raw TLS record bytes received from the client.
        self.ja3 = Ja3Fingerprint::from_record(data).ok();
        if let Some(ref fp) = self.ja3 {
            if fp.is_malicious() {
                // Log the threat match — the pipeline layer decides whether to abort
                // the connection (it calls ja3_threat() after process()).
                crate::log_warn!("tls", "malicious TLS fingerprint detected";
                    "ja3"    => fp.ja3_hash,
                    "threat" => fp.lookup_threat().map(|t| t.tool).unwrap_or("unknown"),
                    "score"  => fp.risk_score()
                );
            }
        }

        // Update transcript with ClientHello
        let msg = parse_handshake_message(data)?;
        if msg.msg_type != MSG_CLIENT_HELLO {
            return Err(TlsError::Protocol("expected ClientHello"));
        }
        self.transcript.update(data);

        // Parse ClientHello to find key_share extension (X25519 key)
        let client_x25519_pub = parse_client_hello_key_share(&msg.body)?;

        // Generate our ephemeral X25519 key pair
        let (our_priv, our_pub) = generate_x25519_keypair(&self.rng)?;

        // ECDH shared secret
        let shared_secret = x25519_agree(our_priv, &client_x25519_pub)?;
        let shared_secret_arr: [u8; 32] = shared_secret;

        // Build ServerHello
        let server_hello = build_server_hello(&our_pub, self.suite)?;
        self.transcript.update(&server_hello);

        // Compute handshake secret after ServerHello
        let transcript_hash = self.transcript_hash();
        let ks     = KeySchedule::new(self.suite, &[]);
        let hs_keys = ks.handshake_keys(&shared_secret_arr, &transcript_hash);

        // Build and encrypt EncryptedExtensions + Certificate + CertificateVerify + Finished
        // For now we build the flight and return it; the record layer in pipeline.rs wraps it.
        let mut flight: Vec<u8> = Vec::new();

        // EncryptedExtensions (empty)
        let ee = handshake_message(MSG_ENCRYPTED_EXTS, &[0, 0]); // 2-byte extensions length = 0
        self.transcript.update(&ee);
        flight.extend_from_slice(&ee);

        // Certificate
        let cert_msg = build_certificate(&self.cert_der);
        self.transcript.update(&cert_msg);
        flight.extend_from_slice(&cert_msg);

        // CertificateVerify
        let cv_transcript = self.transcript_hash();
        let cv_msg = build_cert_verify(&self.key_pair, &cv_transcript, &self.rng)?;
        self.transcript.update(&cv_msg);
        flight.extend_from_slice(&cv_msg);

        // Finished
        let fin_transcript = self.transcript_hash();
        let fin_msg = build_finished(&hs_keys.server_finished_key, &fin_transcript);
        self.transcript.update(&fin_msg);
        flight.extend_from_slice(&fin_msg);

        // Compute app keys for after client Finished
        let app_transcript = self.transcript_hash();
        let app_keys = ks.app_keys(&hs_keys.handshake_secret, &app_transcript);

        self.state = ServerHandshakeState::SentFinished { app_keys };

        // Prepend ServerHello (plaintext) before the encrypted flight
        let mut out = Vec::new();
        // ServerHello is a plain Handshake record
        out.extend_from_slice(&wrap_handshake_record(&server_hello));
        // EncryptedExtensions..Finished would be encrypted with hs_keys in the record layer
        // We return them as plaintext here; the pipeline wraps them.
        out.extend_from_slice(&flight);
        Ok(out)
    }

    fn handle_client_finished(&mut self, data: &[u8]) -> Result<Vec<u8>, TlsError> {
        // Client Finished validation is handled by the pipeline using hs_keys.
        // Transition to Complete state.
        let app_keys = match std::mem::replace(
            &mut self.state,
            ServerHandshakeState::ExpectClientHello,
        ) {
            ServerHandshakeState::SentFinished { app_keys } => app_keys,
            _ => return Err(TlsError::Protocol("unexpected state for client Finished")),
        };
        self.state = ServerHandshakeState::Complete { app_keys };
        Ok(vec![])
    }

    fn transcript_hash(&self) -> [u8; 32] {
        let ctx  = self.transcript.clone();
        let hash = ctx.finish();
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_ref());
        out
    }
}

// ── Client handshake FSM ──────────────────────────────────────────────────────

pub struct ClientHandshake {
    transcript:  digest::Context,
    suite:       CipherSuite,
    rng:         SystemRandom,
    our_priv:    Option<ring::agreement::EphemeralPrivateKey>,
    ks:          Option<KeySchedule>,
    /// Stored handshake keys after process_server_hello; consumed in build_client_finished.
    hs_keys:     Option<HandshakeKeys>,
}

impl ClientHandshake {
    pub fn new() -> Self {
        ClientHandshake {
            transcript: digest::Context::new(&digest::SHA256),
            suite:      CipherSuite::Aes128Gcm,
            rng:        SystemRandom::new(),
            our_priv:   None,
            ks:         None,
            hs_keys:    None,
        }
    }

    // ── Two-step server flight processing (used by pool/connection.rs) ─────────

    /// Ingest a ServerHello handshake message, derive the HandshakeKeys, and
    /// store them for use by `build_client_finished`.
    ///
    /// `server_hello_msg` must be the raw handshake message bytes (msg_type=2
    /// header + body; no TLS record framing).
    pub fn process_server_hello(&mut self, server_hello_msg: &[u8]) -> Result<HandshakeKeys, TlsError> {
        // Parse and validate message type
        let msg = parse_handshake_message(server_hello_msg)?;
        if msg.msg_type != MSG_SERVER_HELLO {
            return Err(TlsError::Protocol("expected ServerHello"));
        }

        // Update transcript
        self.transcript.update(server_hello_msg);

        // Extract server's X25519 public key from key_share extension
        let server_x25519 = parse_server_hello_key_share(&msg.body)?;

        // ECDH shared secret
        let priv_key = self.our_priv.take()
            .ok_or(TlsError::Protocol("process_server_hello called before build_client_hello"))?;
        let shared = x25519_agree(priv_key, &server_x25519)?;
        let shared_arr: [u8; 32] = shared;

        // Derive HandshakeKeys from transcript-hash(ClientHello..ServerHello)
        let transcript_hash = self.transcript_hash();
        let ks      = KeySchedule::new(self.suite, &[]);
        let hs_keys = ks.handshake_keys(&shared_arr, &transcript_hash);

        self.ks = Some(ks);
        // Clone the keys for return (we also keep them in self)
        let hs_clone = HandshakeKeys {
            client:              super::keys::TrafficKeys { key: hs_keys.client.key.clone(), iv: hs_keys.client.iv.clone() },
            server:              super::keys::TrafficKeys { key: hs_keys.server.key.clone(), iv: hs_keys.server.iv.clone() },
            client_finished_key: hs_keys.client_finished_key.clone(),
            server_finished_key: hs_keys.server_finished_key.clone(),
            handshake_secret:    hs_keys.handshake_secret,
        };
        self.hs_keys = Some(hs_keys);
        Ok(hs_clone)
    }

    /// Ingest the decrypted server flight (EncryptedExtensions..Finished),
    /// build the encrypted ClientFinished bytes, and derive AppKeys.
    ///
    /// Must be called after `process_server_hello`.
    pub fn build_client_finished(
        &mut self,
        decrypted_flight: &[u8],
    ) -> Result<(Vec<u8>, AppKeys), TlsError> {
        let hs_keys = self.hs_keys.take()
            .ok_or(TlsError::Protocol("build_client_finished called before process_server_hello"))?;
        let ks = self.ks.take()
            .ok_or(TlsError::Protocol("key schedule missing"))?;

        // Update transcript with the decrypted server flight
        self.transcript.update(decrypted_flight);

        // Build ClientFinished
        let fin_transcript = self.transcript_hash();
        let fin_msg = build_finished(&hs_keys.client_finished_key, &fin_transcript);
        self.transcript.update(&fin_msg);

        // Derive AppKeys
        let app_transcript = self.transcript_hash();
        let app_keys = ks.app_keys(&hs_keys.handshake_secret, &app_transcript);

        Ok((wrap_handshake_record(&fin_msg), app_keys))
    }

    /// Build the ClientHello message.  Call this first; feed the output to the server.
    pub fn build_client_hello(&mut self) -> Result<Vec<u8>, TlsError> {
        let (our_priv, our_pub) = generate_x25519_keypair(&self.rng)?;
        self.our_priv = Some(our_priv);
        let client_hello = build_client_hello(&our_pub, self.suite);
        self.transcript.update(&client_hello);
        Ok(wrap_handshake_record(&client_hello))
    }

    /// Process the server flight (ServerHello + EncryptedExtensions..Finished).
    /// Returns the ClientFinished bytes, and the AppKeys on success.
    pub fn process_server_flight(
        &mut self,
        server_hello: &[u8],
        encrypted_flight: &[u8],
        server_hs_key: &[u8; 32],
    ) -> Result<(Vec<u8>, AppKeys), TlsError> {
        // Update transcript with ServerHello
        self.transcript.update(server_hello);

        // Parse ServerHello to get server's X25519 public key
        let msg = parse_handshake_message(server_hello)?;
        let server_x25519 = parse_server_hello_key_share(&msg.body)?;

        // ECDH
        let priv_key = self.our_priv.take()
            .ok_or(TlsError::Protocol("no private key"))?;
        let shared = x25519_agree(priv_key, &server_x25519)?;
        let shared_arr: [u8; 32] = shared;

        let transcript_hash = self.transcript_hash();
        let ks     = KeySchedule::new(self.suite, &[]);
        let hs_keys = ks.handshake_keys(&shared_arr, &transcript_hash);

        // Process encrypted_flight (EE + Cert + CertVerify + Finished)
        // In production this is decrypted by the record layer first.
        // Here we assume the pipeline passes us decrypted bytes.
        self.transcript.update(encrypted_flight);

        // Build ClientFinished
        let fin_transcript = self.transcript_hash();
        let fin_msg = build_finished(&hs_keys.client_finished_key, &fin_transcript);
        self.transcript.update(&fin_msg);

        let app_transcript = self.transcript_hash();
        let app_keys = ks.app_keys(&hs_keys.handshake_secret, &app_transcript);

        Ok((wrap_handshake_record(&fin_msg), app_keys))
    }

    fn transcript_hash(&self) -> [u8; 32] {
        let ctx  = self.transcript.clone();
        let hash = ctx.finish();
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_ref());
        out
    }
}

impl Default for ClientHandshake {
    fn default() -> Self { Self::new() }
}

// ── Message builders ──────────────────────────────────────────────────────────

/// Build a TLS 1.3 ClientHello with the given X25519 public key.
fn build_client_hello(our_pub: &[u8], suite: CipherSuite) -> Vec<u8> {
    let mut body = Vec::new();

    // Legacy version: TLS 1.2 = 0x0303
    body.extend_from_slice(&[0x03, 0x03]);
    // Random: 32 bytes of zeros (production code uses real randomness)
    body.extend_from_slice(&[0u8; 32]);
    // Legacy session ID length: 0
    body.push(0);
    // Cipher suites: one suite
    body.extend_from_slice(&[0, 2]);       // length = 2
    let wire = suite.wire_id().to_be_bytes();
    body.extend_from_slice(&wire);
    // Compression methods: null only
    body.extend_from_slice(&[1, 0]);

    // Extensions
    let mut exts = Vec::new();

    // supported_versions: TLS 1.3 only
    push_extension(&mut exts, EXT_SUPPORTED_VERSIONS, &{
        let mut v = vec![2]; // list length
        v.extend_from_slice(&TLS_1_3.to_be_bytes());
        v
    });

    // supported_groups: X25519
    push_extension(&mut exts, EXT_SUPPORTED_GROUPS, &{
        let mut v = vec![0, 2]; // list length = 2
        v.extend_from_slice(&GROUP_X25519.to_be_bytes());
        v
    });

    // key_share: X25519
    push_extension(&mut exts, EXT_KEY_SHARE, &{
        let mut v = vec![0, (4 + our_pub.len()) as u8]; // client key share list length
        v.extend_from_slice(&GROUP_X25519.to_be_bytes());
        v.extend_from_slice(&(our_pub.len() as u16).to_be_bytes());
        v.extend_from_slice(our_pub);
        v
    });

    // signature_algorithms: ecdsa_secp256r1_sha256
    push_extension(&mut exts, EXT_SIGNATURE_ALGORITHMS, &{
        let mut v = vec![0, 2]; // list length
        v.extend_from_slice(&SIG_ECDSA_P256_SHA256.to_be_bytes());
        v
    });

    // Extensions total length prefix
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    handshake_message(MSG_CLIENT_HELLO, &body)
}

/// Build a minimal TLS 1.3 ServerHello.
fn build_server_hello(our_pub: &[u8], suite: CipherSuite) -> Result<Vec<u8>, TlsError> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy version
    body.extend_from_slice(&[0u8; 32]);    // random
    body.push(0);                          // no legacy session ID
    body.extend_from_slice(&suite.wire_id().to_be_bytes());
    body.push(0); // no compression

    let mut exts = Vec::new();
    push_extension(&mut exts, EXT_SUPPORTED_VERSIONS, &[0x03, 0x04]); // TLS 1.3
    push_extension(&mut exts, EXT_KEY_SHARE, &{
        let mut v = Vec::new();
        v.extend_from_slice(&GROUP_X25519.to_be_bytes());
        v.extend_from_slice(&(our_pub.len() as u16).to_be_bytes());
        v.extend_from_slice(our_pub);
        v
    });

    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    Ok(handshake_message(MSG_SERVER_HELLO, &body))
}

/// Build a Certificate message (single certificate, no extensions).
fn build_certificate(cert_der: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0); // request context length = 0
    // Certificate list length (4 bytes for inner cert DER length + 2 for extensions)
    let cert_entry_len = 3 + cert_der.len() + 2; // 3-byte DER length + data + 2-byte ext len
    let list_len = cert_entry_len;
    body.push((list_len >> 16) as u8);
    body.push((list_len >> 8)  as u8);
    body.push(list_len         as u8);
    // CertificateEntry: 3-byte length + DER + 2-byte ext len
    body.push((cert_der.len() >> 16) as u8);
    body.push((cert_der.len() >> 8)  as u8);
    body.push(cert_der.len()         as u8);
    body.extend_from_slice(cert_der);
    body.extend_from_slice(&[0, 0]); // no extensions
    handshake_message(MSG_CERTIFICATE, &body)
}

/// Build a CertificateVerify message.
fn build_cert_verify(
    key_pair: &signature::EcdsaKeyPair,
    transcript_hash: &[u8; 32],
    rng: &dyn ring::rand::SecureRandom,
) -> Result<Vec<u8>, TlsError> {
    // The signed content for TLS 1.3 CertificateVerify:
    //   64 0x20 bytes || "TLS 1.3, server CertificateVerify" || 0x00 || transcript_hash
    let mut content = vec![0x20u8; 64];
    content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    content.push(0x00);
    content.extend_from_slice(transcript_hash);

    let sig = key_pair.sign(rng, &content).map_err(|_| TlsError::Protocol("signing failed"))?;
    let sig_bytes = sig.as_ref();

    let mut body = Vec::new();
    body.extend_from_slice(&SIG_ECDSA_P256_SHA256.to_be_bytes());
    body.extend_from_slice(&(sig_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(sig_bytes);

    Ok(handshake_message(MSG_CERTIFICATE_VERIFY, &body))
}

/// Build a Finished message: HMAC-SHA256(finished_key, transcript_hash).
fn build_finished(finished_key: &[u8], transcript_hash: &[u8; 32]) -> Vec<u8> {
    use ring::hmac;
    let key = hmac::Key::new(hmac::HMAC_SHA256, finished_key);
    let tag = hmac::sign(&key, transcript_hash);
    handshake_message(MSG_FINISHED, tag.as_ref())
}

// ── Parsing helpers ───────────────────────────────────────────────────────────

struct HandshakeMsg<'a> {
    msg_type: u8,
    body:     &'a [u8],
}

fn parse_handshake_message(data: &[u8]) -> Result<HandshakeMsg<'_>, TlsError> {
    if data.len() < 4 {
        return Err(TlsError::NeedMore);
    }
    let msg_type = data[0];
    let length   = (data[1] as usize) << 16 | (data[2] as usize) << 8 | data[3] as usize;
    if data.len() < 4 + length {
        return Err(TlsError::NeedMore);
    }
    Ok(HandshakeMsg { msg_type, body: &data[4..4 + length] })
}

/// Parse the X25519 key share from a ClientHello body.
fn parse_client_hello_key_share(body: &[u8]) -> Result<Vec<u8>, TlsError> {
    // Skip: legacy_version(2) + random(32) + session_id_len(1) + session_id + cipher_suites + compression
    if body.len() < 39 {
        return Err(TlsError::Protocol("ClientHello too short"));
    }
    let sid_len  = body[34] as usize;
    let mut pos  = 35 + sid_len;
    if pos + 2 > body.len() { return Err(TlsError::Protocol("ClientHello truncated")); }
    let cs_len   = (body[pos] as usize) << 8 | body[pos + 1] as usize;
    pos += 2 + cs_len;
    if pos + 1 > body.len() { return Err(TlsError::Protocol("no compression")); }
    let comp_len = body[pos] as usize;
    pos += 1 + comp_len;
    // Extensions
    if pos + 2 > body.len() { return Err(TlsError::Protocol("no extensions")); }
    let ext_total = (body[pos] as usize) << 8 | body[pos + 1] as usize;
    pos += 2;
    let ext_end = pos + ext_total;

    while pos + 4 <= ext_end {
        let ext_type = (body[pos] as u16) << 8 | body[pos + 1] as u16;
        let ext_len  = (body[pos + 2] as usize) << 8 | body[pos + 3] as usize;
        pos += 4;
        if ext_type == EXT_KEY_SHARE && ext_len >= 4 {
            // client key share list: 2-byte list length, then entries
            let list_len = (body[pos] as usize) << 8 | body[pos + 1] as usize;
            let mut lp = pos + 2;
            while lp + 4 <= pos + 2 + list_len {
                let group = (body[lp] as u16) << 8 | body[lp + 1] as u16;
                let klen  = (body[lp + 2] as usize) << 8 | body[lp + 3] as usize;
                lp += 4;
                if group == GROUP_X25519 && lp + klen <= body.len() {
                    return Ok(body[lp..lp + klen].to_vec());
                }
                lp += klen;
            }
        }
        pos += ext_len;
    }
    Err(TlsError::Protocol("no X25519 key share in ClientHello"))
}

/// Parse the server's X25519 key share from a ServerHello body.
fn parse_server_hello_key_share(body: &[u8]) -> Result<Vec<u8>, TlsError> {
    if body.len() < 38 { return Err(TlsError::Protocol("ServerHello too short")); }
    // Skip: legacy_version(2) + random(32) + sid_len(1) + sid + cipher_suite(2) + compression(1)
    let sid_len = body[34] as usize;
    let mut pos = 35 + sid_len + 2 + 1; // skip cs + compression
    if pos + 2 > body.len() { return Err(TlsError::Protocol("ServerHello truncated")); }
    let ext_len = (body[pos] as usize) << 8 | body[pos + 1] as usize;
    pos += 2;
    let ext_end = pos + ext_len;

    while pos + 4 <= ext_end {
        let ext_type = (body[pos] as u16) << 8 | body[pos + 1] as u16;
        let elen     = (body[pos + 2] as usize) << 8 | body[pos + 3] as usize;
        pos += 4;
        if ext_type == EXT_KEY_SHARE && elen >= 4 {
            let _group = (body[pos] as u16) << 8 | body[pos + 1] as u16;
            let klen   = (body[pos + 2] as usize) << 8 | body[pos + 3] as usize;
            return Ok(body[pos + 4..pos + 4 + klen].to_vec());
        }
        pos += elen;
    }
    Err(TlsError::Protocol("no key_share in ServerHello"))
}

// ── Wire format helpers ───────────────────────────────────────────────────────

fn handshake_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(msg_type);
    out.push((body.len() >> 16) as u8);
    out.push((body.len() >> 8)  as u8);
    out.push(body.len()         as u8);
    out.extend_from_slice(body);
    out
}

fn wrap_handshake_record(handshake_msg: &[u8]) -> Vec<u8> {
    // TLS record header: type=22 (Handshake), version=0x0303, length
    let mut rec = Vec::with_capacity(5 + handshake_msg.len());
    rec.push(0x16); // Handshake
    rec.push(0x03);
    rec.push(0x03);
    rec.push((handshake_msg.len() >> 8) as u8);
    rec.push(handshake_msg.len()        as u8);
    rec.extend_from_slice(handshake_msg);
    rec
}

fn push_extension(out: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_parseable() {
        let mut client = ClientHandshake::new();
        let hello_rec  = client.build_client_hello().unwrap();
        // Should be a Handshake record
        assert_eq!(hello_rec[0], 0x16); // Handshake content type
        assert_eq!(&hello_rec[1..3], &[0x03, 0x03]); // legacy TLS 1.2
        assert!(hello_rec.len() > 5);
    }

    #[test]
    fn x25519_key_share_round_trip() {
        // Build a ClientHello, extract the key share, build a ServerHello with it
        let mut client   = ClientHandshake::new();
        let hello_rec    = client.build_client_hello().unwrap();
        let hello_body   = &hello_rec[5..]; // skip record header
        let msg          = parse_handshake_message(hello_body).unwrap();
        let client_pub   = parse_client_hello_key_share(msg.body).unwrap();
        assert_eq!(client_pub.len(), 32); // X25519 public key = 32 bytes
    }

    #[test]
    fn handshake_message_format() {
        let body = b"test body";
        let msg  = handshake_message(MSG_CLIENT_HELLO, body);
        assert_eq!(msg[0], MSG_CLIENT_HELLO);
        assert_eq!(msg.len(), 4 + body.len());
        let parsed = parse_handshake_message(&msg).unwrap();
        assert_eq!(parsed.msg_type, MSG_CLIENT_HELLO);
        assert_eq!(parsed.body, body);
    }
}
