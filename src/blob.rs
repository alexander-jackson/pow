use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

/// The serialised form of a locked password. Stored by the user in their
/// password manager in place of the original password.
#[derive(Serialize, Deserialize)]
pub struct Blob {
    /// Schema version (currently 1).
    pub version: u32,
    /// RSA modulus n (base64-encoded big-endian bytes).
    pub n: String,
    /// Number of sequential squarings T.
    pub t: u64,
    /// Squarings/sec measured on the locking machine (informational).
    pub squarings_per_sec: u64,
    /// Intended unlock duration in seconds (informational).
    pub target_secs: u64,
    /// Argon2id salt (base64).
    pub argon2_salt: String,
    /// AES-256-GCM nonce (base64).
    pub nonce: String,
    /// AES-256-GCM ciphertext + authentication tag (base64).
    pub ciphertext: String,
}

impl Blob {
    pub fn new(
        n: &BigUint,
        t: u64,
        squarings_per_sec: u64,
        target_secs: u64,
        argon2_salt: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Self {
        Self {
            version: 1,
            n: BASE64.encode(n.to_bytes_be()),
            t,
            squarings_per_sec,
            target_secs,
            argon2_salt: BASE64.encode(argon2_salt),
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(ciphertext),
        }
    }

    pub fn n_bigint(&self) -> Result<BigUint, String> {
        let bytes = BASE64.decode(&self.n).map_err(|e| e.to_string())?;
        Ok(BigUint::from_bytes_be(&bytes))
    }

    pub fn argon2_salt_bytes(&self) -> Result<Vec<u8>, String> {
        BASE64.decode(&self.argon2_salt).map_err(|e| e.to_string())
    }

    pub fn nonce_bytes(&self) -> Result<Vec<u8>, String> {
        BASE64.decode(&self.nonce).map_err(|e| e.to_string())
    }

    pub fn ciphertext_bytes(&self) -> Result<Vec<u8>, String> {
        BASE64.decode(&self.ciphertext).map_err(|e| e.to_string())
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("serialization failed")
    }

    pub fn from_json(s: &str) -> Result<Self, String> {
        serde_json::from_str(s).map_err(|e| format!("Invalid blob: {}", e))
    }
}
