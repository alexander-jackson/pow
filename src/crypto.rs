use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use num_bigint::BigUint;
use rand::RngCore;
use sha2::Sha256;

// Argon2id parameters. These make brute-forcing the master password expensive.
const M_COST: u32 = 65536; // 64 MB memory
const T_COST: u32 = 3; // 3 passes
const P_COST: u32 = 1; // 1 thread

/// Generate 16 cryptographically random bytes for an Argon2 salt.
pub fn random_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Generate a 12-byte AES-GCM nonce.
fn random_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Derive a 32-byte AES-256 key from the master password and the time-lock result.
///
/// Key material:
///   1. Argon2id(master_password, argon2_salt) → 32-byte master_key
///      (makes brute-forcing the master password costly)
///   2. HKDF-SHA256(ikm=master_key, salt=timelock_result_bytes) → 32-byte aes_key
///      (binds the key to completion of the time-lock work)
///
/// Both the master password AND the full time-lock computation are required to
/// reproduce the key.
pub fn derive_key(
    master_password: &[u8],
    argon2_salt: &[u8],
    timelock_result: &BigUint,
) -> Result<[u8; 32], String> {
    let params = Params::new(M_COST, T_COST, P_COST, Some(32)).map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut master_key = [0u8; 32];
    argon2
        .hash_password_into(master_password, argon2_salt, &mut master_key)
        .map_err(|e| e.to_string())?;

    let tl_bytes = timelock_result.to_bytes_be();
    let hk = Hkdf::<Sha256>::new(Some(&tl_bytes), &master_key);
    let mut aes_key = [0u8; 32];
    hk.expand(b"pow-v1-aes-key", &mut aes_key)
        .map_err(|_| "HKDF expand failed".to_string())?;

    Ok(aes_key)
}

/// Encrypt `plaintext` with AES-256-GCM. Returns `(ciphertext, nonce)`.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> (Vec<u8>, [u8; 12]) {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_bytes = random_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("AES-GCM encryption failed");
    (ciphertext, nonce_bytes)
}

/// Decrypt `ciphertext` with AES-256-GCM.
pub fn decrypt(key: &[u8; 32], ciphertext: &[u8], nonce_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed — wrong master password or corrupted blob.".to_string())
}
