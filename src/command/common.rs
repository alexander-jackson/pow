use std::path::Path;

use crate::blob::Blob;
use crate::crypto::{decrypt, derive_key, encrypt, random_salt};
use crate::timelock::{MODULUS_BITS, Modulus, benchmark, compute_fast, compute_slow};

pub fn load_blob(path: &Path) -> Result<Blob, String> {
    let json = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let blob = Blob::from_json(&json)?;
    if blob.version != 1 {
        return Err(format!("Unsupported blob version {}.", blob.version));
    }
    Ok(blob)
}

pub fn decrypt_blob(blob: &Blob, master_password: &str) -> Result<Vec<u8>, String> {
    let n = blob.n_bigint()?;
    eprintln!(
        "Unlocking — performing {} squarings (target: ~{}s).",
        blob.t, blob.target_secs
    );
    let timelock_result = compute_slow(&n, blob.t);
    let argon2_salt = blob.argon2_salt_bytes()?;
    let aes_key = derive_key(master_password.as_bytes(), &argon2_salt, &timelock_result)?;
    let ciphertext = blob.ciphertext_bytes()?;
    let nonce = blob.nonce_bytes()?;
    decrypt(&aes_key, &ciphertext, &nonce)
}

pub fn encrypt_and_write(
    master_password: &str,
    plaintext: &[u8],
    target_secs: u64,
    output: &Path,
) -> Result<(), String> {
    eprintln!("Generating RSA modulus ({MODULUS_BITS} bits)...");
    let modulus = Modulus::generate();

    eprintln!("Benchmarking this machine (~3s)...");
    let squarings_per_sec = benchmark(&modulus.n);

    let t = squarings_per_sec * target_secs;
    eprintln!("Time-lock set to {t} squarings  ({squarings_per_sec}/sec × {target_secs}s target)");

    eprint!("Computing time-lock (fast path)...");
    let timelock_result = compute_fast(&modulus, t);
    eprintln!(" done.");

    eprintln!("Deriving key and encrypting...");
    let argon2_salt = random_salt();
    let aes_key = derive_key(master_password.as_bytes(), &argon2_salt, &timelock_result)?;
    let (ciphertext, nonce) = encrypt(&aes_key, plaintext);

    let blob = Blob::new(
        &modulus.n,
        t,
        squarings_per_sec,
        target_secs,
        &argon2_salt,
        &nonce,
        &ciphertext,
    );
    std::fs::write(output, blob.to_json()).map_err(|e| e.to_string())?;
    eprintln!("Blob written to {}.", output.display());

    Ok(())
}
