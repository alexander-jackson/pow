use std::path::PathBuf;

use crate::blob::Blob;
use crate::crypto::{decrypt, derive_key};
use crate::timelock::compute_slow;

pub fn run(input: PathBuf) -> Result<(), String> {
    let json = std::fs::read_to_string(&input).map_err(|e| e.to_string())?;

    let blob = Blob::from_json(&json)?;

    if blob.version != 1 {
        return Err(format!("Unsupported blob version {}.", blob.version));
    }

    let master_password =
        rpassword::prompt_password("Master password: ").map_err(|e| e.to_string())?;

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
    let plaintext = decrypt(&aes_key, &ciphertext, &nonce)?;

    let password = String::from_utf8(plaintext).map_err(|e| e.to_string())?;
    println!("{password}");

    Ok(())
}
