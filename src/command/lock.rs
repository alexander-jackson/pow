use std::path::PathBuf;

use crate::LockDuration;
use crate::blob::Blob;
use crate::crypto::{derive_key, encrypt, random_salt};
use crate::timelock::{MODULUS_BITS, Modulus, benchmark, compute_fast};

pub fn run(time: LockDuration, output: Option<PathBuf>) -> Result<(), String> {
    let target_secs = time.0;

    let master_password =
        rpassword::prompt_password("Master password: ").map_err(|e| e.to_string())?;
    let account_password =
        rpassword::prompt_password("Account password to lock: ").map_err(|e| e.to_string())?;
    let confirm =
        rpassword::prompt_password("Confirm account password: ").map_err(|e| e.to_string())?;

    if account_password != confirm {
        return Err("Passwords do not match.".into());
    }

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
    let (ciphertext, nonce) = encrypt(&aes_key, account_password.as_bytes());

    let blob = Blob::new(
        &modulus.n,
        t,
        squarings_per_sec,
        target_secs,
        &argon2_salt,
        &nonce,
        &ciphertext,
    );
    let json = blob.to_json();

    match output {
        Some(ref path) => {
            std::fs::write(path, &json).map_err(|e| e.to_string())?;
            eprintln!("Blob written to {}.", path.display());
        }
        None => println!("{json}"),
    }

    Ok(())
}
