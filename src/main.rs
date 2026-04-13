mod blob;
mod crypto;
mod timelock;

use std::io::{self, Read};
use std::path::PathBuf;

use std::fmt;
use std::str::FromStr;

use clap::{Parser, Subcommand};

use blob::Blob;
use crypto::{decrypt, derive_key, encrypt, random_salt};
use timelock::{benchmark, compute_fast, compute_slow, Modulus, MODULUS_BITS};

#[derive(Parser)]
#[command(
    name = "pow",
    about = "Proof of Work password locker\n\
             \n\
             Encrypts a password so that recovering it requires performing a\n\
             time-lock puzzle — a fixed amount of sequential work that cannot\n\
             be parallelised or shortcut without knowing a secret."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Lock a password behind a time delay.
    ///
    /// Generates a fresh RSA modulus, benchmarks this machine, and produces a
    /// blob that can only be decrypted after performing ~<TIME> worth of
    /// sequential modular squarings.
    Lock {
        /// How long unlocking should take (e.g. 30s, 5m, 1h).
        #[arg(short, long)]
        time: LockDuration,

        /// Write the blob to FILE instead of stdout.
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
    },

    /// Unlock a previously locked password.
    ///
    /// Reads a blob, performs the required sequential work, derives the key,
    /// and prints the original password to stdout.
    Unlock {
        /// Read the blob from FILE instead of stdin.
        #[arg(short, long, value_name = "FILE")]
        input: Option<PathBuf>,
    },
}

/// A duration expressed as a whole number of seconds, parsed from strings like
/// 30s, `5m`, or `1h`. Used as a clap argument type via its `FromStr` impl.
#[derive(Clone, Copy)]
struct LockDuration(u64);

impl fmt::Display for LockDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}s", self.0)
    }
}

impl FromStr for LockDuration {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let (n, multiplier) = match s.chars().last() {
            Some('h') => (&s[..s.len() - 1], 3600),
            Some('m') => (&s[..s.len() - 1], 60),
            Some('s') => (&s[..s.len() - 1], 1),
            _ => (s, 1),
        };
        let secs = n
            .parse::<u64>()
            .map(|n| n * multiplier)
            .map_err(|_| format!("Invalid duration '{s}'. Use formats like 30s, 5m, 1h."))?;

        if secs == 0 {
            return Err("Duration must be at least 1 second.".into());
        }

        Ok(Self(secs))
    }
}

fn cmd_lock(time: LockDuration, output: Option<PathBuf>) -> Result<(), String> {
    let target_secs = time.0;

    let master_password = rpassword::prompt_password("Master password: ")
        .map_err(|e| e.to_string())?;
    let account_password = rpassword::prompt_password("Account password to lock: ")
        .map_err(|e| e.to_string())?;
    let confirm = rpassword::prompt_password("Confirm account password: ")
        .map_err(|e| e.to_string())?;

    if account_password != confirm {
        return Err("Passwords do not match.".into());
    }

    eprintln!("Generating RSA modulus ({MODULUS_BITS} bits)...");
    let modulus = Modulus::generate();

    eprintln!("Benchmarking this machine (~3s)...");
    let squarings_per_sec = benchmark(&modulus.n);

    let t = squarings_per_sec * target_secs;
    eprintln!(
        "Time-lock set to {t} squarings  ({squarings_per_sec}/sec × {target_secs}s target)"
    );

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

fn cmd_unlock(input: Option<PathBuf>) -> Result<(), String> {
    let json = match input {
        Some(path) => std::fs::read_to_string(&path).map_err(|e| e.to_string())?,
        None => {
            let mut s = String::new();
            io::stdin()
                .read_to_string(&mut s)
                .map_err(|e| e.to_string())?;
            s
        }
    };

    let blob = Blob::from_json(&json)?;

    if blob.version != 1 {
        return Err(format!("Unsupported blob version {}.", blob.version));
    }

    let master_password = rpassword::prompt_password("Master password: ")
        .map_err(|e| e.to_string())?;

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

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Lock { time, output } => cmd_lock(time, output),
        Commands::Unlock { input } => cmd_unlock(input),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;

    use test_case::test_case;

    use crate::crypto::{decrypt, derive_key, encrypt};
    use crate::timelock::{compute_fast, compute_slow, Modulus};
    use crate::LockDuration;

    #[test_case("30s",  Some(30)   ; "can_parse_seconds_suffix")]
    #[test_case("5m",   Some(300)  ; "can_parse_minutes_suffix")]
    #[test_case("1h",   Some(3600) ; "can_parse_hours_suffix")]
    #[test_case("120",  Some(120)  ; "bare_number_defaults_to_seconds")]
    #[test_case("abc",  None       ; "non_numeric_input_fails")]
    #[test_case("5x",   None       ; "unknown_suffix_fails")]
    #[test_case("0s",   None       ; "zero_duration_fails")]
    fn parse_duration(input: &str, expected_secs: Option<u64>) {
        let result = input.parse::<LockDuration>();
        match expected_secs {
            Some(secs) => assert_eq!(result.unwrap().0, secs),
            None => assert!(result.is_err()),
        }
    }

    #[test]
    fn fast_and_slow_paths_agree() {
        let modulus = Modulus::generate();
        let t: u64 = 500;
        let fast = compute_fast(&modulus, t);
        let slow = compute_slow(&modulus.n, t);
        assert_eq!(fast, slow);
    }

    #[test]
    fn can_decrypt_after_encrypting() {
        let key = [0xabu8; 32];
        let plaintext = b"hunter2";
        let (ciphertext, nonce) = encrypt(&key, plaintext);
        let recovered = decrypt(&key, &ciphertext, &nonce).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn decrypting_with_wrong_key_fails() {
        let key = [0xabu8; 32];
        let (ciphertext, nonce) = encrypt(&key, b"secret");
        let wrong_key = [0xcdu8; 32];
        assert!(decrypt(&wrong_key, &ciphertext, &nonce).is_err());
    }

    #[test]
    fn can_unlock_after_locking() {
        let modulus = Modulus::generate();
        let t: u64 = 200;

        let timelock_result = compute_fast(&modulus, t);
        let argon2_salt = [0x11u8; 16];
        let master_pw = b"masterpassword";
        let account_pw = b"mypassword123";

        let key = derive_key(master_pw, &argon2_salt, &timelock_result).unwrap();
        let (ciphertext, nonce) = encrypt(&key, account_pw);

        let timelock_result2 = compute_slow(&modulus.n, t);
        let key2 = derive_key(master_pw, &argon2_salt, &timelock_result2).unwrap();
        let recovered = decrypt(&key2, &ciphertext, &nonce).unwrap();

        assert_eq!(recovered, account_pw);
    }

    #[test]
    fn blob_can_be_serialised_and_deserialised() {
        use crate::blob::Blob;

        let n = BigUint::from(12345678901234u64);
        let blob = Blob::new(&n, 999, 50000, 10, &[1u8; 16], &[2u8; 12], &[3u8; 32]);
        let json = blob.to_json();
        let restored = Blob::from_json(&json).unwrap();

        assert_eq!(restored.n_bigint().unwrap(), n);
        assert_eq!(restored.t, 999);
        assert_eq!(restored.squarings_per_sec, 50000);
        assert_eq!(restored.target_secs, 10);
        assert_eq!(restored.nonce_bytes().unwrap(), vec![2u8; 12]);
        assert_eq!(restored.ciphertext_bytes().unwrap(), vec![3u8; 32]);
    }
}
