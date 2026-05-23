use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use clap::{Parser, Subcommand};

mod blob;
mod command;
mod crypto;
mod password;
mod timelock;

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
        output: PathBuf,
    },

    /// Unlock a previously locked password.
    ///
    /// Reads a blob, performs the required sequential work, derives the key,
    /// and prints the original password to stdout.
    Unlock {
        /// Read the blob from FILE instead of stdin.
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,
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

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Lock { time, output } => crate::command::lock::run(time, output),
        Commands::Unlock { input } => crate::command::unlock::run(input),
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

    use crate::LockDuration;
    use crate::crypto::{decrypt, derive_key, encrypt};
    use crate::timelock::{Modulus, compute_fast, compute_slow};

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
