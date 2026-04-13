use indicatif::{ProgressBar, ProgressStyle};
use num_bigint::BigUint;
use num_traits::One;
use std::time::{Duration, Instant};

/// Bit-length of the RSA modulus. 1024 bits balances security and prime-generation
/// speed under pure-Rust big-integer arithmetic.
pub const MODULUS_BITS: usize = 1024;

const BENCHMARK_SECS: f64 = 3.0;

/// Holds the RSA modulus and its Euler totient (kept in memory only during locking).
pub struct Modulus {
    pub n: BigUint,
    /// phi(n) = (p-1)(q-1). Secret — enables the fast lock path.
    phi_n: BigUint,
}

impl Modulus {
    /// Generate a fresh RSA modulus n = p*q and compute phi(n).
    pub fn generate() -> Self {
        let half = MODULUS_BITS / 2;
        loop {
            let p = glass_pumpkin::prime::new(half).expect("prime generation failed");
            let q = glass_pumpkin::prime::new(half).expect("prime generation failed");
            if p != q {
                let n = &p * &q;
                let phi_n = (&p - BigUint::one()) * (&q - BigUint::one());
                return Self { n, phi_n };
            }
        }
    }
}

/// Benchmark sequential modular squarings on `n` for ~3 seconds.
/// Returns squarings per second.
pub fn benchmark(n: &BigUint) -> u64 {
    let target = Duration::from_secs_f64(BENCHMARK_SECS);
    let start = Instant::now();
    let mut x = BigUint::from(2u32);
    let mut count = 0u64;

    while start.elapsed() < target {
        x = (&x * &x) % n;
        count += 1;
    }

    let elapsed = start.elapsed().as_secs_f64();
    (count as f64 / elapsed).round() as u64
}

/// Fast path: compute 2^(2^T) mod n using phi(n) via Euler's theorem.
///
/// Because gcd(2, n) = 1 and phi(n) is known:
///   2^(2^T) mod n  =  2^(2^T mod phi(n)) mod n
///
/// Both inner and outer modpow are efficient — no sequential work required.
pub fn compute_fast(modulus: &Modulus, t: u64) -> BigUint {
    let two = BigUint::from(2u32);
    let exp = two.modpow(&BigUint::from(t), &modulus.phi_n);
    two.modpow(&exp, &modulus.n)
}

/// Slow path: compute 2^(2^T) mod n by performing T sequential squarings.
/// This is the only path available during unlock (phi(n) is not stored).
pub fn compute_slow(n: &BigUint, t: u64) -> BigUint {
    let bar = ProgressBar::new(t).with_style(
        ProgressStyle::with_template(
            "{wide_bar} {percent}%  elapsed {elapsed_precise}  ETA {eta_precise}",
        )
        .unwrap(),
    );
    bar.enable_steady_tick(Duration::from_millis(100));

    let mut x = BigUint::from(2u32);
    for _ in 0..t {
        x = (&x * &x) % n;
        bar.inc(1);
    }

    bar.finish_and_clear();
    x
}
