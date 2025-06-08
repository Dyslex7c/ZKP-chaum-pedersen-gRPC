use rand::rngs::OsRng;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{One};
use num_integer::Integer;
use sha2::{Sha256, Digest};

fn generate_safe_prime_pair(bits: u64) -> (BigUint, BigUint) {
    let mut rng = OsRng;
    loop {
        // Generate Sophie Germain prime q
        let mut q = rng.gen_biguint(bits - 1);
        if q.is_even() {
            q += 1u32;
        }
        
        if is_probably_prime(&q, 40) {
            // Safe prime p = 2q + 1
            let p = &q * 2u32 + 1u32;
            if is_probably_prime(&p, 40) {
                return (p, q); // p is safe prime, q is Sophie Germain prime
            }
        }
    }
}

fn find_generator(p: &BigUint, q: &BigUint) -> BigUint {
    let mut rng = OsRng;
    loop {
        let h = rng.gen_biguint_range(&BigUint::from(2u32), &(p - 1u32));
        
        // For safe primes p = 2q + 1, we compute g = h^2 mod p. this ensures g generates the subgroup of order q
        let g = h.modpow(&BigUint::from(2u32), p);
        
        // Check that g has order q (g^q = 1 mod p, g != 1)
        if !g.is_one() && g.modpow(q, p).is_one() {
            return g;
        }
    }
}

// Simple Miller-Rabin primality test
fn is_probably_prime(n: &BigUint, rounds: usize) -> bool {
    if n < &BigUint::from(2u32) {
        return false;
    }
    if n == &BigUint::from(2u32) || n == &BigUint::from(3u32) {
        return true;
    }
    if n.is_even() {
        return false;
    }

    // Write n-1 as d * 2^r
    let mut d = n - 1u32;
    let mut r = 0;
    while d.is_even() {
        d >>= 1;
        r += 1;
    }

    let mut rng = OsRng;
    
    'witness_loop: for _ in 0..rounds {
        let a = rng.gen_biguint_range(&BigUint::from(2u32), &(n - 1u32));
        let mut x = a.modpow(&d, n);
        
        if x.is_one() || x == n - 1u32 {
            continue 'witness_loop;
        }
        
        for _ in 0..r - 1 {
            x = x.modpow(&BigUint::from(2u32), n);
            if x == n - 1u32 {
                continue 'witness_loop;
            }
        }
        return false;
    }
    true
}

pub fn generate_params(bits: u64) -> (BigUint, BigUint, BigUint) {
    let (p, q) = generate_safe_prime_pair(bits);
    let g = find_generator(&p, &q);
    (p, q, g)
}

pub fn generate_random_element(q: &BigUint) -> BigUint {
    let mut rng = OsRng;
    let q_minus_1 = q - &BigUint::one();
    rng.gen_biguint_range(&BigUint::one(), &q_minus_1)
}

pub fn generate_commitment(g: &BigUint, a: &BigUint, b: &BigUint, p: &BigUint) -> (BigUint, BigUint, BigUint) {
    let a1 = g.modpow(a, p);
    let b1 = g.modpow(b, p);
    let c1 = g.modpow(&(a * b), p);
    (a1, b1, c1)
}

pub fn generate_challenge(y1: &BigUint, y2: &BigUint, q: &BigUint) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(y1.to_bytes_be());
    hasher.update(y2.to_bytes_be());
    
    let hash = hasher.finalize();
    let challenge = BigUint::from_bytes_be(&hash);

    challenge % q
}

pub fn compute_y1y2(x: &BigUint, g: &BigUint, b1: &BigUint, p: &BigUint) -> (BigUint, BigUint) {
    let y1 = g.modpow(x, p);
    let y2 = b1.modpow(x, p);
    (y1, y2)
}

pub fn compute_z(x: &BigUint, a: &BigUint, s: &BigUint, q: &BigUint) -> BigUint {
    (x + (a * s)) % q
}

pub fn verify_proof(
    g: &BigUint,
    b1: &BigUint,
    y1: &BigUint,
    y2: &BigUint,
    a1: &BigUint,
    c1: &BigUint,
    s: &BigUint,
    z: &BigUint,
    p: &BigUint
) -> bool {
    // Check: g^z mod p = a1^s * y1 mod p
    let left1 = g.modpow(z, p);
    let right1 = (a1.modpow(s, p) * y1) % p;
    
    // Check: b1^z mod p = c1^s * y2 mod p  
    let left2 = b1.modpow(z, p);
    let right2 = (c1.modpow(s, p) * y2) % p;
    
    left1 == right1 && left2 == right2
}

pub fn generate_secrets(q: &BigUint) -> (BigUint, BigUint) {
    let mut rng = OsRng;
    let a = rng.gen_biguint_range(&BigUint::one(), q);
    let b = rng.gen_biguint_range(&BigUint::one(), q);
    (a, b)
}

pub fn generate_prover_secret(q: &BigUint) -> BigUint {
    let mut rng = OsRng;
    rng.gen_biguint_range(&BigUint::one(), q)
}