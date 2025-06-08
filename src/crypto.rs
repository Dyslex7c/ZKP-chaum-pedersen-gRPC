use rand::RngCore;
use rand::rngs::OsRng;
use num_bigint::RandBigInt;
use num_traits::{One, Zero};
use num_integer::Integer;

fn generate_random() -> u64 {
    let mut rng = OsRng;
    rng.next_u64();
}

fn generate_safe_prime_pair(bits: usize) -> (BigUint, BigUint) {
    let mut rng = OsRng;
    loop {
        let mut p = rng.gen_biguint(bits - 1);
        if p.is_even() {
            p += 1u32;
        }
        
        if is_probably_prime(&p, 40) {
            let q = &p * 2u32 + 1u32;
            if is_probably_prime(&q, 40) {
                return (p, q);
            }
        }
    }
}

fn generate_prime(bits: usize) -> BigUint {
    let mut rng = OsRng;
    loop {
        let mut candidate = rng.gen_biguint(bits);
        if candidate.is_even() {
            candidate += 1u32;
        }

        if is_probably_prime(&candidate, 40) {
            return candidate;
        }
    }
}

// find a generator for the multiplicative cyclic group of g mod q
// for safe primes q = 2p+1, we need g^p != 1 (mod q) and g^2 != 1 (mod q)
fn find_generator(p: &BigUint, q: &BigUint) {
    let mut rng = OsRng;
    loop {
        let g = rng.gen_biguint_range(&BigUint::from(2u32), &(q - 1u32));

        let gp = g.modpow(p, q);
        let g2 = g.modpow(&BigUint::from(2u32), q);

        if !gp.is_one() && !g2.is_one() {
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

pub fn generate_params(bits: usize) -> (BigUint, BigUint, BigUint) {
    let (p, q) = generate_safe_prime_pair(bits);
    let g = find_generator(&p, &q);
    (p, q, g)
}

pub fn generate_random_element(q: &BigUint) -> BigUint {
    let mut rng = OsRng;
    rng.gen_biguint_range(&BigUint::one(), q)
}