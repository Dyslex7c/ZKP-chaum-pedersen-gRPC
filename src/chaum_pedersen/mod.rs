pub mod crypto;

use num_bigint::BigUint;
use serde::{Serialize, Deserialize};

pub use crypto::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicParameters {
    pub p: BigUint,  // Safe prime p = 2q + 1
    pub q: BigUint,  // Sophie Germain prime (order of subgroup)
    pub g: BigUint,  // Generator of subgroup of order q
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commitment {
    pub a1: BigUint,  // g^a mod p
    pub b1: BigUint,  // g^b mod p  
    pub c1: BigUint,  // g^(ab) mod p
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofChallenge {
    pub y1: BigUint,  // g^x mod p
    pub y2: BigUint,  // b1^x mod p
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofResponse {
    pub z: BigUint,   // x + a*s mod q
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKProof {
    pub commitment: Commitment,
    pub challenge: ProofChallenge,
    pub response: ProofResponse,
    pub challenge_hash: BigUint,
}

impl PublicParameters {
    pub fn new(bits: u64) -> Self {
        let (p, q, g) = generate_params(bits);
        Self { p, q, g }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prover {
    pub params: PublicParameters,
    pub secret_a: BigUint,
    pub secret_b: BigUint,
}

impl Prover {
    pub fn new(params: PublicParameters) -> Self {
        let (secret_a, secret_b) = generate_secrets(&params.q);
        Self {
            params,
            secret_a,
            secret_b,
        }
    }

    pub fn generate_commitment(&self) -> Commitment {
        let (a1, b1, c1) = generate_commitment(
            &self.params.g,
            &self.secret_a,
            &self.secret_b,
            &self.params.p,
        );
        Commitment { a1, b1, c1 }
    }

    pub fn generate_proof_challenge(&self, commitment: &Commitment) -> (ProofChallenge, BigUint) {
        let x = generate_prover_secret(&self.params.q);
        let (y1, y2) = compute_y1y2(&x, &self.params.g, &commitment.b1, &self.params.p);
        
        (ProofChallenge { y1, y2 }, x)
    }

    pub fn generate_response(&self, x: &BigUint, challenge_hash: &BigUint) -> ProofResponse {
        let z = compute_z(x, &self.secret_a, challenge_hash, &self.params.q);
        ProofResponse { z }
    }

    pub fn create_proof(&self) -> ZKProof {
        let commitment = self.generate_commitment();
        let (challenge, x) = self.generate_proof_challenge(&commitment);
        let challenge_hash = generate_challenge(&challenge.y1, &challenge.y2, &self.params.q);
        let response = self.generate_response(&x, &challenge_hash);

        ZKProof {
            commitment,
            challenge,
            response,
            challenge_hash,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Verifier {
    pub params: PublicParameters,
}

impl Verifier {
    pub fn new(params: PublicParameters) -> Self {
        Self { params }
    }

    pub fn verify_proof(&self, proof: &ZKProof) -> bool {
        let expected_challenge = generate_challenge(
            &proof.challenge.y1,
            &proof.challenge.y2,
            &self.params.q,
        );
        
        if expected_challenge != proof.challenge_hash {
            return false;
        }

        verify_proof(
            &self.params.g,
            &proof.commitment.b1,
            &proof.challenge.y1,
            &proof.challenge.y2,
            &proof.commitment.a1,
            &proof.commitment.c1,
            &proof.challenge_hash,
            &proof.response.z,
            &self.params.p,
        )
    }
}