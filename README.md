# Chaum Pedersen Zero-Knowledge Protocol gRPC

Chaum Pedersen ZKP is an interactive ZK protocol that allows a prover to prove to a verifier that they know a secret discrete logarithm (say x) of a commitment without revealing x itself. The project provides a complete gRPC-based system to test out this protocol.

This entire implementation provides a distributed architecture where the prover and verifier communicate over gRPC, making it suitable for applications that require remote attestation.

Given public values:
- p: A safe prime (p = 2q + 1)
- q: A Sophie Germain prime (order of the subgroup)
- g: A generator of the subgroup of order q
- a₁ = g^a mod p and b₁ = g^b mod p (commitments)
- c₁ = g^(ab) mod p (product commitment)

## Protocol Flow

Commitment Phase: Prover generates random x(secret) and computes:
- y₁ = g^x mod p
- y₂ = b₁^x mod p

Challenge Phase: Verifier generates challenge s = H(y₁, y₂) using SHA-256

Response Phase: Prover computes z = x + as mod q

Verification: Verifier checks:
- g^z ≡ a₁^s · y₁ (mod p)
- b₁^z ≡ c₁^s · y₂ (mod p)

## Setup and Usage
```bash
cargo run --quiet --bin grpc-zkp-server
```

Run the client in the same way in another terminal
```bash
cargo run --quiet --bin grpc-zkp-client
```