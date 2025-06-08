use num_bigint::BigUint;
use tonic::transport::Channel;
use tonic::Request;
use zkp_chaum_pedersen_grpc::chaum_pedersen;

pub mod zkp_client {
    tonic::include_proto!("zkp");
}

use zkp_client::chaum_pedersen_service_client::ChaumPedersenServiceClient;
use zkp_client::*;

use chaum_pedersen::{
    PublicParameters as CryptoPublicParameters,
    Prover, generate_prover_secret, compute_y1y2, compute_z
};

#[derive(Debug)]
pub struct ChaumPedersenClient {
    client: ChaumPedersenServiceClient<Channel>,
}

impl ChaumPedersenClient {
    pub async fn connect(addr: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let client = ChaumPedersenServiceClient::connect(addr.to_string()).await?;
        Ok(Self { client })
    }

    pub async fn run_protocol(&mut self, bit_size: u32) -> Result<bool, Box<dyn std::error::Error>> {
        println!("Starting Chaum-Pedersen Zero-Knowledge Proof Protocol");

        println!("Getting public parameters from verifier...");
        let init_request = Request::new(InitializeRequest { bit_size });
        let init_response = self.client.initialize_protocol(init_request).await?.into_inner();

        let session_id = init_response.session_id;
        let params = init_response.params.ok_or("Missing parameters")?;

        let crypto_params = CryptoPublicParameters {
            p: BigUint::from_bytes_be(&params.p),
            q: BigUint::from_bytes_be(&params.q),
            g: BigUint::from_bytes_be(&params.g),
        };

        println!("Received public parameters");
        println!("   Session ID: {}", session_id);
        println!("   Safe prime p: {} bits", crypto_params.p.bits());
        println!("   Sophie Germain prime q: {} bits", crypto_params.q.bits());

        println!("\nGenerating secrets and commitment...");
        let prover = Prover::new(crypto_params.clone());
        let commitment = prover.generate_commitment();
        
        println!("Generated commitment:");
        println!("   a1 = g^a mod p");
        println!("   b1 = g^b mod p"); 
        println!("   c1 = g^(a*b) mod p");

        println!("\nGenerating proof challenge values...");
        let x = generate_prover_secret(&crypto_params.q);
        let (y1, y2) = compute_y1y2(&x, &crypto_params.g, &commitment.b1, &crypto_params.p);

        println!("Generated challenge values:");
        println!("   y1 = g^x mod p");
        println!("   y2 = b1^x mod p");

        println!("\nSending commitment and challenge values...");
        let commitment_request = Request::new(CommitmentRequest {
            session_id: session_id.clone(),
            commitment: Some(Commitment {
                a1: commitment.a1.to_bytes_be(),
                b1: commitment.b1.to_bytes_be(),
                c1: commitment.c1.to_bytes_be(),
            }),
            challenge_values: Some(ProofChallenge {
                y1: y1.to_bytes_be(),
                y2: y2.to_bytes_be(),
            }),
        });

        let challenge_response = self.client.send_commitment(commitment_request).await?.into_inner();
        let challenge = BigUint::from_bytes_be(&challenge_response.challenge);

        println!("Received challenge from verifier");

        println!("\nComputing proof response...");
        let z = compute_z(&x, &prover.secret_a, &challenge, &crypto_params.q);

        println!("Computed response z = x + a*s mod q (here s is the challenge)");

        println!("\nSending response for verification...");
        let verify_request = Request::new(VerifyProofRequest {
            session_id: session_id.clone(),
            z: z.to_bytes_be(),
        });

        let verify_response = self.client.verify_proof(verify_request).await?.into_inner();

        if verify_response.verified {
            println!("SUCCESS: {}", verify_response.message);
            println!("Verified: The prover demonstrated knowledge of the discrete logarithm without revealing the secret value");
        } else {
            println!("FAILED: {}", verify_response.message);
            println!("The zero-knowledge proof verification failed!");
        }

        Ok(verify_response.verified)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = ChaumPedersenClient::connect("http://[::1]:50051").await?;

    println!("Connected to Chaum-Pedersen ZKP Server.");
    
    let bit_size = 512;
    let result = client.run_protocol(bit_size).await?;

    println!("Result: {}", if result { "Proof has been verified." } else { "Proof has failed!" });

    Ok(())
}