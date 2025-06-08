use tonic::{transport::Server, Request, Response, Status};
use tokio;
use zkp_chaum_pedersen_grpc::chaum_pedersen;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use num_bigint::BigUint;

pub mod zkp {
    tonic::include_proto!("zkp");
}

use zkp::chaum_pedersen_service_server::{ChaumPedersenService, ChaumPedersenServiceServer};
use zkp::*;

use chaum_pedersen::{
    PublicParameters as CryptoPublicParameters,
    Commitment as CryptoCommitment,
    Prover, Verifier, generate_challenge
};

#[derive(Debug, Clone)]
struct Session {
    params: CryptoPublicParameters,
    commitment: CryptoCommitment,
    verifier: Verifier,
    y1: Option<BigUint>,
    y2: Option<BigUint>,
    challenge: Option<BigUint>,
}

#[derive(Debug)]
pub struct ChaumPedersenServer {
    sessions: Arc<Mutex<HashMap<String, Session>>>,
}

impl ChaumPedersenServer {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn generate_session_id() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..16).map(|_| rng.gen_range(0..16)).map(|x| format!("{:x}", x)).collect()
    }
}

#[tonic::async_trait]
impl ChaumPedersenService for ChaumPedersenServer {
    async fn initialize_protocol(
        &self,
        request: Request<InitializeRequest>,
    ) -> Result<Response<InitializeResponse>, Status> {
        let req = request.into_inner();
        let bit_size = req.bit_size as u64;

        if bit_size < 256 || bit_size > 4096 {
            return Err(Status::invalid_argument("Bit size must be between 256 and 4096"));
        }

        let params = CryptoPublicParameters::new(bit_size);
        
        let prover = Prover::new(params.clone());
        let commitment = prover.generate_commitment();
        
        let verifier = Verifier::new(params.clone());
        
        let session_id = Self::generate_session_id();
        let session = Session {
            params: params.clone(),
            commitment: commitment.clone(),
            verifier,
            y1: None,
            y2: None,
            challenge: None,
        };

        {
            let mut sessions = self.sessions.lock().unwrap();
            sessions.insert(session_id.clone(), session);
        }

        let proto_params = PublicParameters {
            p: params.p.to_bytes_be(),
            q: params.q.to_bytes_be(),
            g: params.g.to_bytes_be(),
        };

        let proto_commitment = Commitment {
            a1: commitment.a1.to_bytes_be(),
            b1: commitment.b1.to_bytes_be(),
            c1: commitment.c1.to_bytes_be(),
        };

        let response = InitializeResponse {
            params: Some(proto_params),
            commitment: Some(proto_commitment),
        };

        println!("Protocol initialized with session ID: {}", session_id);
        Ok(Response::new(response))
    }

    async fn send_proof_challenge(
        &self,
        request: Request<ProofChallengeRequest>,
    ) -> Result<Response<ChallengeResponse>, Status> {
        let req = request.into_inner();
        
        let y1 = BigUint::from_bytes_be(&req.y1);
        let y2 = BigUint::from_bytes_be(&req.y2);

        //let challenge = generate_challenge(&y1, &y2, &BigUint::from(2u32).pow(256));
        
        let session_id = {
            let sessions = self.sessions.lock().unwrap();
            sessions.keys().next().cloned()
        };

        if let Some(session_id) = session_id {
            {
                let mut sessions = self.sessions.lock().unwrap();
                if let Some(session) = sessions.get_mut(&session_id) {
                    session.y1 = Some(y1.clone());
                    session.y2 = Some(y2.clone());
                    
                    let proper_challenge = generate_challenge(&y1, &y2, &session.params.q);
                    session.challenge = Some(proper_challenge.clone());
                    
                    let response = ChallengeResponse {
                        challenge: proper_challenge.to_bytes_be(),
                    };

                    println!("Generated challenge for session: {}", session_id);
                    return Ok(Response::new(response));
                }
            }
        }

        Err(Status::not_found("Session not found"))
    }

    async fn verify_proof(
        &self,
        request: Request<VerifyProofRequest>,
    ) -> Result<Response<VerifyProofResponse>, Status> {
        let req = request.into_inner();
        let z = BigUint::from_bytes_be(&req.z);

        let session_id = {
            let sessions = self.sessions.lock().unwrap();
            sessions.keys().next().cloned()
        };

        if let Some(session_id) = session_id {
            let verification_result = {
                let sessions = self.sessions.lock().unwrap();
                if let Some(session) = sessions.get(&session_id) {
                    if let (Some(y1), Some(y2), Some(challenge)) = (&session.y1, &session.y2, &session.challenge) {
                        // Perform verification
                        let verification = chaum_pedersen::verify_proof(
                            &session.params.g,
                            &session.commitment.b1,
                            y1,
                            y2,
                            &session.commitment.a1,
                            &session.commitment.c1,
                            challenge,
                            &z,
                            &session.params.q,
                        );
                        
                        Some(verification)
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            match verification_result {
                Some(true) => {
                    println!("Proof verified successfully for session: {}", session_id);
                    Ok(Response::new(VerifyProofResponse {
                        verified: true,
                        message: "Proof verified successfully".to_string(),
                    }))
                }
                Some(false) => {
                    println!("Proof verification failed for session: {}", session_id);
                    Ok(Response::new(VerifyProofResponse {
                        verified: false,
                        message: "Proof verification failed".to_string(),
                    }))
                }
                None => Err(Status::invalid_argument("Invalid session state")),
            }
        } else {
            Err(Status::not_found("Session not found"))
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let server = ChaumPedersenServer::new();

    println!("Chaum-Pedersen gRPC Server listening on {}", addr);

    Server::builder()
        .add_service(ChaumPedersenServiceServer::new(server))
        .serve(addr)
        .await?;

    Ok(())
}