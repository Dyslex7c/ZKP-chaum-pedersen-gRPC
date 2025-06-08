use tonic::{transport::Server, Request, Response, Status};
use tokio;
use zkp_chaum_pedersen_grpc::chaum_pedersen;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use num_bigint::BigUint;
use uuid::Uuid;

pub mod zkp {
    tonic::include_proto!("zkp");
}

use zkp::chaum_pedersen_service_server::{ChaumPedersenService, ChaumPedersenServiceServer};
use zkp::*;

use chaum_pedersen::{
    PublicParameters as CryptoPublicParameters,
    Commitment as CryptoCommitment,
    generate_challenge, verify_proof
};

#[derive(Debug, Clone)]
struct VerifierSession {
    params: CryptoPublicParameters,
    commitment: Option<CryptoCommitment>,
    y1: Option<BigUint>,
    y2: Option<BigUint>,
    challenge: Option<BigUint>,
}

#[derive(Debug)]
pub struct ChaumPedersenServer {
    // shared state across requests with thread-safe access
    sessions: Arc<Mutex<HashMap<String, VerifierSession>>>,
}

impl ChaumPedersenServer {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn generate_session_id(&self) -> String {
        Uuid::new_v4().to_string()
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
        let session_id = self.generate_session_id();
        
        let session = VerifierSession {
            params: params.clone(),
            commitment: None,
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

        let response = InitializeResponse {
            session_id: session_id.clone(),
            params: Some(proto_params),
        };

        println!("Protocol initialized with session ID: {}", session_id);
        Ok(Response::new(response))
    }

    async fn send_commitment(
        &self,
        request: Request<CommitmentRequest>,
    ) -> Result<Response<ChallengeResponse>, Status> {
        let req = request.into_inner();
        let session_id = req.session_id;
        
        let commitment_proto = req.commitment.ok_or_else(|| {
            Status::invalid_argument("Missing commitment")
        })?;
        
        let challenge_proto = req.challenge_values.ok_or_else(|| {
            Status::invalid_argument("Missing challenge values")
        })?;

        let commitment = CryptoCommitment {
            a1: BigUint::from_bytes_be(&commitment_proto.a1),
            b1: BigUint::from_bytes_be(&commitment_proto.b1),
            c1: BigUint::from_bytes_be(&commitment_proto.c1),
        };

        let y1 = BigUint::from_bytes_be(&challenge_proto.y1);
        let y2 = BigUint::from_bytes_be(&challenge_proto.y2);

        {
            let mut sessions = self.sessions.lock().unwrap();
            if let Some(session) = sessions.get_mut(&session_id) {
                session.commitment = Some(commitment);
                session.y1 = Some(y1.clone());
                session.y2 = Some(y2.clone());
                
                let challenge = generate_challenge(&y1, &y2, &session.params.q);
                session.challenge = Some(challenge.clone());
                
                let response = ChallengeResponse {
                    challenge: challenge.to_bytes_be(),
                };

                println!("Generated challenge for session: {}", session_id);
                return Ok(Response::new(response));
            }
        }

        Err(Status::not_found("Session not found"))
    }

    async fn verify_proof(
        &self,
        request: Request<VerifyProofRequest>,
    ) -> Result<Response<VerifyProofResponse>, Status> {
        let req = request.into_inner();
        let session_id = req.session_id;
        let z = BigUint::from_bytes_be(&req.z);

        let verification_result = {
            let sessions = self.sessions.lock().unwrap();
            if let Some(session) = sessions.get(&session_id) {
                if let (Some(commitment), Some(y1), Some(y2), Some(challenge)) = 
                    (&session.commitment, &session.y1, &session.y2, &session.challenge) {
                    
                    let verification = verify_proof(
                        &session.params.g,
                        &commitment.b1,
                        y1,
                        y2,
                        &commitment.a1,
                        &commitment.c1,
                        challenge,
                        &z,
                        &session.params.p,
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
                {
                    let mut sessions = self.sessions.lock().unwrap();
                    sessions.remove(&session_id);
                }
                Ok(Response::new(VerifyProofResponse {
                    verified: true,
                    message: "Zero-knowledge proof verified successfully!".to_string(),
                }))
            }
            Some(false) => {
                println!("Proof verification failed for session: {}", session_id);
                Ok(Response::new(VerifyProofResponse {
                    verified: false,
                    message: "Zero-knowledge proof verification failed!".to_string(),
                }))
            }
            None => Err(Status::invalid_argument("Invalid session state or session not found")),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let server = ChaumPedersenServer::new();

    println!("Listening on {}", addr);
    // starting the gRPC server listening for requests
    Server::builder()
        .add_service(ChaumPedersenServiceServer::new(server))
        .serve(addr)
        .await?;

    Ok(())
}