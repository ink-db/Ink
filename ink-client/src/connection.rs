//! Network connection and client protocol state machine.

use crate::error::ClientError;
use futures_util::{SinkExt, StreamExt};
use ink_core::Keypair;
use ink_proto::{
    compute_auth_digest, AppendChallengeMsg, AppendCommitMsg, AppendInitMsg, AuthFailMsg,
    AuthOkMsg, AuthRespMsg, ChallengeMsg, ErrorCode, FrameCodec, FrameType, HeartbeatPingMsg,
    HelloReqMsg, ProofReqMsg, ProofRespMsg, QueryCompleteMsg, QueryReqMsg, RowDataMsg,
    RowHeaderMsg, TreeHeadReqMsg, TreeHeadRespMsg, CURRENT_VERSION,
};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

/// Tabular query execution result returned by `Connection::query`.
#[derive(Debug, Clone)]
pub struct ClientQueryResult {
    /// Ordered column names
    pub columns: Vec<String>,
    /// Row JSON values
    pub rows: Vec<serde_json::Value>,
    /// Total row count
    pub rows_returned: u64,
    /// Server query execution time in microseconds
    pub execution_time_us: u64,
}

/// Append execution confirmation returned by `Connection::append`.
#[derive(Debug, Clone)]
pub struct ClientAppendResult {
    /// Committed record sequence ID
    pub record_id: u64,
    /// Record BLAKE3 cryptographic hash (hex string)
    pub record_hash: String,
    /// Assigned timestamp in microseconds since Unix epoch
    pub timestamp_us: u64,
}

/// Active authenticated connection to an Ink TCP server daemon.
pub struct Connection {
    framed: Framed<TcpStream, FrameCodec>,
    keypair: Keypair,
    session_id: [u8; 16],
    database_id: [u8; 16],
    roles: Vec<String>,
    next_stream_id: u32,
}

impl Connection {
    /// Connect to an Ink TCP server daemon at `addr` and perform the Ed25519 challenge-response handshake.
    pub async fn connect(
        addr: &str,
        keypair: &Keypair,
        server_cert_hash: Option<[u8; 32]>,
    ) -> Result<Self, ClientError> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| ClientError::InvalidAddress(addr.to_string(), e.to_string()))?;

        let mut framed = Framed::new(stream, FrameCodec::new());

        // Step 1: Send HELLO_REQ
        let hello = HelloReqMsg {
            client_pubkey: keypair.public_key(),
            client_version: CURRENT_VERSION as u16,
            capabilities: 0,
        };
        framed.send(hello.to_frame(0)?).await?;

        // Step 2: Receive CHALLENGE or AUTH_FAIL
        let challenge_frame = framed.next().await.ok_or(ClientError::ConnectionClosed)??;

        if challenge_frame.header.frame_type == FrameType::AuthFail {
            let fail = AuthFailMsg::from_payload(&challenge_frame.payload)?;
            let name = ErrorCode::from_u16(fail.error_code)
                .map(|e| e.name())
                .unwrap_or("UNKNOWN")
                .to_string();
            return Err(ClientError::AuthFailed {
                code: fail.error_code,
                name,
                reason: fail.reason,
            });
        }

        if challenge_frame.header.frame_type != FrameType::Challenge {
            return Err(ClientError::UnexpectedFrame {
                expected: FrameType::Challenge,
                actual: challenge_frame.header.frame_type,
            });
        }

        let challenge = ChallengeMsg::from_payload(&challenge_frame.payload)?;

        // Step 3: Compute canonical challenge digest and sign locally
        let cert_hash = server_cert_hash.unwrap_or([0u8; 32]);
        let digest = compute_auth_digest(
            &challenge.database_id,
            &challenge.nonce,
            &challenge.session_id,
            &cert_hash,
        );
        let signature = keypair.sign(&digest);

        // Step 4: Send AUTH_RESP
        let auth_resp = AuthRespMsg {
            session_id: challenge.session_id,
            signature,
        };
        framed.send(auth_resp.to_frame(0)?).await?;

        // Step 5: Receive AUTH_OK or AUTH_FAIL
        let auth_result_frame = framed.next().await.ok_or(ClientError::ConnectionClosed)??;

        if auth_result_frame.header.frame_type == FrameType::AuthFail {
            let fail = AuthFailMsg::from_payload(&auth_result_frame.payload)?;
            let name = ErrorCode::from_u16(fail.error_code)
                .map(|e| e.name())
                .unwrap_or("UNKNOWN")
                .to_string();
            return Err(ClientError::AuthFailed {
                code: fail.error_code,
                name,
                reason: fail.reason,
            });
        }

        if auth_result_frame.header.frame_type != FrameType::AuthOk {
            return Err(ClientError::UnexpectedFrame {
                expected: FrameType::AuthOk,
                actual: auth_result_frame.header.frame_type,
            });
        }

        let auth_ok = AuthOkMsg::from_payload(&auth_result_frame.payload)?;
        let roles: Vec<String> = serde_json::from_str(&auth_ok.roles_json).unwrap_or_default();

        Ok(Self {
            framed,
            keypair: keypair.clone(),
            session_id: auth_ok.session_id,
            database_id: challenge.database_id,
            roles,
            next_stream_id: 1,
        })
    }

    /// Return the active connection session ID.
    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    /// Return the connected cluster database UUID.
    pub fn database_id(&self) -> [u8; 16] {
        self.database_id
    }

    /// Return the granted roles for the authenticated identity.
    pub fn roles(&self) -> &[String] {
        &self.roles
    }

    /// Allocate the next multiplexed stream ID.
    fn allocate_stream_id(&mut self) -> u32 {
        let id = self.next_stream_id;
        self.next_stream_id = self.next_stream_id.wrapping_add(1);
        if self.next_stream_id == 0 {
            self.next_stream_id = 1;
        }
        id
    }

    /// Execute an IQL query statement over the wire, collecting tabular results.
    pub async fn query(&mut self, iql: &str) -> Result<ClientQueryResult, ClientError> {
        let stream_id = self.allocate_stream_id();
        let query_req = QueryReqMsg {
            iql: iql.to_string(),
        };
        self.framed.send(query_req.to_frame(stream_id)?).await?;

        let mut columns = Vec::new();
        let mut rows = Vec::new();
        let mut rows_returned = 0u64;
        let mut execution_time_us = 0u64;

        while let Some(frame_res) = self.framed.next().await {
            let frame = frame_res?;
            if frame.header.stream_id != stream_id {
                continue;
            }

            match frame.header.frame_type {
                FrameType::RowHeader => {
                    let header = RowHeaderMsg::from_payload(&frame.payload)?;
                    columns = header.columns;
                }
                FrameType::RowData => {
                    let row_msg = RowDataMsg::from_payload(&frame.payload)?;
                    let json_val: serde_json::Value = serde_json::from_str(&row_msg.data_json)
                        .map_err(|e| {
                            ClientError::QueryFailed(format!("Invalid row JSON: {}", e))
                        })?;
                    rows.push(json_val);
                }
                FrameType::QueryComplete => {
                    let complete = QueryCompleteMsg::from_payload(&frame.payload)?;
                    rows_returned = complete.rows_returned;
                    execution_time_us = complete.execution_time_us;
                    break;
                }
                FrameType::AuthFail => {
                    let fail = AuthFailMsg::from_payload(&frame.payload)?;
                    if fail.error_code == ErrorCode::AccessDenied.as_u16() {
                        return Err(ClientError::AccessDenied(fail.reason));
                    }
                    return Err(ClientError::QueryFailed(fail.reason));
                }
                other => {
                    return Err(ClientError::QueryFailed(format!(
                        "Unexpected frame type in query stream: {:?}",
                        other
                    )));
                }
            }
        }

        Ok(ClientQueryResult {
            columns,
            rows,
            rows_returned,
            execution_time_us,
        })
    }

    /// Perform a remote signed append using the two-step signing flow.
    pub async fn append(
        &mut self,
        table: &str,
        json_data: &str,
    ) -> Result<ClientAppendResult, ClientError> {
        let stream_id = self.allocate_stream_id();

        // Step 1: Send APPEND_INIT
        let init_msg = AppendInitMsg {
            table_name: table.to_string(),
            data_json: json_data.to_string(),
        };
        self.framed.send(init_msg.to_frame(stream_id)?).await?;

        // Step 2: Await APPEND_CHALLENGE or AUTH_FAIL
        let challenge_frame = self
            .framed
            .next()
            .await
            .ok_or(ClientError::ConnectionClosed)??;

        if challenge_frame.header.frame_type == FrameType::AuthFail {
            let fail = AuthFailMsg::from_payload(&challenge_frame.payload)?;
            if fail.error_code == ErrorCode::AccessDenied.as_u16() {
                return Err(ClientError::AccessDenied(fail.reason));
            }
            return Err(ClientError::QueryFailed(fail.reason));
        }

        if challenge_frame.header.frame_type != FrameType::AppendChallenge {
            return Err(ClientError::UnexpectedFrame {
                expected: FrameType::AppendChallenge,
                actual: challenge_frame.header.frame_type,
            });
        }

        let chal = AppendChallengeMsg::from_payload(&challenge_frame.payload)?;

        // Step 3: Sign canonical record hash locally with author key
        let signature = self.keypair.sign(&chal.canonical_record_hash);

        // Step 4: Send APPEND_COMMIT
        let commit_msg = AppendCommitMsg {
            lease_token: chal.lease_token,
            signature,
        };
        self.framed.send(commit_msg.to_frame(stream_id)?).await?;

        // Step 5: Await confirmation
        while let Some(frame_res) = self.framed.next().await {
            let frame = frame_res?;
            if frame.header.stream_id != stream_id {
                continue;
            }

            match frame.header.frame_type {
                FrameType::QueryComplete => {
                    return Ok(ClientAppendResult {
                        record_id: chal.record_id,
                        record_hash: hex::encode(chal.canonical_record_hash),
                        timestamp_us: chal.timestamp_us,
                    });
                }
                FrameType::RowData => {
                    // Confirmation row
                    continue;
                }
                FrameType::AuthFail => {
                    let fail = AuthFailMsg::from_payload(&frame.payload)?;
                    if fail.error_code == ErrorCode::LeaseExpired.as_u16() {
                        return Err(ClientError::LeaseExpired(fail.reason));
                    }
                    return Err(ClientError::QueryFailed(fail.reason));
                }
                other => {
                    return Err(ClientError::QueryFailed(format!(
                        "Unexpected frame type following append commit: {:?}",
                        other
                    )));
                }
            }
        }

        Err(ClientError::ConnectionClosed)
    }

    /// Retrieve the latest RFC 6962 tree head root hash for a table.
    pub async fn get_tree_head(&mut self, table: &str) -> Result<TreeHeadRespMsg, ClientError> {
        let stream_id = self.allocate_stream_id();
        let req = TreeHeadReqMsg {
            table_name: table.to_string(),
        };
        self.framed.send(req.to_frame(stream_id)?).await?;

        let frame = self
            .framed
            .next()
            .await
            .ok_or(ClientError::ConnectionClosed)??;

        if frame.header.frame_type == FrameType::AuthFail {
            let fail = AuthFailMsg::from_payload(&frame.payload)?;
            return Err(ClientError::QueryFailed(fail.reason));
        }

        if frame.header.frame_type != FrameType::TreeHeadResp {
            return Err(ClientError::UnexpectedFrame {
                expected: FrameType::TreeHeadResp,
                actual: frame.header.frame_type,
            });
        }

        TreeHeadRespMsg::from_payload(&frame.payload).map_err(ClientError::from)
    }

    /// Retrieve an inclusion proof for a specific record ID in a table.
    pub async fn get_proof(
        &mut self,
        table: &str,
        record_id: u64,
    ) -> Result<ProofRespMsg, ClientError> {
        let stream_id = self.allocate_stream_id();
        let req = ProofReqMsg {
            table_name: table.to_string(),
            record_id,
        };
        self.framed.send(req.to_frame(stream_id)?).await?;

        let frame = self
            .framed
            .next()
            .await
            .ok_or(ClientError::ConnectionClosed)??;

        if frame.header.frame_type == FrameType::AuthFail {
            let fail = AuthFailMsg::from_payload(&frame.payload)?;
            return Err(ClientError::QueryFailed(fail.reason));
        }

        if frame.header.frame_type != FrameType::ProofResp {
            return Err(ClientError::UnexpectedFrame {
                expected: FrameType::ProofResp,
                actual: frame.header.frame_type,
            });
        }

        ProofRespMsg::from_payload(&frame.payload).map_err(ClientError::from)
    }

    /// Send a heartbeat ping to measure network round-trip latency.
    pub async fn ping(&mut self) -> Result<Duration, ClientError> {
        let stream_id = self.allocate_stream_id();
        let start = Instant::now();
        let ping_msg = HeartbeatPingMsg {
            timestamp_us: start.elapsed().as_micros() as u64,
        };
        self.framed.send(ping_msg.to_frame(stream_id)?).await?;

        let frame = self
            .framed
            .next()
            .await
            .ok_or(ClientError::ConnectionClosed)??;

        if frame.header.frame_type != FrameType::HeartbeatPong {
            return Err(ClientError::UnexpectedFrame {
                expected: FrameType::HeartbeatPong,
                actual: frame.header.frame_type,
            });
        }

        Ok(start.elapsed())
    }
}
