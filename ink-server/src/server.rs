//! TCP Server Daemon for Ink Wire Protocol (IWP/1.0).

use anyhow::{Context, Result};
use ed25519_dalek::{Verifier, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use ink_core::{auth::Role, record::compute_record_hash, segment::now_micros, Store};
use ink_proto::{
    compute_auth_digest, AppendChallengeMsg, AppendCommitMsg, AppendInitMsg, AuthFailMsg,
    AuthOkMsg, AuthRespMsg, ChallengeMsg, ErrorCode, FrameCodec, FrameType, HeartbeatPongMsg,
    HelloReqMsg, ProofRespMsg, QueryCompleteMsg, QueryReqMsg, RowDataMsg, RowHeaderMsg,
    TreeHeadRespMsg, CURRENT_VERSION,
};
use ink_query::query_authenticated;
use rand_core::{OsRng, RngCore};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};
use tokio_util::codec::Framed;

/// Active reservation lease for a remote two-step signed append.
#[derive(Debug, Clone)]
struct AppendLease {
    _lease_token: [u8; 16],
    table_name: String,
    author: [u8; 32],
    record_id: u64,
    timestamp_us: i64,
    _canonical_record_hash: [u8; 32],
    data: Vec<u8>,
    expires_at: Instant,
}

/// Token bucket and failure lockout tracker per IP address.
struct IpTracker {
    last_attempt: Instant,
    tokens: f64,
    failed_handshakes: u32,
    blocked_until: Option<Instant>,
}

impl IpTracker {
    fn new() -> Self {
        Self {
            last_attempt: Instant::now(),
            tokens: 20.0,
            failed_handshakes: 0,
            blocked_until: None,
        }
    }

    fn check_allowed(&mut self) -> Result<(), ErrorCode> {
        let now = Instant::now();
        if let Some(until) = self.blocked_until {
            if now < until {
                return Err(ErrorCode::IpBlocked);
            } else {
                self.blocked_until = None;
                self.failed_handshakes = 0;
            }
        }

        let elapsed = now.duration_since(self.last_attempt).as_secs_f64();
        self.last_attempt = now;
        self.tokens = (self.tokens + elapsed * (20.0 / 60.0)).min(20.0);

        if self.tokens < 1.0 {
            return Err(ErrorCode::RateLimited);
        }
        self.tokens -= 1.0;
        Ok(())
    }

    fn record_failed_handshake(&mut self) {
        self.failed_handshakes = self.failed_handshakes.saturating_add(1);
        if self.failed_handshakes >= 5 {
            // 15-minute ban
            self.blocked_until = Some(Instant::now() + Duration::from_secs(15 * 60));
        }
    }

    fn record_successful_handshake(&mut self) {
        self.failed_handshakes = 0;
    }
}

/// Ink TCP server daemon instance.
pub struct TcpDaemon {
    store: Arc<Mutex<Store>>,
    leases: Arc<Mutex<HashMap<[u8; 16], AppendLease>>>,
    rate_limiter: Arc<Mutex<HashMap<std::net::IpAddr, IpTracker>>>,
    bind_addr: String,
    max_unauth_conns: usize,
}

impl TcpDaemon {
    /// Construct a new TCP daemon bound to `bind_addr`.
    pub fn new(store: Store, bind_addr: String, max_unauth_conns: usize) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            leases: Arc::new(Mutex::new(HashMap::new())),
            rate_limiter: Arc::new(Mutex::new(HashMap::new())),
            bind_addr,
            max_unauth_conns,
        }
    }

    /// Bind to address, spawn the accept loop in a background task, and return the local `SocketAddr` and handle.
    pub async fn start(
        store: Store,
        bind_addr: &str,
        max_unauth_conns: usize,
    ) -> Result<(SocketAddr, tokio::task::JoinHandle<Result<()>>)> {
        let listener = TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("Failed to bind TCP listener to {}", bind_addr))?;
        let local_addr = listener.local_addr()?;

        let daemon = Arc::new(Self {
            store: Arc::new(Mutex::new(store)),
            leases: Arc::new(Mutex::new(HashMap::new())),
            rate_limiter: Arc::new(Mutex::new(HashMap::new())),
            bind_addr: bind_addr.to_string(),
            max_unauth_conns,
        });

        let handle = tokio::spawn(async move { daemon.run_with_listener(listener).await });

        Ok((local_addr, handle))
    }

    /// Run the server accept loop using a pre-bound listener.
    pub async fn run_with_listener(&self, listener: TcpListener) -> Result<()> {
        let unauth_sem = Arc::new(Semaphore::new(self.max_unauth_conns));

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(res) => res,
                Err(e) => {
                    eprintln!("Accept error: {}", e);
                    continue;
                }
            };

            let permit = match unauth_sem.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    eprintln!(
                        "Max concurrent unauthenticated connections reached; dropping {}",
                        peer_addr
                    );
                    drop(stream);
                    continue;
                }
            };

            let store_clone = self.store.clone();
            let leases_clone = self.leases.clone();
            let rate_limiter_clone = self.rate_limiter.clone();

            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = handle_client(
                    stream,
                    peer_addr,
                    store_clone,
                    leases_clone,
                    rate_limiter_clone,
                )
                .await
                {
                    eprintln!("Session [{}] error: {}", peer_addr, e);
                }
            });
        }
    }

    /// Run the server accept loop.
    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.bind_addr)
            .await
            .with_context(|| format!("Failed to bind TCP listener to {}", self.bind_addr))?;

        println!("Ink TCP server listening on {}", self.bind_addr);
        println!("  Wire Protocol:  IWP/1.0");
        println!("  Max Unauth:     {}", self.max_unauth_conns);

        self.run_with_listener(listener).await
    }
}

async fn handle_client(
    stream: TcpStream,
    peer_addr: SocketAddr,
    store: Arc<Mutex<Store>>,
    leases: Arc<Mutex<HashMap<[u8; 16], AppendLease>>>,
    rate_limiter: Arc<Mutex<HashMap<std::net::IpAddr, IpTracker>>>,
) -> Result<()> {
    // Check IP rate limits
    {
        let mut limiter = rate_limiter.lock().await;
        let tracker = limiter.entry(peer_addr.ip()).or_insert_with(IpTracker::new);
        if let Err(code) = tracker.check_allowed() {
            let mut framed = Framed::new(stream, FrameCodec::new());
            let fail = AuthFailMsg {
                error_code: code.as_u16(),
                reason: code.name().to_string(),
            };
            let _ = framed.send(fail.to_frame(0)?).await;
            return Ok(());
        }
    }

    let mut framed = Framed::new(stream, FrameCodec::new());

    // Step 1: Handshake within 5,000 ms timeout
    let handshake_res = tokio::time::timeout(
        Duration::from_millis(5000),
        perform_handshake(&mut framed, peer_addr, store.clone(), rate_limiter.clone()),
    )
    .await;

    let client_pubkey = match handshake_res {
        Ok(Ok(pubkey)) => pubkey,
        Ok(Err(e)) => {
            let fail = AuthFailMsg {
                error_code: ErrorCode::AccessDenied.as_u16(),
                reason: "Access denied".into(),
            };
            let _ = framed.send(fail.to_frame(0)?).await;
            return Err(e);
        }
        Err(_) => {
            let fail = AuthFailMsg {
                error_code: ErrorCode::ChallengeTimeout.as_u16(),
                reason: "Authentication challenge timed out".into(),
            };
            let _ = framed.send(fail.to_frame(0)?).await;
            return Ok(());
        }
    };

    // Client authenticated! Process request stream.
    while let Some(frame_res) = framed.next().await {
        let frame = frame_res?;
        let stream_id = frame.header.stream_id;

        match frame.header.frame_type {
            FrameType::HeartbeatPing => {
                let ping = ink_proto::HeartbeatPingMsg::from_payload(&frame.payload)?;
                let pong = HeartbeatPongMsg {
                    timestamp_us: ping.timestamp_us,
                };
                framed.send(pong.to_frame(stream_id)?).await?;
            }

            FrameType::QueryReq => {
                let query_msg = QueryReqMsg::from_payload(&frame.payload)?;
                let start = Instant::now();
                let mut st = store.lock().await;
                match query_authenticated(&mut st, &query_msg.iql, Some(&client_pubkey)) {
                    Ok(query_res) => {
                        let exec_us = start.elapsed().as_micros() as u64;
                        let (columns, rows) = query_result_to_rows(query_res);
                        let rows_len = rows.len() as u64;

                        // Send column header
                        framed
                            .send(RowHeaderMsg { columns }.to_frame(stream_id)?)
                            .await?;

                        // Stream rows
                        for (idx, row) in rows.into_iter().enumerate() {
                            let row_msg = RowDataMsg {
                                row_id: idx as u64,
                                data_json: row.to_string(),
                            };
                            framed.send(row_msg.to_frame(stream_id)?).await?;
                        }

                        // Send query complete
                        let complete = QueryCompleteMsg {
                            rows_returned: rows_len,
                            execution_time_us: exec_us,
                        };
                        framed.send(complete.to_frame(stream_id)?).await?;
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        let error_code = if err_str.contains("Access denied") {
                            ErrorCode::AccessDenied.as_u16()
                        } else {
                            ErrorCode::QueryExecFailed.as_u16()
                        };
                        let fail = AuthFailMsg {
                            error_code,
                            reason: err_str,
                        };
                        framed.send(fail.to_frame(stream_id)?).await?;
                    }
                }
            }

            FrameType::AppendInit => {
                let init = AppendInitMsg::from_payload(&frame.payload)?;

                let st = store.lock().await;
                let now = now_micros();

                // Enforce writer permissions on table
                if !st.is_authorized(&client_pubkey, Role::Writer, &init.table_name)
                    && !st.is_authorized(&client_pubkey, Role::Admin, &init.table_name)
                {
                    drop(st);
                    let fail = AuthFailMsg {
                        error_code: ErrorCode::AccessDenied.as_u16(),
                        reason: format!(
                            "Access denied: insufficient permissions to write to '{}'",
                            init.table_name
                        ),
                    };
                    framed.send(fail.to_frame(stream_id)?).await?;
                    continue;
                }

                // Validate JSON syntax
                let json_data = init.data_json.as_bytes();
                if let Err(e) = serde_json::from_slice::<serde_json::Value>(json_data) {
                    drop(st);
                    let fail = AuthFailMsg {
                        error_code: ErrorCode::PayloadValidationError.as_u16(),
                        reason: format!("Invalid JSON payload: {}", e),
                    };
                    framed.send(fail.to_frame(stream_id)?).await?;
                    continue;
                }

                let next_id = st.next_global_id();
                let prev_hash = st.last_hash_for_table(&init.table_name);
                let canonical_record_hash = compute_record_hash(
                    next_id,
                    now,
                    &init.table_name,
                    &client_pubkey,
                    0,
                    None,
                    json_data,
                    &prev_hash,
                );

                let mut lease_token = [0u8; 16];
                OsRng.fill_bytes(&mut lease_token);

                let lease = AppendLease {
                    _lease_token: lease_token,
                    table_name: init.table_name,
                    author: client_pubkey,
                    record_id: next_id,
                    timestamp_us: now,
                    _canonical_record_hash: canonical_record_hash,
                    data: json_data.to_vec(),
                    expires_at: Instant::now() + Duration::from_millis(2000),
                };

                leases.lock().await.insert(lease_token, lease);
                drop(st);

                let chal = AppendChallengeMsg {
                    lease_token,
                    record_id: next_id,
                    timestamp_us: now as u64,
                    canonical_record_hash,
                    lease_duration_ms: 2000,
                };
                framed.send(chal.to_frame(stream_id)?).await?;
            }

            FrameType::AppendCommit => {
                let commit = AppendCommitMsg::from_payload(&frame.payload)?;

                let lease = leases.lock().await.remove(&commit.lease_token);
                let lease = match lease {
                    Some(l) => {
                        if Instant::now() > l.expires_at {
                            let fail = AuthFailMsg {
                                error_code: ErrorCode::LeaseExpired.as_u16(),
                                reason: "Append lease expired".into(),
                            };
                            framed.send(fail.to_frame(stream_id)?).await?;
                            continue;
                        }
                        l
                    }
                    None => {
                        let fail = AuthFailMsg {
                            error_code: ErrorCode::LeaseExpired.as_u16(),
                            reason: "Invalid or expired append lease token".into(),
                        };
                        framed.send(fail.to_frame(stream_id)?).await?;
                        continue;
                    }
                };

                let mut st = store.lock().await;
                match st.append_signed_with_signature(
                    &lease.table_name,
                    &lease.data,
                    lease.author,
                    commit.signature,
                    lease.record_id,
                    lease.timestamp_us,
                ) {
                    Ok(rec) => {
                        let conf_row = RowDataMsg {
                            row_id: rec.id,
                            data_json: format!(
                                "{{\"record_id\":{},\"hash\":\"{}\",\"timestamp\":{}}}",
                                rec.id,
                                hex::encode(rec.record_hash),
                                rec.timestamp
                            ),
                        };
                        framed.send(conf_row.to_frame(stream_id)?).await?;
                        framed
                            .send(
                                QueryCompleteMsg {
                                    rows_returned: 1,
                                    execution_time_us: 100,
                                }
                                .to_frame(stream_id)?,
                            )
                            .await?;
                    }
                    Err(e) => {
                        let fail = AuthFailMsg {
                            error_code: ErrorCode::InvalidSignature.as_u16(),
                            reason: format!("Failed to commit record: {}", e),
                        };
                        framed.send(fail.to_frame(stream_id)?).await?;
                    }
                }
            }

            FrameType::TreeHeadReq => {
                let st = store.lock().await;
                let (tree_size, root_hash) = st.tree_head_info();
                drop(st);
                let resp = TreeHeadRespMsg {
                    tree_size,
                    root_hash,
                };
                framed.send(resp.to_frame(stream_id)?).await?;
            }

            FrameType::ProofReq => {
                let proof_req = ink_proto::ProofReqMsg::from_payload(&frame.payload)?;
                let st = store.lock().await;
                match st.get_inclusion_proof(proof_req.record_id) {
                    Ok(proof) => {
                        let audit_path_bytes: Vec<[u8; 32]> = proof
                            .audit_path
                            .iter()
                            .filter_map(|hex_s| {
                                let b = hex::decode(hex_s).ok()?;
                                let arr: [u8; 32] = b.try_into().ok()?;
                                Some(arr)
                            })
                            .collect();
                        let resp = ProofRespMsg {
                            record_id: proof_req.record_id,
                            tree_size: proof.tree_size,
                            audit_path: audit_path_bytes,
                        };
                        framed.send(resp.to_frame(stream_id)?).await?;
                    }
                    Err(e) => {
                        let fail = AuthFailMsg {
                            error_code: ErrorCode::QueryExecFailed.as_u16(),
                            reason: format!("Proof generation failed: {}", e),
                        };
                        framed.send(fail.to_frame(stream_id)?).await?;
                    }
                }
            }

            _ => {
                // Ignore unexpected frame types
            }
        }
    }

    Ok(())
}

async fn perform_handshake(
    framed: &mut Framed<TcpStream, FrameCodec>,
    peer_addr: SocketAddr,
    store: Arc<Mutex<Store>>,
    rate_limiter: Arc<Mutex<HashMap<std::net::IpAddr, IpTracker>>>,
) -> Result<[u8; 32]> {
    // Step 1: Read HELLO_REQ
    let frame = framed
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("Connection closed before HELLO_REQ"))??;

    if frame.header.frame_type != FrameType::HelloReq {
        anyhow::bail!("Expected HELLO_REQ, got {:?}", frame.header.frame_type);
    }

    let hello = HelloReqMsg::from_payload(&frame.payload)?;
    let client_pubkey = hello.client_pubkey;

    // Generate fresh single-use random nonce and session ID
    let mut nonce = [0u8; 32];
    let mut session_id = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    OsRng.fill_bytes(&mut session_id);

    let (database_id_bytes, is_registered, roles) = {
        let st = store.lock().await;
        let db_id_str = st.database_id();
        let db_uuid = uuid::Uuid::parse_str(db_id_str).unwrap_or_else(|_| uuid::Uuid::nil());
        let db_bytes = *db_uuid.as_bytes();

        let now = now_micros();
        // A key is authorized to connect if it holds ANY non-expired grant on ANY table.
        // Per-table grants (e.g. Reader on "sales") do not use the wildcard "*" table;
        // we must check the raw grant list rather than a fixed table scope.
        let authorized = match st.acl().get_grants_for_key(&client_pubkey) {
            Some(grants) => grants.iter().any(|g| !g.is_expired(now)),
            None => false,
        };

        let roles_vec = if st.acl().is_admin(&client_pubkey, now) {
            vec!["admin".to_string()]
        } else {
            vec!["user".to_string()]
        };

        (db_bytes, authorized, roles_vec)
    };

    // Step 2: Send CHALLENGE
    let challenge = ChallengeMsg {
        database_id: database_id_bytes,
        nonce,
        session_id,
        auth_timeout_ms: 5000,
    };
    framed.send(challenge.to_frame(0)?).await?;

    // Step 3: Read AUTH_RESP
    let resp_frame = framed
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("Connection closed before AUTH_RESP"))??;

    if resp_frame.header.frame_type != FrameType::AuthResp {
        anyhow::bail!("Expected AUTH_RESP, got {:?}", resp_frame.header.frame_type);
    }

    let auth_resp = AuthRespMsg::from_payload(&resp_frame.payload)?;
    if auth_resp.session_id != session_id {
        anyhow::bail!("Session ID mismatch in AUTH_RESP");
    }

    // Verify signature over canonical challenge digest
    let digest = compute_auth_digest(&database_id_bytes, &nonce, &session_id, &[0u8; 32]);
    let vk = VerifyingKey::from_bytes(&client_pubkey);

    let mut sig_valid = false;
    if let Ok(verifying_key) = vk {
        let sig = ed25519_dalek::Signature::from_bytes(&auth_resp.signature);
        if verifying_key.verify(&digest, &sig).is_ok() {
            sig_valid = true;
        }
    }

    // Constant-time check: must have valid signature AND be authorized
    if !sig_valid || !is_registered {
        // Record failure against IP
        let mut limiter = rate_limiter.lock().await;
        if let Some(tracker) = limiter.get_mut(&peer_addr.ip()) {
            tracker.record_failed_handshake();
        }
        anyhow::bail!("Access denied");
    }

    // Record success
    {
        let mut limiter = rate_limiter.lock().await;
        if let Some(tracker) = limiter.get_mut(&peer_addr.ip()) {
            tracker.record_successful_handshake();
        }
    }

    // Step 4: Send AUTH_OK
    let roles_json = serde_json::to_string(&roles)?;
    let auth_ok = AuthOkMsg {
        session_id,
        server_version: CURRENT_VERSION as u16,
        roles_json,
    };
    framed.send(auth_ok.to_frame(0)?).await?;

    Ok(client_pubkey)
}

fn query_result_to_rows(qr: ink_query::QueryResult) -> (Vec<String>, Vec<serde_json::Value>) {
    match qr {
        ink_query::QueryResult::Records(recs) | ink_query::QueryResult::History(recs) => {
            let cols = vec![
                "id".to_string(),
                "timestamp".to_string(),
                "author".to_string(),
                "data".to_string(),
                "hash".to_string(),
            ];
            let rows = recs
                .into_iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id,
                        "timestamp": r.timestamp,
                        "author": r.author,
                        "data": r.data,
                        "hash": r.hash,
                    })
                })
                .collect();
            (cols, rows)
        }
        ink_query::QueryResult::Appended(r) | ink_query::QueryResult::Corrected(r) => {
            let cols = vec!["id".to_string(), "status".to_string(), "hash".to_string()];
            let rows = vec![serde_json::json!({
                "id": r.id,
                "status": "committed",
                "hash": r.hash,
            })];
            (cols, rows)
        }
        ink_query::QueryResult::Scalar(val) => {
            let cols = vec!["result".to_string()];
            let rows = vec![serde_json::json!({ "result": val })];
            (cols, rows)
        }
        ink_query::QueryResult::Grouped(pairs) => {
            let cols = vec!["group".to_string(), "value".to_string()];
            let rows = pairs
                .into_iter()
                .map(|(g, v)| serde_json::json!({ "group": g, "value": v }))
                .collect();
            (cols, rows)
        }
        ink_query::QueryResult::Tables(tables) => {
            let cols = vec!["table_name".to_string()];
            let rows = tables
                .into_iter()
                .map(|t| serde_json::json!({ "table_name": t }))
                .collect();
            (cols, rows)
        }
        ink_query::QueryResult::Status(s) => {
            let cols = vec!["property".to_string(), "value".to_string()];
            let rows = vec![
                serde_json::json!({ "property": "record_count", "value": s.record_count }),
                serde_json::json!({ "property": "table_count", "value": s.table_count }),
                serde_json::json!({ "property": "tree_head", "value": s.tree_head }),
            ];
            (cols, rows)
        }
        ink_query::QueryResult::Verification(v) => {
            let cols = vec![
                "is_valid".to_string(),
                "records_checked".to_string(),
                "errors".to_string(),
            ];
            let rows = vec![serde_json::json!({
                "is_valid": v.is_valid,
                "records_checked": v.records_checked,
                "errors": v.errors,
            })];
            (cols, rows)
        }
    }
}
