//! Strongly typed message definitions and wire conversions for IWP/1.0.

use crate::error::ProtoError;
use crate::frame::{FrameType, RawFrame};

/// `HELLO_REQ` (0x01) — Initial client greeting presenting public key and version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloReqMsg {
    /// Client Ed25519 public key (32 bytes).
    pub client_pubkey: [u8; 32],
    /// Client wire protocol version.
    pub client_version: u16,
    /// Bitmask of client protocol capabilities.
    pub capabilities: u32,
}

impl HelloReqMsg {
    /// Encode into a `RawFrame`.
    pub fn to_frame(&self, stream_id: u32) -> Result<RawFrame, ProtoError> {
        let mut payload = Vec::with_capacity(38);
        payload.extend_from_slice(&self.client_pubkey);
        payload.extend_from_slice(&self.client_version.to_le_bytes());
        payload.extend_from_slice(&self.capabilities.to_le_bytes());
        RawFrame::new(FrameType::HelloReq, 0, stream_id, payload)
    }

    /// Decode from payload bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, ProtoError> {
        if payload.len() < 38 {
            return Err(ProtoError::IncompletePayload {
                expected: 38,
                actual: payload.len(),
            });
        }
        let mut client_pubkey = [0u8; 32];
        client_pubkey.copy_from_slice(&payload[0..32]);
        let client_version = u16::from_le_bytes([payload[32], payload[33]]);
        let capabilities = u32::from_le_bytes([payload[34], payload[35], payload[36], payload[37]]);
        Ok(Self {
            client_pubkey,
            client_version,
            capabilities,
        })
    }
}

/// `CHALLENGE` (0x02) — Server response presenting authentication challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeMsg {
    /// Target database UUID (16 bytes).
    pub database_id: [u8; 16],
    /// Fresh single-use random server nonce (32 bytes).
    pub nonce: [u8; 32],
    /// Unique connection session ID (16 bytes).
    pub session_id: [u8; 16],
    /// Maximum milliseconds allowed to submit `AUTH_RESP`.
    pub auth_timeout_ms: u32,
}

impl ChallengeMsg {
    /// Encode into a `RawFrame`.
    pub fn to_frame(&self, stream_id: u32) -> Result<RawFrame, ProtoError> {
        let mut payload = Vec::with_capacity(68);
        payload.extend_from_slice(&self.database_id);
        payload.extend_from_slice(&self.nonce);
        payload.extend_from_slice(&self.session_id);
        payload.extend_from_slice(&self.auth_timeout_ms.to_le_bytes());
        RawFrame::new(FrameType::Challenge, 0, stream_id, payload)
    }

    /// Decode from payload bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, ProtoError> {
        if payload.len() < 68 {
            return Err(ProtoError::IncompletePayload {
                expected: 68,
                actual: payload.len(),
            });
        }
        let mut database_id = [0u8; 16];
        database_id.copy_from_slice(&payload[0..16]);
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&payload[16..48]);
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&payload[48..64]);
        let auth_timeout_ms =
            u32::from_le_bytes([payload[64], payload[65], payload[66], payload[67]]);
        Ok(Self {
            database_id,
            nonce,
            session_id,
            auth_timeout_ms,
        })
    }
}

/// `AUTH_RESP` (0x03) — Client response with Ed25519 signature over challenge digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRespMsg {
    /// Session ID matching the received challenge.
    pub session_id: [u8; 16],
    /// Ed25519 signature over challenge digest (64 bytes).
    pub signature: [u8; 64],
}

impl AuthRespMsg {
    /// Encode into a `RawFrame`.
    pub fn to_frame(&self, stream_id: u32) -> Result<RawFrame, ProtoError> {
        let mut payload = Vec::with_capacity(80);
        payload.extend_from_slice(&self.session_id);
        payload.extend_from_slice(&self.signature);
        RawFrame::new(FrameType::AuthResp, 0, stream_id, payload)
    }

    /// Decode from payload bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, ProtoError> {
        if payload.len() < 80 {
            return Err(ProtoError::IncompletePayload {
                expected: 80,
                actual: payload.len(),
            });
        }
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&payload[0..16]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&payload[16..80]);
        Ok(Self {
            session_id,
            signature,
        })
    }
}

/// `AUTH_OK` (0x04) — Server confirmation of authentication success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthOkMsg {
    /// Session ID.
    pub session_id: [u8; 16],
    /// Server protocol version.
    pub server_version: u16,
    /// JSON serialization of granted user roles.
    pub roles_json: String,
}

impl AuthOkMsg {
    /// Encode into a `RawFrame`.
    pub fn to_frame(&self, stream_id: u32) -> Result<RawFrame, ProtoError> {
        let roles_bytes = self.roles_json.as_bytes();
        let mut payload = Vec::with_capacity(16 + 2 + 2 + roles_bytes.len());
        payload.extend_from_slice(&self.session_id);
        payload.extend_from_slice(&self.server_version.to_le_bytes());
        payload.extend_from_slice(&(roles_bytes.len() as u16).to_le_bytes());
        payload.extend_from_slice(roles_bytes);
        RawFrame::new(FrameType::AuthOk, 0, stream_id, payload)
    }

    /// Decode from payload bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, ProtoError> {
        if payload.len() < 20 {
            return Err(ProtoError::IncompletePayload {
                expected: 20,
                actual: payload.len(),
            });
        }
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&payload[0..16]);
        let server_version = u16::from_le_bytes([payload[16], payload[17]]);
        let roles_len = u16::from_le_bytes([payload[18], payload[19]]) as usize;
        if payload.len() < 20 + roles_len {
            return Err(ProtoError::IncompletePayload {
                expected: 20 + roles_len,
                actual: payload.len(),
            });
        }
        let roles_json = String::from_utf8(payload[20..20 + roles_len].to_vec())?;
        Ok(Self {
            session_id,
            server_version,
            roles_json,
        })
    }
}

/// `AUTH_FAIL` (0x05) — Server rejection of authentication attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthFailMsg {
    /// Error code (e.g. 0x0403).
    pub error_code: u16,
    /// Reason description.
    pub reason: String,
}

impl AuthFailMsg {
    /// Encode into a `RawFrame`.
    pub fn to_frame(&self, stream_id: u32) -> Result<RawFrame, ProtoError> {
        let reason_bytes = self.reason.as_bytes();
        let mut payload = Vec::with_capacity(4 + reason_bytes.len());
        payload.extend_from_slice(&self.error_code.to_le_bytes());
        payload.extend_from_slice(&(reason_bytes.len() as u16).to_le_bytes());
        payload.extend_from_slice(reason_bytes);
        RawFrame::new(FrameType::AuthFail, 0, stream_id, payload)
    }

    /// Decode from payload bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, ProtoError> {
        if payload.len() < 4 {
            return Err(ProtoError::IncompletePayload {
                expected: 4,
                actual: payload.len(),
            });
        }
        let error_code = u16::from_le_bytes([payload[0], payload[1]]);
        let reason_len = u16::from_le_bytes([payload[2], payload[3]]) as usize;
        if payload.len() < 4 + reason_len {
            return Err(ProtoError::IncompletePayload {
                expected: 4 + reason_len,
                actual: payload.len(),
            });
        }
        let reason = String::from_utf8(payload[4..4 + reason_len].to_vec())?;
        Ok(Self { error_code, reason })
    }
}

/// `QUERY_REQ` (0x10) — Request to execute an IQL query statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryReqMsg {
    /// IQL statement string.
    pub iql: String,
}

impl QueryReqMsg {
    /// Encode into a `RawFrame`.
    pub fn to_frame(&self, stream_id: u32) -> Result<RawFrame, ProtoError> {
        let bytes = self.iql.as_bytes();
        let mut payload = Vec::with_capacity(4 + bytes.len());
        payload.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        payload.extend_from_slice(bytes);
        RawFrame::new(FrameType::QueryReq, 0, stream_id, payload)
    }

    /// Decode from payload bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, ProtoError> {
        if payload.len() < 4 {
            return Err(ProtoError::IncompletePayload {
                expected: 4,
                actual: payload.len(),
            });
        }
        let len = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
        if payload.len() < 4 + len {
            return Err(ProtoError::IncompletePayload {
                expected: 4 + len,
                actual: payload.len(),
            });
        }
        let iql = String::from_utf8(payload[4..4 + len].to_vec())?;
        Ok(Self { iql })
    }
}

/// `ROW_HEADER` (0x11) — Column names for tabular streaming query results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowHeaderMsg {
    /// Column names in order.
    pub columns: Vec<String>,
}

impl RowHeaderMsg {
    /// Encode into a `RawFrame`.
    pub fn to_frame(&self, stream_id: u32) -> Result<RawFrame, ProtoError> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(self.columns.len() as u16).to_le_bytes());
        for col in &self.columns {
            let col_bytes = col.as_bytes();
            payload.extend_from_slice(&(col_bytes.len() as u16).to_le_bytes());
            payload.extend_from_slice(col_bytes);
        }
        RawFrame::new(FrameType::RowHeader, 0, stream_id, payload)
    }

    /// Decode from payload bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, ProtoError> {
        if payload.len() < 2 {
            return Err(ProtoError::IncompletePayload {
                expected: 2,
                actual: payload.len(),
            });
        }
        let count = u16::from_le_bytes([payload[0], payload[1]]) as usize;
        let mut offset = 2;
        let mut columns = Vec::with_capacity(count);
        for _ in 0..count {
            if payload.len() < offset + 2 {
                return Err(ProtoError::IncompletePayload {
                    expected: offset + 2,
                    actual: payload.len(),
                });
            }
            let col_len = u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
            offset += 2;
            if payload.len() < offset + col_len {
                return Err(ProtoError::IncompletePayload {
                    expected: offset + col_len,
                    actual: payload.len(),
                });
            }
            let col_name = String::from_utf8(payload[offset..offset + col_len].to_vec())?;
            offset += col_len;
            columns.push(col_name);
        }
        Ok(Self { columns })
    }
}

/// `ROW_DATA` (0x12) — Single row payload in streaming query results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowDataMsg {
    /// Sequential record ID.
    pub row_id: u64,
    /// Raw record payload JSON string.
    pub data_json: String,
}

impl RowDataMsg {
    /// Encode into a `RawFrame`.
    pub fn to_frame(&self, stream_id: u32) -> Result<RawFrame, ProtoError> {
        let data_bytes = self.data_json.as_bytes();
        let mut payload = Vec::with_capacity(8 + 4 + data_bytes.len());
        payload.extend_from_slice(&self.row_id.to_le_bytes());
        payload.extend_from_slice(&(data_bytes.len() as u32).to_le_bytes());
        payload.extend_from_slice(data_bytes);
        RawFrame::new(FrameType::RowData, 0, stream_id, payload)
    }

    /// Decode from payload bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, ProtoError> {
        if payload.len() < 12 {
            return Err(ProtoError::IncompletePayload {
                expected: 12,
                actual: payload.len(),
            });
        }
        let row_id = u64::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
            payload[7],
        ]);
        let data_len =
            u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]) as usize;
        if payload.len() < 12 + data_len {
            return Err(ProtoError::IncompletePayload {
                expected: 12 + data_len,
                actual: payload.len(),
            });
        }
        let data_json = String::from_utf8(payload[12..12 + data_len].to_vec())?;
        Ok(Self { row_id, data_json })
    }
}

/// `QUERY_COMPLETE` (0x13) — Query completion notification with summary metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryCompleteMsg {
    /// Total count of rows returned by query.
    pub rows_returned: u64,
    /// Execution duration in microseconds.
    pub execution_time_us: u64,
}

impl QueryCompleteMsg {
    /// Encode into a `RawFrame`.
    pub fn to_frame(&self, stream_id: u32) -> Result<RawFrame, ProtoError> {
        let mut payload = Vec::with_capacity(16);
        payload.extend_from_slice(&self.rows_returned.to_le_bytes());
        payload.extend_from_slice(&self.execution_time_us.to_le_bytes());
        RawFrame::new(FrameType::QueryComplete, 0, stream_id, payload)
    }

    /// Decode from payload bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, ProtoError> {
        if payload.len() < 16 {
            return Err(ProtoError::IncompletePayload {
                expected: 16,
                actual: payload.len(),
            });
        }
        let rows_returned = u64::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
            payload[7],
        ]);
        let execution_time_us = u64::from_le_bytes([
            payload[8],
            payload[9],
            payload[10],
            payload[11],
            payload[12],
            payload[13],
            payload[14],
            payload[15],
        ]);
        Ok(Self {
            rows_returned,
            execution_time_us,
        })
    }
}

/// `REQ_CANCEL` (0x14) — Request cancellation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReqCancelMsg {
    /// Cancellation reason.
    pub reason: String,
}

impl ReqCancelMsg {
    /// Encode into a `RawFrame`.
    pub fn to_frame(&self, stream_id: u32) -> Result<RawFrame, ProtoError> {
        let bytes = self.reason.as_bytes();
        let mut payload = Vec::with_capacity(2 + bytes.len());
        payload.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        payload.extend_from_slice(bytes);
        RawFrame::new(FrameType::ReqCancel, 0, stream_id, payload)
    }

    /// Decode from payload bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, ProtoError> {
        if payload.len() < 2 {
            return Err(ProtoError::IncompletePayload {
                expected: 2,
                actual: payload.len(),
            });
        }
        let len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
        if payload.len() < 2 + len {
            return Err(ProtoError::IncompletePayload {
                expected: 2 + len,
                actual: payload.len(),
            });
        }
        let reason = String::from_utf8(payload[2..2 + len].to_vec())?;
        Ok(Self { reason })
    }
}

/// `APPEND_INIT` (0x15) — Client step 1 of remote signing flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendInitMsg {
    /// Target table name.
    pub table_name: String,
    /// Record payload JSON string.
    pub data_json: String,
}

impl AppendInitMsg {
    /// Encode into a `RawFrame`.
    pub fn to_frame(&self, stream_id: u32) -> Result<RawFrame, ProtoError> {
        let table_bytes = self.table_name.as_bytes();
        let data_bytes = self.data_json.as_bytes();
        let mut payload = Vec::with_capacity(2 + table_bytes.len() + 4 + data_bytes.len());
        payload.extend_from_slice(&(table_bytes.len() as u16).to_le_bytes());
        payload.extend_from_slice(table_bytes);
        payload.extend_from_slice(&(data_bytes.len() as u32).to_le_bytes());
        payload.extend_from_slice(data_bytes);
        RawFrame::new(FrameType::AppendInit, 0, stream_id, payload)
    }

    /// Decode from payload bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, ProtoError> {
        if payload.len() < 6 {
            return Err(ProtoError::IncompletePayload {
                expected: 6,
                actual: payload.len(),
            });
        }
        let table_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
        let mut offset = 2;
        if payload.len() < offset + table_len + 4 {
            return Err(ProtoError::IncompletePayload {
                expected: offset + table_len + 4,
                actual: payload.len(),
            });
        }
        let table_name = String::from_utf8(payload[offset..offset + table_len].to_vec())?;
        offset += table_len;

        let data_len = u32::from_le_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
        ]) as usize;
        offset += 4;

        if payload.len() < offset + data_len {
            return Err(ProtoError::IncompletePayload {
                expected: offset + data_len,
                actual: payload.len(),
            });
        }
        let data_json = String::from_utf8(payload[offset..offset + data_len].to_vec())?;
        Ok(Self {
            table_name,
            data_json,
        })
    }
}

/// `APPEND_CHALLENGE` (0x16) — Server step 2: reservation and canonical digest challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendChallengeMsg {
    /// Ephemeral lease token (16 bytes).
    pub lease_token: [u8; 16],
    /// Reserved sequential record ID.
    pub record_id: u64,
    /// Assigned record creation timestamp in microseconds since Unix epoch.
    pub timestamp_us: u64,
    /// Canonical BLAKE3 record hash to be signed by the author.
    pub canonical_record_hash: [u8; 32],
    /// Duration of the reservation lease in milliseconds.
    pub lease_duration_ms: u32,
}

impl AppendChallengeMsg {
    /// Encode into a `RawFrame`.
    pub fn to_frame(&self, stream_id: u32) -> Result<RawFrame, ProtoError> {
        let mut payload = Vec::with_capacity(68);
        payload.extend_from_slice(&self.lease_token);
        payload.extend_from_slice(&self.record_id.to_le_bytes());
        payload.extend_from_slice(&self.timestamp_us.to_le_bytes());
        payload.extend_from_slice(&self.canonical_record_hash);
        payload.extend_from_slice(&self.lease_duration_ms.to_le_bytes());
        RawFrame::new(FrameType::AppendChallenge, 0, stream_id, payload)
    }

    /// Decode from payload bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, ProtoError> {
        if payload.len() < 68 {
            return Err(ProtoError::IncompletePayload {
                expected: 68,
                actual: payload.len(),
            });
        }
        let mut lease_token = [0u8; 16];
        lease_token.copy_from_slice(&payload[0..16]);
        let record_id = u64::from_le_bytes([
            payload[16],
            payload[17],
            payload[18],
            payload[19],
            payload[20],
            payload[21],
            payload[22],
            payload[23],
        ]);
        let timestamp_us = u64::from_le_bytes([
            payload[24],
            payload[25],
            payload[26],
            payload[27],
            payload[28],
            payload[29],
            payload[30],
            payload[31],
        ]);
        let mut canonical_record_hash = [0u8; 32];
        canonical_record_hash.copy_from_slice(&payload[32..64]);
        let lease_duration_ms =
            u32::from_le_bytes([payload[64], payload[65], payload[66], payload[67]]);
        Ok(Self {
            lease_token,
            record_id,
            timestamp_us,
            canonical_record_hash,
            lease_duration_ms,
        })
    }
}

/// `APPEND_COMMIT` (0x17) — Client step 3: signature submission committing the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendCommitMsg {
    /// Ephemeral lease token matching the challenge.
    pub lease_token: [u8; 16],
    /// Author Ed25519 signature over canonical record hash (64 bytes).
    pub signature: [u8; 64],
}

impl AppendCommitMsg {
    /// Encode into a `RawFrame`.
    pub fn to_frame(&self, stream_id: u32) -> Result<RawFrame, ProtoError> {
        let mut payload = Vec::with_capacity(80);
        payload.extend_from_slice(&self.lease_token);
        payload.extend_from_slice(&self.signature);
        RawFrame::new(FrameType::AppendCommit, 0, stream_id, payload)
    }

    /// Decode from payload bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, ProtoError> {
        if payload.len() < 80 {
            return Err(ProtoError::IncompletePayload {
                expected: 80,
                actual: payload.len(),
            });
        }
        let mut lease_token = [0u8; 16];
        lease_token.copy_from_slice(&payload[0..16]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&payload[16..80]);
        Ok(Self {
            lease_token,
            signature,
        })
    }
}

/// `TREE_HEAD_REQ` (0x24) — Request current Merkle root and tree size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeHeadReqMsg {
    /// Target table name.
    pub table_name: String,
}

impl TreeHeadReqMsg {
    /// Encode into a `RawFrame`.
    pub fn to_frame(&self, stream_id: u32) -> Result<RawFrame, ProtoError> {
        let bytes = self.table_name.as_bytes();
        let mut payload = Vec::with_capacity(2 + bytes.len());
        payload.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        payload.extend_from_slice(bytes);
        RawFrame::new(FrameType::TreeHeadReq, 0, stream_id, payload)
    }

    /// Decode from payload bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, ProtoError> {
        if payload.len() < 2 {
            return Err(ProtoError::IncompletePayload {
                expected: 2,
                actual: payload.len(),
            });
        }
        let len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
        if payload.len() < 2 + len {
            return Err(ProtoError::IncompletePayload {
                expected: 2 + len,
                actual: payload.len(),
            });
        }
        let table_name = String::from_utf8(payload[2..2 + len].to_vec())?;
        Ok(Self { table_name })
    }
}

/// `TREE_HEAD_RESP` (0x25) — Current Merkle root response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeHeadRespMsg {
    /// Total count of records in Merkle tree.
    pub tree_size: u64,
    /// RFC 6962 root hash (32 bytes).
    pub root_hash: [u8; 32],
}

impl TreeHeadRespMsg {
    /// Encode into a `RawFrame`.
    pub fn to_frame(&self, stream_id: u32) -> Result<RawFrame, ProtoError> {
        let mut payload = Vec::with_capacity(40);
        payload.extend_from_slice(&self.tree_size.to_le_bytes());
        payload.extend_from_slice(&self.root_hash);
        RawFrame::new(FrameType::TreeHeadResp, 0, stream_id, payload)
    }

    /// Decode from payload bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, ProtoError> {
        if payload.len() < 40 {
            return Err(ProtoError::IncompletePayload {
                expected: 40,
                actual: payload.len(),
            });
        }
        let tree_size = u64::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
            payload[7],
        ]);
        let mut root_hash = [0u8; 32];
        root_hash.copy_from_slice(&payload[8..40]);
        Ok(Self {
            tree_size,
            root_hash,
        })
    }
}

/// `PROOF_REQ` (0x26) — Request inclusion proof for a record ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofReqMsg {
    /// Table name.
    pub table_name: String,
    /// Record ID for which inclusion proof is requested.
    pub record_id: u64,
}

impl ProofReqMsg {
    /// Encode into a `RawFrame`.
    pub fn to_frame(&self, stream_id: u32) -> Result<RawFrame, ProtoError> {
        let table_bytes = self.table_name.as_bytes();
        let mut payload = Vec::with_capacity(2 + table_bytes.len() + 8);
        payload.extend_from_slice(&(table_bytes.len() as u16).to_le_bytes());
        payload.extend_from_slice(table_bytes);
        payload.extend_from_slice(&self.record_id.to_le_bytes());
        RawFrame::new(FrameType::ProofReq, 0, stream_id, payload)
    }

    /// Decode from payload bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, ProtoError> {
        if payload.len() < 10 {
            return Err(ProtoError::IncompletePayload {
                expected: 10,
                actual: payload.len(),
            });
        }
        let table_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
        let mut offset = 2;
        if payload.len() < offset + table_len + 8 {
            return Err(ProtoError::IncompletePayload {
                expected: offset + table_len + 8,
                actual: payload.len(),
            });
        }
        let table_name = String::from_utf8(payload[offset..offset + table_len].to_vec())?;
        offset += table_len;

        let record_id = u64::from_le_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
            payload[offset + 4],
            payload[offset + 5],
            payload[offset + 6],
            payload[offset + 7],
        ]);
        Ok(Self {
            table_name,
            record_id,
        })
    }
}

/// `PROOF_RESP` (0x27) — Inclusion proof audit path response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofRespMsg {
    /// Record ID verified.
    pub record_id: u64,
    /// Tree size committed.
    pub tree_size: u64,
    /// Ordered audit path hashes.
    pub audit_path: Vec<[u8; 32]>,
}

impl ProofRespMsg {
    /// Encode into a `RawFrame`.
    pub fn to_frame(&self, stream_id: u32) -> Result<RawFrame, ProtoError> {
        let mut payload = Vec::with_capacity(16 + 2 + self.audit_path.len() * 32);
        payload.extend_from_slice(&self.record_id.to_le_bytes());
        payload.extend_from_slice(&self.tree_size.to_le_bytes());
        payload.extend_from_slice(&(self.audit_path.len() as u16).to_le_bytes());
        for hash in &self.audit_path {
            payload.extend_from_slice(hash);
        }
        RawFrame::new(FrameType::ProofResp, 0, stream_id, payload)
    }

    /// Decode from payload bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, ProtoError> {
        if payload.len() < 18 {
            return Err(ProtoError::IncompletePayload {
                expected: 18,
                actual: payload.len(),
            });
        }
        let record_id = u64::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
            payload[7],
        ]);
        let tree_size = u64::from_le_bytes([
            payload[8],
            payload[9],
            payload[10],
            payload[11],
            payload[12],
            payload[13],
            payload[14],
            payload[15],
        ]);
        let path_len = u16::from_le_bytes([payload[16], payload[17]]) as usize;
        let mut offset = 18;
        if payload.len() < offset + path_len * 32 {
            return Err(ProtoError::IncompletePayload {
                expected: offset + path_len * 32,
                actual: payload.len(),
            });
        }
        let mut audit_path = Vec::with_capacity(path_len);
        for _ in 0..path_len {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&payload[offset..offset + 32]);
            offset += 32;
            audit_path.push(hash);
        }
        Ok(Self {
            record_id,
            tree_size,
            audit_path,
        })
    }
}

/// `HEARTBEAT_PING` (0x3A) — Liveness ping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatPingMsg {
    /// Timestamp in microseconds.
    pub timestamp_us: u64,
}

impl HeartbeatPingMsg {
    /// Encode into a `RawFrame`.
    pub fn to_frame(&self, stream_id: u32) -> Result<RawFrame, ProtoError> {
        RawFrame::new(
            FrameType::HeartbeatPing,
            0,
            stream_id,
            self.timestamp_us.to_le_bytes().to_vec(),
        )
    }

    /// Decode from payload bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, ProtoError> {
        if payload.len() < 8 {
            return Err(ProtoError::IncompletePayload {
                expected: 8,
                actual: payload.len(),
            });
        }
        let timestamp_us = u64::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
            payload[7],
        ]);
        Ok(Self { timestamp_us })
    }
}

/// `HEARTBEAT_PONG` (0x3B) — Liveness pong response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatPongMsg {
    /// Echoed or reply timestamp in microseconds.
    pub timestamp_us: u64,
}

impl HeartbeatPongMsg {
    /// Encode into a `RawFrame`.
    pub fn to_frame(&self, stream_id: u32) -> Result<RawFrame, ProtoError> {
        RawFrame::new(
            FrameType::HeartbeatPong,
            0,
            stream_id,
            self.timestamp_us.to_le_bytes().to_vec(),
        )
    }

    /// Decode from payload bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, ProtoError> {
        if payload.len() < 8 {
            return Err(ProtoError::IncompletePayload {
                expected: 8,
                actual: payload.len(),
            });
        }
        let timestamp_us = u64::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
            payload[7],
        ]);
        Ok(Self { timestamp_us })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_messages_roundtrip() {
        // HelloReqMsg
        let hello = HelloReqMsg {
            client_pubkey: [7u8; 32],
            client_version: 1,
            capabilities: 0x03,
        };
        let frame = hello.to_frame(0).unwrap();
        let decoded_hello = HelloReqMsg::from_payload(&frame.payload).unwrap();
        assert_eq!(hello, decoded_hello);

        // ChallengeMsg
        let challenge = ChallengeMsg {
            database_id: [1u8; 16],
            nonce: [2u8; 32],
            session_id: [3u8; 16],
            auth_timeout_ms: 5000,
        };
        let frame = challenge.to_frame(0).unwrap();
        let decoded_challenge = ChallengeMsg::from_payload(&frame.payload).unwrap();
        assert_eq!(challenge, decoded_challenge);

        // AuthRespMsg
        let auth_resp = AuthRespMsg {
            session_id: [3u8; 16],
            signature: [9u8; 64],
        };
        let frame = auth_resp.to_frame(0).unwrap();
        let decoded_auth_resp = AuthRespMsg::from_payload(&frame.payload).unwrap();
        assert_eq!(auth_resp, decoded_auth_resp);

        // AppendInitMsg & Challenge & Commit
        let append_init = AppendInitMsg {
            table_name: "sales".to_string(),
            data_json: "{\"amount\": 100}".to_string(),
        };
        let frame = append_init.to_frame(1).unwrap();
        let decoded_append_init = AppendInitMsg::from_payload(&frame.payload).unwrap();
        assert_eq!(append_init, decoded_append_init);

        let append_chal = AppendChallengeMsg {
            lease_token: [4u8; 16],
            record_id: 101,
            timestamp_us: 1700000000000000,
            canonical_record_hash: [5u8; 32],
            lease_duration_ms: 2000,
        };
        let frame = append_chal.to_frame(1).unwrap();
        let decoded_chal = AppendChallengeMsg::from_payload(&frame.payload).unwrap();
        assert_eq!(append_chal, decoded_chal);

        let append_commit = AppendCommitMsg {
            lease_token: [4u8; 16],
            signature: [6u8; 64],
        };
        let frame = append_commit.to_frame(1).unwrap();
        let decoded_commit = AppendCommitMsg::from_payload(&frame.payload).unwrap();
        assert_eq!(append_commit, decoded_commit);

        // TreeHead & Proof
        let tree_head_resp = TreeHeadRespMsg {
            tree_size: 42,
            root_hash: [8u8; 32],
        };
        let frame = tree_head_resp.to_frame(2).unwrap();
        let decoded_tree_head = TreeHeadRespMsg::from_payload(&frame.payload).unwrap();
        assert_eq!(tree_head_resp, decoded_tree_head);

        let proof_resp = ProofRespMsg {
            record_id: 15,
            tree_size: 42,
            audit_path: vec![[10u8; 32], [11u8; 32]],
        };
        let frame = proof_resp.to_frame(2).unwrap();
        let decoded_proof = ProofRespMsg::from_payload(&frame.payload).unwrap();
        assert_eq!(proof_resp, decoded_proof);
    }
}
