//! Binary wire protocol codec and frame definitions for the Ink database (IWP/1.0).

pub mod codec;
pub mod error;
pub mod error_codes;
pub mod frame;
pub mod messages;

pub use codec::FrameCodec;
pub use error::ProtoError;
pub use error_codes::ErrorCode;
pub use frame::{
    FrameHeader, FrameType, RawFrame, CURRENT_VERSION, FLAG_COMPRESSED, FLAG_EOS, HEADER_SIZE,
    MAGIC, MAX_PAYLOAD_SIZE, TRAILER_SIZE,
};
pub use messages::{
    AppendChallengeMsg, AppendCommitMsg, AppendInitMsg, AuthFailMsg, AuthOkMsg, AuthRespMsg,
    ChallengeMsg, HeartbeatPingMsg, HeartbeatPongMsg, HelloReqMsg, ProofReqMsg, ProofRespMsg,
    QueryCompleteMsg, QueryReqMsg, ReqCancelMsg, RowDataMsg, RowHeaderMsg, TreeHeadReqMsg,
    TreeHeadRespMsg,
};

/// Domain separation tag for IWP authentication handshake digests.
pub const AUTH_DOMAIN_TAG: &[u8] = b"INK-AUTH-v1";

/// Compute the 32-byte domain-separated authentication challenge digest:
/// `BLAKE3("INK-AUTH-v1" || database_id || nonce || session_id || server_cert_hash)`
pub fn compute_auth_digest(
    database_id: &[u8; 16],
    nonce: &[u8; 32],
    session_id: &[u8; 16],
    server_cert_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(AUTH_DOMAIN_TAG);
    hasher.update(database_id);
    hasher.update(nonce);
    hasher.update(session_id);
    hasher.update(server_cert_hash);
    *hasher.finalize().as_bytes()
}
