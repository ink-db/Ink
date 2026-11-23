//! Standardized wire protocol error codes.

/// Numeric error codes returned in `AUTH_FAIL` or error response payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ErrorCode {
    // Protocol / Framing (0x0001 - 0x00FF)
    /// Bad frame format or corrupt header structure.
    BadFrameFormat = 0x0001,
    /// Frame payload exceeds the maximum 64 MiB limit.
    PayloadTooLarge = 0x0002,
    /// Protocol version requested is not supported.
    UnsupportedVersion = 0x0003,
    /// Header or payload CRC32-C mismatch.
    CrcMismatch = 0x0004,
    /// Stream was closed or reset.
    StreamClosed = 0x0005,

    // Authentication (0x0101 - 0x01FF)
    /// Operation attempted before handshake completed.
    AuthRequired = 0x0101,
    /// Challenge response was not received within timeout window.
    ChallengeTimeout = 0x0102,
    /// Handshake negotiation failed.
    HandshakeFailed = 0x0103,
    /// Connection attempts exceeded token bucket limit.
    RateLimited = 0x0104,
    /// Source IP temporarily banned due to consecutive failed handshakes.
    IpBlocked = 0x0105,

    // Query Execution (0x0201 - 0x02FF)
    /// IQL statement syntax error.
    ParseError = 0x0201,
    /// Prohibited statement attempted (UPDATE, DELETE, DROP, TRUNCATE).
    ProhibitedStatement = 0x0202,
    /// Target table does not exist.
    UnknownTable = 0x0203,
    /// Runtime query evaluation failure.
    QueryExecFailed = 0x0204,

    // Storage / Two-Step Append (0x0301 - 0x03FF)
    /// Append lease window expired before commit signature received.
    LeaseExpired = 0x0301,
    /// Ed25519 author signature verification failed.
    InvalidSignature = 0x0302,
    /// Sequence collision or broken prev_hash chain.
    IdCollision = 0x0303,
    /// JSON payload malformed or fails schema constraints.
    PayloadValidationError = 0x0304,

    // Authorization (0x0401 - 0x04FF)
    /// Constant-time timing-uniform access rejection (key not found, expired, wrong role).
    AccessDenied = 0x0403,

    // Replication (0x0501 - 0x05FF)
    /// Secondary node hash chain has diverged from coordinator.
    PeerDesync = 0x0501,
    /// Fewer than `replication_quorum` secondary nodes acknowledged write.
    QuorumUnmet = 0x0502,
    /// Peer node public key not authorized for cluster replication.
    NodeUnauthorized = 0x0503,
    /// Catch-up sync stream failed.
    SyncFailed = 0x0504,
}

impl ErrorCode {
    /// Convert an integer error code into an `ErrorCode` enum if known.
    pub fn from_u16(code: u16) -> Option<Self> {
        match code {
            0x0001 => Some(Self::BadFrameFormat),
            0x0002 => Some(Self::PayloadTooLarge),
            0x0003 => Some(Self::UnsupportedVersion),
            0x0004 => Some(Self::CrcMismatch),
            0x0005 => Some(Self::StreamClosed),
            0x0101 => Some(Self::AuthRequired),
            0x0102 => Some(Self::ChallengeTimeout),
            0x0103 => Some(Self::HandshakeFailed),
            0x0104 => Some(Self::RateLimited),
            0x0105 => Some(Self::IpBlocked),
            0x0201 => Some(Self::ParseError),
            0x0202 => Some(Self::ProhibitedStatement),
            0x0203 => Some(Self::UnknownTable),
            0x0204 => Some(Self::QueryExecFailed),
            0x0301 => Some(Self::LeaseExpired),
            0x0302 => Some(Self::InvalidSignature),
            0x0303 => Some(Self::IdCollision),
            0x0304 => Some(Self::PayloadValidationError),
            0x0403 => Some(Self::AccessDenied),
            0x0501 => Some(Self::PeerDesync),
            0x0502 => Some(Self::QuorumUnmet),
            0x0503 => Some(Self::NodeUnauthorized),
            0x0504 => Some(Self::SyncFailed),
            _ => None,
        }
    }

    /// Return the raw `u16` code.
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Return a human-readable identifier string for the error code.
    pub fn name(self) -> &'static str {
        match self {
            Self::BadFrameFormat => "BAD_FRAME_FORMAT",
            Self::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
            Self::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Self::CrcMismatch => "CRC_MISMATCH",
            Self::StreamClosed => "STREAM_CLOSED",
            Self::AuthRequired => "AUTH_REQUIRED",
            Self::ChallengeTimeout => "CHALLENGE_TIMEOUT",
            Self::HandshakeFailed => "HANDSHAKE_FAILED",
            Self::RateLimited => "RATE_LIMITED",
            Self::IpBlocked => "IP_BLOCKED",
            Self::ParseError => "PARSE_ERROR",
            Self::ProhibitedStatement => "PROHIBITED_STATEMENT",
            Self::UnknownTable => "UNKNOWN_TABLE",
            Self::QueryExecFailed => "QUERY_EXEC_FAILED",
            Self::LeaseExpired => "LEASE_EXPIRED",
            Self::InvalidSignature => "INVALID_SIGNATURE",
            Self::IdCollision => "ID_COLLISION",
            Self::PayloadValidationError => "PAYLOAD_VALIDATION_ERROR",
            Self::AccessDenied => "ACCESS_DENIED",
            Self::PeerDesync => "PEER_DESYNC",
            Self::QuorumUnmet => "QUORUM_UNMET",
            Self::NodeUnauthorized => "NODE_UNAUTHORIZED",
            Self::SyncFailed => "SYNC_FAILED",
        }
    }
}
