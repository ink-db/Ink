//! Low-level frame types and binary serialization for IWP/1.0.

use crate::error::ProtoError;
use crc32fast::Hasher;

/// Magic bytes identifying Ink Wire Protocol frames: ASCII "INK".
pub const MAGIC: [u8; 3] = [0x49, 0x4E, 0x4B];

/// Current supported wire protocol version.
pub const CURRENT_VERSION: u8 = 1;

/// Fixed size of the IWP frame header in bytes.
pub const HEADER_SIZE: usize = 18;

/// Fixed size of the trailing payload CRC32-C in bytes.
pub const TRAILER_SIZE: usize = 4;

/// Maximum payload size allowed for a single frame (64 MiB).
pub const MAX_PAYLOAD_SIZE: u32 = 64 * 1024 * 1024;

/// Frame Flag: End of Stream (last frame on this stream ID).
pub const FLAG_EOS: u8 = 0x01;

/// Frame Flag: Payload data is compressed.
pub const FLAG_COMPRESSED: u8 = 0x02;

/// Frame type identifiers in the IWP/1.0 specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameType {
    // Handshake (0x01 - 0x0F)
    /// Client initiation containing public key and protocol capabilities.
    HelloReq = 0x01,
    /// Server challenge containing random nonce, session ID, and database ID.
    Challenge = 0x02,
    /// Client response containing Ed25519 signature over challenge digest.
    AuthResp = 0x03,
    /// Server confirmation of successful authentication.
    AuthOk = 0x04,
    /// Server rejection of authentication attempt (timing-uniform).
    AuthFail = 0x05,

    // Query & Results (0x10 - 0x1F)
    /// Execute an IQL query statement.
    QueryReq = 0x10,
    /// Schema column metadata for streaming tabular results.
    RowHeader = 0x11,
    /// Single row JSON data frame.
    RowData = 0x12,
    /// Query completion marker with summary statistics.
    QueryComplete = 0x13,
    /// Client cancellation of an in-flight request/stream.
    ReqCancel = 0x14,

    // Two-Step Append (0x15 - 0x1F)
    /// Request to append a new record with data payload.
    AppendInit = 0x15,
    /// Server reservation of record ID and challenge hash with a short lease.
    AppendChallenge = 0x16,
    /// Client signature committing the reserved record frame.
    AppendCommit = 0x17,

    // Streaming & Flow Control (0x20 - 0x23)
    /// Chunk of bulk streaming data.
    StreamChunk = 0x20,
    /// Flow control window acknowledgment from receiver.
    StreamAck = 0x21,

    // Inspection & Audit (0x24 - 0x2F)
    /// Request latest Merkle tree head root hash for a table.
    TreeHeadReq = 0x24,
    /// Response with Merkle tree head and size.
    TreeHeadResp = 0x25,
    /// Request an RFC 6962 inclusion proof for a record ID.
    ProofReq = 0x26,
    /// Response containing the audit path for an inclusion proof.
    ProofResp = 0x27,

    // Replication (0x30 - 0x39)
    /// Forward committed record to secondary peers.
    ReplAppend = 0x30,
    /// Signed acknowledgment from secondary node.
    ReplAck = 0x31,
    /// Historical catch-up sync request.
    ReplSyncReq = 0x32,
    /// Streamed chunk of historical records for disaster recovery.
    ReplSyncChunk = 0x33,

    // Heartbeat & Liveness (0x3A - 0x3F)
    /// Ping message to keep connection alive and measure latency.
    HeartbeatPing = 0x3A,
    /// Pong response acknowledging a heartbeat ping.
    HeartbeatPong = 0x3B,
}

impl FrameType {
    /// Convert a raw `u8` byte into a `FrameType` if valid.
    pub fn from_u8(byte: u8) -> Result<Self, ProtoError> {
        match byte {
            0x01 => Ok(Self::HelloReq),
            0x02 => Ok(Self::Challenge),
            0x03 => Ok(Self::AuthResp),
            0x04 => Ok(Self::AuthOk),
            0x05 => Ok(Self::AuthFail),
            0x10 => Ok(Self::QueryReq),
            0x11 => Ok(Self::RowHeader),
            0x12 => Ok(Self::RowData),
            0x13 => Ok(Self::QueryComplete),
            0x14 => Ok(Self::ReqCancel),
            0x15 => Ok(Self::AppendInit),
            0x16 => Ok(Self::AppendChallenge),
            0x17 => Ok(Self::AppendCommit),
            0x20 => Ok(Self::StreamChunk),
            0x21 => Ok(Self::StreamAck),
            0x24 => Ok(Self::TreeHeadReq),
            0x25 => Ok(Self::TreeHeadResp),
            0x26 => Ok(Self::ProofReq),
            0x27 => Ok(Self::ProofResp),
            0x30 => Ok(Self::ReplAppend),
            0x31 => Ok(Self::ReplAck),
            0x32 => Ok(Self::ReplSyncReq),
            0x33 => Ok(Self::ReplSyncChunk),
            0x3A => Ok(Self::HeartbeatPing),
            0x3B => Ok(Self::HeartbeatPong),
            _ => Err(ProtoError::InvalidFrameType(byte)),
        }
    }

    /// Return the raw byte representation of the frame type.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Parsed 18-byte fixed header of an IWP frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// 3-byte magic ASCII prefix ("INK").
    pub magic: [u8; 3],
    /// Protocol version (must equal 1).
    pub version: u8,
    /// Type of frame.
    pub frame_type: FrameType,
    /// Status flags (EOS, compression).
    pub flags: u8,
    /// Multiplexed stream ID.
    pub stream_id: u32,
    /// Length of the following payload data in bytes.
    pub payload_len: u32,
    /// CRC32-C checksum calculated over bytes 0..14.
    pub header_crc: u32,
}

impl FrameHeader {
    /// Construct a new frame header, computing the header CRC32-C automatically.
    pub fn new(
        frame_type: FrameType,
        flags: u8,
        stream_id: u32,
        payload_len: u32,
    ) -> Result<Self, ProtoError> {
        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(ProtoError::PayloadTooLarge {
                length: payload_len,
                max: MAX_PAYLOAD_SIZE,
            });
        }

        let mut header = Self {
            magic: MAGIC,
            version: CURRENT_VERSION,
            frame_type,
            flags,
            stream_id,
            payload_len,
            header_crc: 0,
        };
        header.header_crc = header.compute_crc();
        Ok(header)
    }

    /// Compute CRC32-C over bytes 0..14.
    pub fn compute_crc(&self) -> u32 {
        let mut bytes = [0u8; 14];
        bytes[0..3].copy_from_slice(&self.magic);
        bytes[3] = self.version;
        bytes[4] = self.frame_type.as_u8();
        bytes[5] = self.flags;
        bytes[6..10].copy_from_slice(&self.stream_id.to_le_bytes());
        bytes[10..14].copy_from_slice(&self.payload_len.to_le_bytes());

        let mut hasher = Hasher::new();
        hasher.update(&bytes);
        hasher.finalize()
    }

    /// Encode this header into its exact 18-byte wire representation.
    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..3].copy_from_slice(&self.magic);
        buf[3] = self.version;
        buf[4] = self.frame_type.as_u8();
        buf[5] = self.flags;
        buf[6..10].copy_from_slice(&self.stream_id.to_le_bytes());
        buf[10..14].copy_from_slice(&self.payload_len.to_le_bytes());
        buf[14..18].copy_from_slice(&self.header_crc.to_le_bytes());
        buf
    }

    /// Decode an 18-byte slice into a `FrameHeader`, verifying magic, version, bounds, and header CRC32-C.
    pub fn decode(bytes: &[u8; HEADER_SIZE]) -> Result<Self, ProtoError> {
        let magic = [bytes[0], bytes[1], bytes[2]];
        if magic != MAGIC {
            return Err(ProtoError::BadMagic(magic));
        }

        let version = bytes[3];
        if version != CURRENT_VERSION {
            return Err(ProtoError::UnsupportedVersion(version));
        }

        let frame_type = FrameType::from_u8(bytes[4])?;
        let flags = bytes[5];
        let stream_id = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
        let payload_len = u32::from_le_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]);
        let header_crc = u32::from_le_bytes([bytes[14], bytes[15], bytes[16], bytes[17]]);

        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(ProtoError::PayloadTooLarge {
                length: payload_len,
                max: MAX_PAYLOAD_SIZE,
            });
        }

        let mut hasher = Hasher::new();
        hasher.update(&bytes[0..14]);
        let computed = hasher.finalize();

        if computed != header_crc {
            return Err(ProtoError::HeaderCrcMismatch {
                expected: header_crc,
                computed,
            });
        }

        Ok(Self {
            magic,
            version,
            frame_type,
            flags,
            stream_id,
            payload_len,
            header_crc,
        })
    }
}

/// A complete IWP raw frame comprising an 18-byte header, payload data, and trailing 4-byte payload CRC32-C.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFrame {
    /// Validated frame header.
    pub header: FrameHeader,
    /// Raw payload bytes.
    pub payload: Vec<u8>,
}

impl RawFrame {
    /// Construct a new raw frame, automatically calculating both header and payload CRC checksums.
    pub fn new(
        frame_type: FrameType,
        flags: u8,
        stream_id: u32,
        payload: Vec<u8>,
    ) -> Result<Self, ProtoError> {
        let header = FrameHeader::new(frame_type, flags, stream_id, payload.len() as u32)?;
        Ok(Self { header, payload })
    }

    /// Calculate the CRC32-C checksum over the payload data.
    pub fn compute_payload_crc(&self) -> u32 {
        let mut hasher = Hasher::new();
        hasher.update(&self.payload);
        hasher.finalize()
    }

    /// Serialize the entire frame into a contiguous byte buffer:
    /// `18-byte header` || `payload` || `4-byte payload CRC32-C`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE + self.payload.len() + TRAILER_SIZE);
        out.extend_from_slice(&self.header.encode());
        out.extend_from_slice(&self.payload);
        let payload_crc = self.compute_payload_crc();
        out.extend_from_slice(&payload_crc.to_le_bytes());
        out
    }

    /// Decode a complete frame from a slice if sufficient bytes are available.
    ///
    /// Returns `Ok(Some((frame, bytes_consumed)))` if a complete frame was decoded,
    /// `Ok(None)` if more bytes are needed, or `Err(ProtoError)` if corruption/invalidity detected.
    pub fn try_decode(buf: &[u8]) -> Result<Option<(Self, usize)>, ProtoError> {
        if buf.len() < HEADER_SIZE {
            return Ok(None);
        }

        let header_bytes: [u8; HEADER_SIZE] =
            buf[..HEADER_SIZE]
                .try_into()
                .map_err(|_| ProtoError::IncompletePayload {
                    expected: HEADER_SIZE,
                    actual: buf.len(),
                })?;
        let header = FrameHeader::decode(&header_bytes)?;

        let total_expected_len = HEADER_SIZE + header.payload_len as usize + TRAILER_SIZE;
        if buf.len() < total_expected_len {
            return Ok(None);
        }

        let payload_start = HEADER_SIZE;
        let payload_end = payload_start + header.payload_len as usize;
        let payload = buf[payload_start..payload_end].to_vec();

        let trailer_bytes: [u8; 4] =
            buf[payload_end..total_expected_len]
                .try_into()
                .map_err(|_| ProtoError::IncompletePayload {
                    expected: 4,
                    actual: buf.len() - payload_end,
                })?;
        let expected_payload_crc = u32::from_le_bytes(trailer_bytes);

        let mut hasher = Hasher::new();
        hasher.update(&payload);
        let computed_payload_crc = hasher.finalize();

        if computed_payload_crc != expected_payload_crc {
            return Err(ProtoError::PayloadCrcMismatch {
                expected: expected_payload_crc,
                computed: computed_payload_crc,
            });
        }

        Ok(Some((Self { header, payload }, total_expected_len)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_encode_decode_roundtrip() {
        let header = FrameHeader::new(FrameType::HelloReq, FLAG_EOS, 42, 128).unwrap();
        let encoded = header.encode();
        assert_eq!(encoded.len(), HEADER_SIZE);

        let decoded = FrameHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.magic, MAGIC);
        assert_eq!(decoded.version, CURRENT_VERSION);
        assert_eq!(decoded.frame_type, FrameType::HelloReq);
        assert_eq!(decoded.flags, FLAG_EOS);
        assert_eq!(decoded.stream_id, 42);
        assert_eq!(decoded.payload_len, 128);
        assert_eq!(decoded.header_crc, header.header_crc);
    }

    #[test]
    fn test_header_crc_corruption_detected() {
        let header = FrameHeader::new(FrameType::QueryReq, 0, 1, 64).unwrap();
        let mut encoded = header.encode();
        // Corrupt stream ID byte
        encoded[7] ^= 0xFF;
        let err = FrameHeader::decode(&encoded).unwrap_err();
        match err {
            ProtoError::HeaderCrcMismatch { .. } => {}
            other => panic!("Expected HeaderCrcMismatch, got {:?}", other),
        }
    }

    #[test]
    fn test_raw_frame_encode_try_decode() {
        let payload = b"{\"action\":\"read\"}".to_vec();
        let frame = RawFrame::new(FrameType::QueryReq, 0, 10, payload.clone()).unwrap();
        let wire_bytes = frame.encode();

        assert_eq!(wire_bytes.len(), HEADER_SIZE + payload.len() + TRAILER_SIZE);

        let (decoded, consumed) = RawFrame::try_decode(&wire_bytes).unwrap().unwrap();
        assert_eq!(consumed, wire_bytes.len());
        assert_eq!(decoded.header.frame_type, FrameType::QueryReq);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_payload_crc_corruption_detected() {
        let payload = b"important immutable data".to_vec();
        let frame = RawFrame::new(FrameType::RowData, 0, 1, payload).unwrap();
        let mut wire_bytes = frame.encode();

        // Corrupt payload byte
        wire_bytes[HEADER_SIZE + 2] ^= 0xAA;

        let err = RawFrame::try_decode(&wire_bytes).unwrap_err();
        match err {
            ProtoError::PayloadCrcMismatch { .. } => {}
            other => panic!("Expected PayloadCrcMismatch, got {:?}", other),
        }
    }
}
