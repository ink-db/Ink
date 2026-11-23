//! Asynchronous frame encoder and decoder for Tokio streams.

use crate::error::ProtoError;
use crate::frame::{FrameHeader, RawFrame, HEADER_SIZE, MAX_PAYLOAD_SIZE, TRAILER_SIZE};
use bytes::{Buf, BufMut, BytesMut};
use crc32fast::Hasher;
use tokio_util::codec::{Decoder, Encoder};

/// Tokio-compatible codec for encoding and decoding IWP binary frames over TCP/TLS streams.
#[derive(Debug, Default, Clone)]
pub struct FrameCodec {
    /// Maximum allowed payload size. Defaults to `MAX_PAYLOAD_SIZE` (64 MiB).
    pub max_payload_size: u32,
}

impl FrameCodec {
    /// Create a new codec with default 64 MiB payload bounds.
    pub fn new() -> Self {
        Self {
            max_payload_size: MAX_PAYLOAD_SIZE,
        }
    }

    /// Create a new codec with custom maximum payload size limit.
    pub fn with_max_payload(max_payload_size: u32) -> Self {
        Self { max_payload_size }
    }
}

impl Decoder for FrameCodec {
    type Item = RawFrame;
    type Error = ProtoError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < HEADER_SIZE {
            return Ok(None);
        }

        // Peek header bytes without consuming buffer yet
        let header_slice: [u8; HEADER_SIZE] =
            src[..HEADER_SIZE]
                .try_into()
                .map_err(|_| ProtoError::IncompletePayload {
                    expected: HEADER_SIZE,
                    actual: src.len(),
                })?;
        let header = FrameHeader::decode(&header_slice)?;

        if header.payload_len > self.max_payload_size {
            return Err(ProtoError::PayloadTooLarge {
                length: header.payload_len,
                max: self.max_payload_size,
            });
        }

        let total_frame_size = HEADER_SIZE + header.payload_len as usize + TRAILER_SIZE;
        if src.len() < total_frame_size {
            // Reserve remaining buffer capacity to avoid incremental re-allocations
            src.reserve(total_frame_size - src.len());
            return Ok(None);
        }

        // Consume the entire frame from the buffer
        let mut frame_bytes = src.split_to(total_frame_size);
        frame_bytes.advance(HEADER_SIZE); // advance past header

        let payload_len = header.payload_len as usize;
        let payload = frame_bytes.split_to(payload_len).to_vec();

        let trailer_bytes: [u8; 4] =
            frame_bytes[..4]
                .try_into()
                .map_err(|_| ProtoError::IncompletePayload {
                    expected: 4,
                    actual: frame_bytes.len(),
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

        Ok(Some(RawFrame { header, payload }))
    }
}

impl Encoder<RawFrame> for FrameCodec {
    type Error = ProtoError;

    fn encode(&mut self, item: RawFrame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if item.payload.len() as u32 > self.max_payload_size {
            return Err(ProtoError::PayloadTooLarge {
                length: item.payload.len() as u32,
                max: self.max_payload_size,
            });
        }

        let total_len = HEADER_SIZE + item.payload.len() + TRAILER_SIZE;
        dst.reserve(total_len);

        dst.put_slice(&item.header.encode());
        dst.put_slice(&item.payload);
        let payload_crc = item.compute_payload_crc();
        dst.put_u32_le(payload_crc);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::FrameType;

    #[test]
    fn test_codec_tokio_framing_partial_chunks() {
        let mut codec = FrameCodec::new();
        let payload = vec![0x42; 250];
        let frame = RawFrame::new(FrameType::StreamChunk, 0, 7, payload.clone()).unwrap();

        let mut buf = BytesMut::new();
        codec.encode(frame, &mut buf).unwrap();

        let full_wire = buf.clone();

        // Feed half buffer
        let mut partial = BytesMut::new();
        partial.extend_from_slice(&full_wire[..20]);
        assert!(codec.decode(&mut partial).unwrap().is_none());

        // Feed rest of buffer
        partial.extend_from_slice(&full_wire[20..]);
        let decoded = codec
            .decode(&mut partial)
            .unwrap()
            .expect("Should decode full frame");
        assert_eq!(decoded.header.stream_id, 7);
        assert_eq!(decoded.payload, payload);
        assert!(partial.is_empty());
    }
}
