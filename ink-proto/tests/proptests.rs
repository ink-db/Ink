//! Property-based testing for IWP framing and serialization.

use ink_proto::{FrameHeader, FrameType, RawFrame, CURRENT_VERSION, MAGIC};
use proptest::prelude::*;

proptest! {
    #[test]
    fn proptest_header_roundtrip(
        frame_type_byte in 0u8..255u8,
        flags in any::<u8>(),
        stream_id in any::<u32>(),
        payload_len in 0u32..10_000u32,
    ) {
        if let Ok(frame_type) = FrameType::from_u8(frame_type_byte) {
            let header = FrameHeader::new(frame_type, flags, stream_id, payload_len).unwrap();
            let encoded = header.encode();
            let decoded = FrameHeader::decode(&encoded).unwrap();

            prop_assert_eq!(decoded.magic, MAGIC);
            prop_assert_eq!(decoded.version, CURRENT_VERSION);
            prop_assert_eq!(decoded.frame_type, frame_type);
            prop_assert_eq!(decoded.flags, flags);
            prop_assert_eq!(decoded.stream_id, stream_id);
            prop_assert_eq!(decoded.payload_len, payload_len);
            prop_assert_eq!(decoded.header_crc, header.header_crc);
        }
    }

    #[test]
    fn proptest_raw_frame_roundtrip(
        flags in any::<u8>(),
        stream_id in any::<u32>(),
        payload in proptest::collection::vec(any::<u8>(), 0..2000),
    ) {
        let frame = RawFrame::new(FrameType::RowData, flags, stream_id, payload.clone()).unwrap();
        let wire = frame.encode();

        let (decoded, consumed) = RawFrame::try_decode(&wire).unwrap().expect("Should decode");
        prop_assert_eq!(consumed, wire.len());
        prop_assert_eq!(decoded.header.frame_type, FrameType::RowData);
        prop_assert_eq!(decoded.header.flags, flags);
        prop_assert_eq!(decoded.header.stream_id, stream_id);
        prop_assert_eq!(decoded.payload, payload);
    }
}
