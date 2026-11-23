//! Segment file reading and writing.
//!
//! Each table stores its records in one or more **segment files** located at:
//!
//! ```text
//! <data_dir>/segments/<table>/seg_000000.ink     ← active (writable)
//! <data_dir>/segments/<table>/seg_000000.sealed  ← sealed (read-only)
//! ```
//!
//! Segments are opened in append-only mode. When a segment reaches its size
//! limit it is *sealed* (renamed from `.ink` to `.sealed`) and a new one is
//! created.
//!
//! # On-disk frame format (see `FORMAT.md §3.3`)
//!
//! Every record is stored as a length-prefixed frame:
//!
//! ```text
//! bytes  0– 3   frame_length  (u32 LE) — total bytes including this field
//! byte   4      frame_version (u8)     — currently 0
//! byte   5      flags         (u8)     — 0x01 = is_correction
//! bytes  6–13   record_id     (u64 LE)
//! bytes 14–21   timestamp     (i64 LE, microseconds since Unix epoch)
//! bytes 22–23   table_len     (u16 LE)
//! bytes 24..N   table         (UTF-8, table_len bytes)
//! 2 bytes       author_key_len (u16 LE, always 32)
//! 32 bytes      author        (Ed25519 public key)
//! 8 bytes       correction_of (u64 LE; u64::MAX if not a correction)
//! 4 bytes       data_len      (u32 LE)
//! D bytes       data          (payload bytes)
//! 32 bytes      prev_hash     (BLAKE3)
//! 32 bytes      record_hash   (BLAKE3)
//! 64 bytes      signature     (Ed25519; zeros in Phase 1)
//! 4 bytes       crc32         (CRC32 of all bytes above)
//! ```
//!
//! Fixed overhead per frame: 202 bytes.  Total = 202 + table_len + data_len.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{InkError, Result};
use crate::record::{Record, MAX_RECORD_DATA_SIZE, MAX_TABLE_NAME_SIZE, NOT_A_CORRECTION};

// Constants

/// Magic bytes for a segment file header: b"INKSEGMT".
const SEGMENT_MAGIC: &[u8; 8] = b"INKSEGMT";

/// Segment format version understood by this implementation.
pub const SEGMENT_FORMAT_VERSION: u16 = 0;

/// Size of the segment file header in bytes.
pub const SEGMENT_HEADER_SIZE: usize = 32;

/// Fixed byte overhead of a record frame, excluding table name and payload.
///
/// 4 (len) + 1 (ver) + 1 (flags) + 8 (id) + 8 (ts) + 2 (table_len)
/// + 2 (author_key_len) + 32 (author) + 8 (correction_of) + 4 (data_len)
/// + 32 (prev_hash) + 32 (record_hash) + 64 (signature) + 4 (crc) = 202
pub const FRAME_FIXED_OVERHEAD: usize = 202;

/// Minimum valid frame length (empty table name, empty payload).
const FRAME_MIN_SIZE: usize = FRAME_FIXED_OVERHEAD;

/// Maximum valid frame length.
const FRAME_MAX_SIZE: usize = FRAME_FIXED_OVERHEAD + MAX_TABLE_NAME_SIZE + MAX_RECORD_DATA_SIZE;

// Segment header helpers

/// Write the 32-byte segment file header.
///
/// ```text
/// bytes  0– 7  magic "INKSEGMT" (8 bytes)
/// bytes  8– 9  format version   (u16 LE)
/// bytes 10–11  flags            (u16 LE, reserved = 0)
/// bytes 12–19  sequence number  (u64 LE)
/// bytes 20–27  creation ts      (i64 LE, microseconds since epoch)
/// bytes 28–31  reserved         (u32, 0)
/// ```
fn write_segment_header<W: Write>(writer: &mut W, sequence: u32, created_at: i64) -> Result<()> {
    let mut header = [0u8; SEGMENT_HEADER_SIZE];
    header[0..8].copy_from_slice(SEGMENT_MAGIC);
    header[8..10].copy_from_slice(&SEGMENT_FORMAT_VERSION.to_le_bytes());
    // bytes 10–11: flags = 0 (reserved)
    header[12..20].copy_from_slice(&(sequence as u64).to_le_bytes());
    header[20..28].copy_from_slice(&created_at.to_le_bytes());
    // bytes 28–31: reserved = 0
    writer.write_all(&header)?;
    Ok(())
}

/// Read and validate the 32-byte segment header.
///
/// Returns the segment sequence number.
fn read_segment_header<R: Read>(reader: &mut R, path: &Path) -> Result<u32> {
    let mut header = [0u8; SEGMENT_HEADER_SIZE];
    reader.read_exact(&mut header).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            InkError::CorruptRecord {
                offset: 0,
                path: path.to_string_lossy().to_string(),
                reason: "file too short to contain segment header".to_string(),
            }
        } else {
            InkError::Io(e)
        }
    })?;

    // Verify magic
    if &header[0..8] != SEGMENT_MAGIC {
        let found = u64::from_le_bytes(header[0..8].try_into().unwrap());
        return Err(InkError::InvalidSegmentMagic {
            path: path.to_string_lossy().to_string(),
            found,
        });
    }

    // Verify format version
    let version = u16::from_le_bytes(header[8..10].try_into().unwrap());
    if version > SEGMENT_FORMAT_VERSION {
        return Err(InkError::UnsupportedVersion {
            found: version,
            max: SEGMENT_FORMAT_VERSION,
            path: path.to_string_lossy().to_string(),
        });
    }

    let sequence = u64::from_le_bytes(header[12..20].try_into().unwrap()) as u32;
    Ok(sequence)
}

// Frame serialization

/// Serialize a [`Record`] into a frame and write it to `writer`.
///
/// Returns the total number of bytes written (the frame length).
pub fn write_record_frame<W: Write>(writer: &mut W, record: &Record) -> Result<usize> {
    let table_bytes = record.table.as_bytes();
    let n = table_bytes.len(); // table name length
    let d = record.data.len(); // payload length
    let frame_len = FRAME_FIXED_OVERHEAD + n + d;

    // Build the frame in a Vec so we can compute CRC over the whole thing.
    let mut frame = Vec::with_capacity(frame_len);

    // Frame length (u32 LE)
    frame.extend_from_slice(&(frame_len as u32).to_le_bytes());
    // Frame version (u8)
    frame.push(0u8);
    // Flags (u8)
    frame.push(record.flags);
    // Record ID (u64 LE)
    frame.extend_from_slice(&record.id.to_le_bytes());
    // Timestamp (i64 LE, microseconds since epoch)
    frame.extend_from_slice(&record.timestamp.to_le_bytes());
    // Table name length (u16 LE)
    frame.extend_from_slice(&(n as u16).to_le_bytes());
    // Table name (UTF-8 bytes)
    frame.extend_from_slice(table_bytes);
    // Author key length (u16 LE, always 32 for Ed25519)
    frame.extend_from_slice(&32u16.to_le_bytes());
    // Author public key (32 bytes)
    frame.extend_from_slice(&record.author);
    // Correction-of ID (u64 LE; NOT_A_CORRECTION sentinel if not a correction)
    let corr = record.correction_of.unwrap_or(NOT_A_CORRECTION);
    frame.extend_from_slice(&corr.to_le_bytes());
    // Data length (u32 LE)
    frame.extend_from_slice(&(d as u32).to_le_bytes());
    // Data payload
    frame.extend_from_slice(&record.data);
    // prev_hash (32 bytes, BLAKE3)
    frame.extend_from_slice(&record.prev_hash);
    // record_hash (32 bytes, BLAKE3)
    frame.extend_from_slice(&record.record_hash);
    // Signature (64 bytes, Ed25519; all zeros in Phase 1)
    frame.extend_from_slice(&record.signature);

    debug_assert_eq!(
        frame.len(),
        frame_len - 4,
        "frame body before CRC should be {}-4 bytes",
        frame_len
    );

    // CRC32 of everything except the last 4 bytes
    let crc = crc32fast::hash(&frame);
    frame.extend_from_slice(&crc.to_le_bytes());

    debug_assert_eq!(frame.len(), frame_len);

    writer.write_all(&frame)?;
    Ok(frame_len)
}

/// Parse a [`Record`] from a fully-read and CRC-verified frame buffer.
///
/// `file_offset` is the byte offset of the frame start within the segment file
/// (used only for error messages).
fn parse_record_from_frame(frame: &[u8], file_offset: u64, path: &Path) -> Result<Record> {
    let path_str = path.to_string_lossy().to_string();

    // frame[0..4] = frame_len (already parsed by caller)
    // frame[4]    = frame_version (unused in v0)
    let flags = frame[5];

    let id = u64::from_le_bytes(frame[6..14].try_into().unwrap());
    let timestamp = i64::from_le_bytes(frame[14..22].try_into().unwrap());

    let table_len = u16::from_le_bytes(frame[22..24].try_into().unwrap()) as usize;
    if table_len > MAX_TABLE_NAME_SIZE {
        return Err(InkError::CorruptRecord {
            offset: file_offset,
            path: path_str,
            reason: format!("table name length {table_len} exceeds maximum {MAX_TABLE_NAME_SIZE}"),
        });
    }

    let table_end = 24 + table_len;
    let table = std::str::from_utf8(&frame[24..table_end])
        .map_err(|_| InkError::InvalidUtf8 {
            offset: file_offset,
        })?
        .to_string();

    // author_key_len (u16 LE, always 32)
    let author_key_len =
        u16::from_le_bytes(frame[table_end..table_end + 2].try_into().unwrap()) as usize;
    if author_key_len != 32 {
        return Err(InkError::CorruptRecord {
            offset: file_offset,
            path: path_str,
            reason: format!("unexpected author key length: {author_key_len} (expected 32)"),
        });
    }

    let author_start = table_end + 2; // = 26 + table_len
    let mut author = [0u8; 32];
    author.copy_from_slice(&frame[author_start..author_start + 32]);

    let corr_start = author_start + 32; // = 58 + table_len
    let correction_raw = u64::from_le_bytes(frame[corr_start..corr_start + 8].try_into().unwrap());
    let correction_of = if correction_raw == NOT_A_CORRECTION {
        None
    } else {
        Some(correction_raw)
    };

    let data_len_start = corr_start + 8; // = 66 + table_len
    let data_len = u32::from_le_bytes(
        frame[data_len_start..data_len_start + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    if data_len > MAX_RECORD_DATA_SIZE {
        return Err(InkError::CorruptRecord {
            offset: file_offset,
            path: path_str,
            reason: format!("data length {data_len} exceeds maximum {MAX_RECORD_DATA_SIZE}"),
        });
    }

    let data_start = data_len_start + 4; // = 70 + table_len
    let data_end = data_start + data_len; // = 70 + table_len + data_len

    // Verify total frame length is consistent
    // After data: 32 (prev_hash) + 32 (record_hash) + 64 (sig) + 4 (crc) = 132
    let expected_frame_len = data_end + 132;
    if expected_frame_len != frame.len() {
        return Err(InkError::CorruptRecord {
            offset: file_offset,
            path: path_str,
            reason: format!(
                "frame length inconsistency: computed {expected_frame_len}, stored {}",
                frame.len()
            ),
        });
    }

    let data = frame[data_start..data_end].to_vec();

    let prev_hash_start = data_end;
    let mut prev_hash = [0u8; 32];
    prev_hash.copy_from_slice(&frame[prev_hash_start..prev_hash_start + 32]);

    let record_hash_start = prev_hash_start + 32;
    let mut record_hash = [0u8; 32];
    record_hash.copy_from_slice(&frame[record_hash_start..record_hash_start + 32]);

    let sig_start = record_hash_start + 32;
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&frame[sig_start..sig_start + 64]);

    // The last 4 bytes are the CRC (already verified by the caller).

    Ok(Record {
        id,
        timestamp,
        table,
        author,
        data,
        flags,
        correction_of,
        prev_hash,
        record_hash,
        signature,
    })
}

// Segment scanning (read path, crash recovery)

/// Result of scanning a segment file.
pub struct ScanResult {
    /// Successfully parsed records paired with their byte offsets in the file.
    pub records: Vec<(u64, Record)>,
    /// Sequence number embedded in the file header.
    pub sequence: u32,
    /// If the file has a partial tail write from a crash (unexpected EOF),
    /// this is the byte offset to which the file should be truncated.
    pub truncate_at: Option<u64>,
    /// If a complete frame has a CRC mismatch or corrupt fields (tampering),
    /// this records the byte offset where corruption was first encountered.
    pub corrupt_at: Option<u64>,
}

/// Read all valid records from a segment file, handling crash recovery.
///
/// # Crash recovery
///
/// If the final frame is incomplete (unexpected EOF while reading frame body)
/// or has a CRC mismatch, `truncate_at` is set to the byte offset of that
/// frame's start.  The caller is responsible for actually truncating the file.
///
/// # Tamper detection
///
/// A CRC mismatch on a *complete* frame (all bytes present) also sets
/// `truncate_at`.  The [`store::Store::verify_table`] method re-scans with
/// full hash-chain checks and reports whether the cause is a crash or tampering.
pub fn scan_segment(path: &Path) -> Result<ScanResult> {
    let file = File::open(path)?;
    let file_size = file.metadata()?.len();
    let mut reader = BufReader::new(file);

    // Read and validate the 32-byte segment header.
    let sequence = read_segment_header(&mut reader, path)?;

    let mut records = Vec::new();
    let mut current_offset = SEGMENT_HEADER_SIZE as u64;
    let mut truncate_at: Option<u64> = None;
    let mut corrupt_at: Option<u64> = None;

    loop {
        let frame_start = current_offset;

        // --- Step 1: read the 4-byte frame length ---
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // Clean EOF if at current_offset == file_size, otherwise partial length bytes.
                if current_offset < file_size {
                    truncate_at = Some(frame_start);
                }
                break;
            }
            Err(e) => return Err(InkError::Io(e)),
        }

        let frame_len = u32::from_le_bytes(len_buf) as usize;

        // Sanity-check frame length before allocating.
        if !(FRAME_MIN_SIZE..=FRAME_MAX_SIZE).contains(&frame_len) {
            corrupt_at = Some(frame_start);
            break;
        }

        // --- Step 2: read the rest of the frame ---
        let mut rest = vec![0u8; frame_len - 4];
        match reader.read_exact(&mut rest) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // Partial frame at EOF — this is a crash recovery case.
                truncate_at = Some(frame_start);
                break;
            }
            Err(e) => return Err(InkError::Io(e)),
        }

        // --- Step 3: verify CRC (last 4 bytes of the complete frame) ---
        let mut frame = Vec::with_capacity(frame_len);
        frame.extend_from_slice(&len_buf);
        frame.extend_from_slice(&rest);

        let stored_crc = u32::from_le_bytes(frame[frame_len - 4..frame_len].try_into().unwrap());
        let computed_crc = crc32fast::hash(&frame[..frame_len - 4]);

        if stored_crc != computed_crc {
            // CRC failure on a complete frame — this is corruption or tampering.
            // Do NOT truncate: let verify_table catch and report it.
            corrupt_at = Some(frame_start);
            break;
        }

        // --- Step 4: parse fields from the validated frame ---
        let record = parse_record_from_frame(&frame, frame_start, path)?;
        records.push((frame_start, record));
        current_offset = frame_start + frame_len as u64;
    }

    Ok(ScanResult {
        records,
        sequence,
        truncate_at,
        corrupt_at,
    })
}

/// Read a single record from a segment file at a known byte offset.
///
/// Used by [`store::Store::get_record`] for index-based lookups.
pub fn read_record_at(path: &Path, byte_offset: u64) -> Result<Record> {
    use std::io::Seek;

    let mut file = File::open(path)?;
    file.seek(io::SeekFrom::Start(byte_offset))?;
    let mut reader = BufReader::new(file);

    // Read frame length
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            InkError::CorruptRecord {
                offset: byte_offset,
                path: path.to_string_lossy().to_string(),
                reason: "unexpected EOF reading frame length".to_string(),
            }
        } else {
            InkError::Io(e)
        }
    })?;

    let frame_len = u32::from_le_bytes(len_buf) as usize;
    if !(FRAME_MIN_SIZE..=FRAME_MAX_SIZE).contains(&frame_len) {
        return Err(InkError::CorruptRecord {
            offset: byte_offset,
            path: path.to_string_lossy().to_string(),
            reason: format!("invalid frame length {frame_len}"),
        });
    }

    let mut rest = vec![0u8; frame_len - 4];
    reader.read_exact(&mut rest)?;

    let mut frame = Vec::with_capacity(frame_len);
    frame.extend_from_slice(&len_buf);
    frame.extend_from_slice(&rest);

    // Verify CRC
    let stored_crc = u32::from_le_bytes(frame[frame_len - 4..].try_into().unwrap());
    let computed_crc = crc32fast::hash(&frame[..frame_len - 4]);
    if stored_crc != computed_crc {
        return Err(InkError::CrcMismatch {
            offset: byte_offset,
            path: path.to_string_lossy().to_string(),
        });
    }

    parse_record_from_frame(&frame, byte_offset, path)
}

// File listing helper

/// List all segment files in a table directory, sorted by sequence number.
///
/// Returns a `Vec` of `(sequence_number, path, is_sealed)` tuples.
pub fn list_table_segments(table_dir: &Path) -> Result<Vec<(u32, PathBuf, bool)>> {
    let mut segments = Vec::new();

    if !table_dir.exists() {
        return Ok(segments);
    }

    for entry in fs::read_dir(table_dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        if let Some(rest) = name.strip_prefix("seg_") {
            if let Some(seq_str) = rest.strip_suffix(".sealed") {
                if let Ok(seq) = seq_str.parse::<u32>() {
                    segments.push((seq, path, true)); // sealed
                }
            } else if let Some(seq_str) = rest.strip_suffix(".ink") {
                if let Ok(seq) = seq_str.parse::<u32>() {
                    segments.push((seq, path, false)); // active
                }
            }
        }
    }

    // Sort by sequence number so we scan in insertion order.
    segments.sort_by_key(|(seq, _, _)| *seq);
    Ok(segments)
}

// SegmentWriter

/// Writes records to an append-only segment file.
///
/// Each record write is followed by an `fsync` to guarantee durability.
/// When the segment reaches `max_size`, call [`seal`] to rename it and
/// create a new active segment.
pub struct SegmentWriter {
    /// Open file handle (append mode).
    file: File,
    /// Absolute path of this segment file (always has `.ink` extension).
    path: PathBuf,
    /// Sequence number of this segment within its table directory.
    sequence: u32,
    /// Current file size in bytes (equals position of the next write).
    size: u64,
    /// Maximum file size before the caller should seal this segment.
    max_size: u64,
}

impl SegmentWriter {
    /// Create a brand-new segment file and write the 32-byte header.
    pub fn create(path: PathBuf, sequence: u32, max_size: u64) -> Result<Self> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(&path)?;

        let created_at = now_micros();
        write_segment_header(&mut file, sequence, created_at)?;
        file.sync_all()?;

        Ok(Self {
            file,
            path,
            sequence,
            size: SEGMENT_HEADER_SIZE as u64,
            max_size,
        })
    }

    /// Open an existing segment file for appending.
    ///
    /// The caller must have already scanned the file (via [`scan_segment`])
    /// and truncated any corrupt tail before calling this method.
    pub fn open(path: PathBuf, sequence: u32, max_size: u64) -> Result<Self> {
        let file = OpenOptions::new().append(true).open(&path)?;
        let size = fs::metadata(&path)?.len();

        Ok(Self {
            file,
            path,
            sequence,
            size,
            max_size,
        })
    }

    /// Append a record frame to this segment.
    ///
    /// Returns the byte offset within the file where this frame begins.
    /// The write is followed by an `fsync` to ensure durability.
    pub fn append_record(&mut self, record: &Record) -> Result<u64> {
        let frame_start = self.size;
        let frame_len = write_record_frame(&mut self.file, record)?;
        self.file.sync_all()?;
        self.size += frame_len as u64;
        Ok(frame_start)
    }

    /// Seal this segment by renaming it from `.ink` to `.sealed`.
    ///
    /// Consumes `self` to prevent further writes. The returned path is the
    /// sealed file's new location.
    pub fn seal(self) -> Result<PathBuf> {
        self.file.sync_all()?;
        // Drop the file handle before renaming (required on Windows).
        drop(self.file);

        let sealed = self.path.with_extension("sealed");
        fs::rename(&self.path, &sealed)?;
        Ok(sealed)
    }

    /// Returns `true` if the segment has reached or exceeded its maximum size.
    #[inline]
    pub fn is_full(&self) -> bool {
        self.size >= self.max_size
    }

    /// Sequence number of this segment within its table directory.
    #[inline]
    pub fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Absolute path of this segment file.
    #[inline]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Current file size in bytes.
    #[inline]
    pub fn size(&self) -> u64 {
        self.size
    }
}

// Time helper (priv)

/// Current time as microseconds since the Unix epoch (UTC).
pub fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::compute_record_hash;
    use tempfile::tempdir;

    fn make_record(id: u64, table: &str, data: &[u8]) -> Record {
        let prev_hash = [0u8; 32];
        let author = [0u8; 32];
        let record_hash =
            compute_record_hash(id, 1_000_000, table, &author, 0, None, data, &prev_hash);
        Record {
            id,
            timestamp: 1_000_000,
            table: table.to_string(),
            author,
            data: data.to_vec(),
            flags: 0,
            correction_of: None,
            prev_hash,
            record_hash,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn write_and_scan_single_record() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("seg_000000.ink");

        let record = make_record(0, "sales", b"{\"amount\": 100}");

        // Write
        let mut writer = SegmentWriter::create(path.clone(), 0, 64 * 1024 * 1024).unwrap();
        let offset = writer.append_record(&record).unwrap();
        assert_eq!(offset, SEGMENT_HEADER_SIZE as u64);
        drop(writer);

        // Scan
        let result = scan_segment(&path).unwrap();
        assert_eq!(result.sequence, 0);
        assert!(result.truncate_at.is_none());
        assert_eq!(result.records.len(), 1);
        let (off, r) = &result.records[0];
        assert_eq!(*off, SEGMENT_HEADER_SIZE as u64);
        assert_eq!(r.id, 0);
        assert_eq!(r.data, b"{\"amount\": 100}");
    }

    #[test]
    fn write_multiple_records_then_scan() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("seg_000000.ink");

        let r0 = make_record(0, "t", b"{\"n\":0}");
        let r1 = make_record(1, "t", b"{\"n\":1}");
        let r2 = make_record(2, "t", b"{\"n\":2}");

        let mut writer = SegmentWriter::create(path.clone(), 0, 64 * 1024 * 1024).unwrap();
        writer.append_record(&r0).unwrap();
        writer.append_record(&r1).unwrap();
        writer.append_record(&r2).unwrap();
        drop(writer);

        let result = scan_segment(&path).unwrap();
        assert!(result.truncate_at.is_none());
        assert_eq!(result.records.len(), 3);
        for (i, (_, r)) in result.records.iter().enumerate() {
            assert_eq!(r.id, i as u64);
        }
    }

    #[test]
    fn read_record_at_offset() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("seg_000000.ink");

        let r0 = make_record(0, "t", b"{\"n\":0}");
        let r1 = make_record(1, "t", b"{\"n\":1}");

        let mut writer = SegmentWriter::create(path.clone(), 0, 64 * 1024 * 1024).unwrap();
        let off0 = writer.append_record(&r0).unwrap();
        let off1 = writer.append_record(&r1).unwrap();
        drop(writer);

        let rec0 = read_record_at(&path, off0).unwrap();
        assert_eq!(rec0.id, 0);

        let rec1 = read_record_at(&path, off1).unwrap();
        assert_eq!(rec1.id, 1);
    }

    #[test]
    fn corrupt_crc_detected_on_scan() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("seg_000000.ink");

        let r0 = make_record(0, "t", b"{\"n\":0}");
        let r1 = make_record(1, "t", b"{\"n\":1}");

        let mut writer = SegmentWriter::create(path.clone(), 0, 64 * 1024 * 1024).unwrap();
        let off0 = writer.append_record(&r0).unwrap();
        writer.append_record(&r1).unwrap();
        drop(writer);

        // Corrupt one byte in the DATA section of r0.
        // Data starts at offset: off0 + 70 + table_len("t" = 1) = off0 + 71
        let mut bytes = fs::read(&path).unwrap();
        let data_offset = off0 as usize + 70 + 1; // 70 + N where N = len("t") = 1
        bytes[data_offset] ^= 0xFF;
        fs::write(&path, &bytes).unwrap();

        let result = scan_segment(&path).unwrap();
        // The scan should stop at r0's frame and flag corrupt_at.
        assert!(result.corrupt_at.is_some());
        assert_eq!(result.corrupt_at, Some(off0));
        assert!(result.truncate_at.is_none());
        // No valid records returned (r0 itself is corrupt).
        assert!(result.records.is_empty());
    }

    #[test]
    fn list_table_segments_mixed() {
        let dir = tempdir().unwrap();
        let d = dir.path();

        // Create dummy files
        fs::write(d.join("seg_000000.sealed"), b"").unwrap();
        fs::write(d.join("seg_000001.sealed"), b"").unwrap();
        fs::write(d.join("seg_000002.ink"), b"").unwrap();
        fs::write(d.join("unrelated.txt"), b"").unwrap();

        let segs = list_table_segments(d).unwrap();
        assert_eq!(segs.len(), 3);
        assert_eq!(segs[0].0, 0);
        assert!(segs[0].2); // sealed
        assert_eq!(segs[1].0, 1);
        assert!(segs[1].2); // sealed
        assert_eq!(segs[2].0, 2);
        assert!(!segs[2].2); // active
    }
}
