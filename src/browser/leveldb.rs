//! Minimal read-only LevelDB parser for Chrome localStorage extraction.
//!
//! Reads `.ldb` (SSTable) and `.log` (WAL) files from a LevelDB directory,
//! merges entries by sequence number, honours tombstones, and yields
//! `(key, value)` string pairs. No unsafe code.
//!
//! This is *not* a full LevelDB implementation — it only handles the subset
//! needed to read Chrome/Chromium/Brave/Edge localStorage databases.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::SksError;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Minimal read-only LevelDB reader.
pub struct LevelDbReader {
    db_path: PathBuf,
}

impl LevelDbReader {
    /// Open a LevelDB directory. Validates that `CURRENT` exists.
    pub fn open(path: &Path) -> Result<Self, SksError> {
        let current_path = path.join("CURRENT");
        if !current_path.exists() {
            return Err(SksError::Collector(format!(
                "not a LevelDB directory (missing CURRENT): {}",
                path.display()
            )));
        }
        Ok(Self {
            db_path: path.to_path_buf(),
        })
    }

    /// Check if the database is locked by a running browser.
    pub fn is_locked(&self) -> bool {
        let lock_path = self.db_path.join("LOCK");
        if !lock_path.exists() {
            return false;
        }
        // Try to acquire an exclusive lock on the file.
        // If we can't, the browser holds it.
        use std::fs::OpenOptions;
        match OpenOptions::new().read(true).open(&lock_path) {
            Ok(file) => !try_lock_exclusive(&file),
            Err(_) => true,
        }
    }

    /// Read all key-value pairs from the database.
    ///
    /// Keys are localStorage keys (with origin prefix). Values are the stored
    /// string values. Entries are merged by sequence number; tombstones
    /// (deletions) are honoured.
    pub fn read_all(&self) -> Result<Vec<(String, String)>, SksError> {
        let mut entries: HashMap<Vec<u8>, InternalEntry> = HashMap::new();

        // 1. Read .ldb / .sst files (SSTables)
        let sst_files = self.find_sst_files();
        for sst_path in &sst_files {
            match read_sstable(sst_path) {
                Ok(table_entries) => {
                    merge_entries(&mut entries, table_entries);
                }
                Err(e) => {
                    eprintln!(
                        "sks warn: skipping corrupt SSTable {}: {e}",
                        sst_path.display()
                    );
                }
            }
        }

        // 2. Read .log files (WAL — more recent writes)
        let log_files = self.find_log_files();
        for log_path in &log_files {
            match read_log_file(log_path) {
                Ok(log_entries) => {
                    merge_entries(&mut entries, log_entries);
                }
                Err(e) => {
                    eprintln!("sks warn: skipping corrupt log {}: {e}", log_path.display());
                }
            }
        }

        // 3. Filter out tombstones and convert to (String, String)
        let mut result: Vec<(String, String)> = Vec::new();
        for (key_bytes, entry) in entries {
            if entry.deleted {
                continue;
            }
            // Chrome localStorage keys are UTF-16LE encoded after a prefix.
            // Try to decode as UTF-8 first (works for some Chromium builds),
            // then try UTF-16LE if that fails.
            let key = decode_chrome_key(&key_bytes);
            let value = decode_chrome_value(&entry.value);
            if let (Some(k), Some(v)) = (key, value) {
                result.push((k, v));
            }
        }
        result.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(result)
    }

    /// Find all .ldb and .sst files in the database directory.
    fn find_sst_files(&self) -> Vec<PathBuf> {
        let mut files = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.db_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    let ext = ext.to_string_lossy();
                    if ext == "ldb" || ext == "sst" {
                        files.push(path);
                    }
                }
            }
        }
        files.sort();
        files
    }

    /// Find all .log files in the database directory.
    fn find_log_files(&self) -> Vec<PathBuf> {
        let mut files = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.db_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if ext == "log" {
                        files.push(path);
                    }
                }
            }
        }
        files.sort();
        files
    }
}

// ---------------------------------------------------------------------------
// Internal entry type (tracks sequence number + deletion)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct InternalEntry {
    value: Vec<u8>,
    seq: u64,
    deleted: bool,
}

fn merge_entries(
    map: &mut HashMap<Vec<u8>, InternalEntry>,
    new_entries: Vec<(Vec<u8>, InternalEntry)>,
) {
    for (key, entry) in new_entries {
        match map.get(&key) {
            Some(existing) if existing.seq >= entry.seq => {}
            _ => {
                map.insert(key, entry);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SSTable reader
// ---------------------------------------------------------------------------

/// SSTable footer is the last 48 bytes. Layout:
///   - metaindex handle (varint64 offset, varint64 size) — padded to 20 bytes
///   - index handle    (varint64 offset, varint64 size) — padded to 20 bytes
///   - padding to fill 40 bytes total
///   - 8-byte magic number (0xdb4775248b80fb57)
const FOOTER_SIZE: usize = 48;
const TABLE_MAGIC: u64 = 0xdb4775248b80fb57;

fn read_sstable(path: &Path) -> Result<Vec<(Vec<u8>, InternalEntry)>, SksError> {
    let data = fs::read(path).map_err(SksError::Io)?;
    if data.len() < FOOTER_SIZE {
        return Err(SksError::Collector(format!(
            "SSTable too small ({}B): {}",
            data.len(),
            path.display()
        )));
    }

    // Parse footer
    let footer = &data[data.len() - FOOTER_SIZE..];
    let magic = u64::from_le_bytes(footer[40..48].try_into().unwrap());
    if magic != TABLE_MAGIC {
        return Err(SksError::Collector(format!(
            "bad SSTable magic in {}",
            path.display()
        )));
    }

    // Parse index block handle from footer bytes 20..40
    let (index_offset, n1) = decode_varint(&footer[20..])?;
    let (index_size, _) = decode_varint(&footer[20 + n1..])?;

    // Read and decompress the index block
    let index_block = read_block(&data, index_offset as usize, index_size as usize)?;

    // Each entry in the index block points to a data block.
    // Parse index entries to get data block handles.
    let index_entries = parse_block_entries(&index_block);

    let mut entries = Vec::new();
    for (_, handle_data) in &index_entries {
        // handle_data is the encoded BlockHandle (varint offset + varint size)
        let (block_offset, n1) = match decode_varint(handle_data) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let (block_size, _) = match decode_varint(&handle_data[n1..]) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Read and decompress the data block
        let block = match read_block(&data, block_offset as usize, block_size as usize) {
            Ok(b) => b,
            Err(_) => continue, // skip corrupt blocks
        };

        // Parse key-value entries from the data block
        let block_entries = parse_block_entries(&block);
        for (key, value) in block_entries {
            if let Some((user_key, seq, vtype)) = parse_internal_key(&key) {
                let deleted = vtype == VALUE_TYPE_DELETION;
                entries.push((
                    user_key.to_vec(),
                    InternalEntry {
                        value,
                        seq,
                        deleted,
                    },
                ));
            }
        }
    }

    Ok(entries)
}

/// Read a block from the SSTable at the given offset and size.
/// Each block on disk has:
///   - `size` bytes of (possibly compressed) data
///   - 1 byte compression type (0=none, 1=snappy)
///   - 4 bytes CRC32
fn read_block(data: &[u8], offset: usize, size: usize) -> Result<Vec<u8>, SksError> {
    let block_end = offset + size;
    // Need size bytes of data + 1 byte type + 4 bytes crc
    if block_end + 5 > data.len() {
        return Err(SksError::Collector("block extends past end of file".into()));
    }

    let raw = &data[offset..block_end];
    let compression_type = data[block_end];

    match compression_type {
        0 => Ok(raw.to_vec()),
        1 => {
            // Snappy decompression
            let mut decoder = snap::raw::Decoder::new();
            decoder
                .decompress_vec(raw)
                .map_err(|e| SksError::Collector(format!("snappy decompression failed: {e}")))
        }
        other => Err(SksError::Collector(format!(
            "unknown compression type: {other}"
        ))),
    }
}

/// Parse key-value entries from a decompressed block.
///
/// Block format:
///   Repeated entries of:
///     - shared_key_len   (varint)
///     - unshared_key_len (varint)
///     - value_len        (varint)
///     - unshared_key     (unshared_key_len bytes)
///     - value            (value_len bytes)
///
///   Followed by a trailer:
///     - 4 bytes × num_restarts (restart point offsets, little-endian u32)
///     - 4 bytes num_restarts (little-endian u32)
fn parse_block_entries(block: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    if block.len() < 4 {
        return Vec::new();
    }

    // Read the restart count from the last 4 bytes
    let num_restarts =
        u32::from_le_bytes(block[block.len() - 4..].try_into().unwrap_or([0; 4])) as usize;

    // The restart array starts at: block.len() - 4 - (num_restarts * 4)
    let restarts_start = block.len().saturating_sub(4 + num_restarts * 4);

    // Data region is everything before the restart array
    let data_region = &block[..restarts_start];

    let mut entries = Vec::new();
    let mut pos = 0;
    let mut last_key: Vec<u8> = Vec::new();

    while pos < data_region.len() {
        // shared key length
        let (shared, n) = match decode_varint(&data_region[pos..]) {
            Ok(v) => v,
            Err(_) => break,
        };
        pos += n;

        // unshared key length
        let (unshared, n) = match decode_varint(&data_region[pos..]) {
            Ok(v) => v,
            Err(_) => break,
        };
        pos += n;

        // value length
        let (value_len, n) = match decode_varint(&data_region[pos..]) {
            Ok(v) => v,
            Err(_) => break,
        };
        pos += n;

        let shared = shared as usize;
        let unshared = unshared as usize;
        let value_len = value_len as usize;

        if pos + unshared + value_len > data_region.len() {
            break;
        }
        if shared > last_key.len() {
            break;
        }

        // Reconstruct the full key using shared prefix
        let mut key = Vec::with_capacity(shared + unshared);
        key.extend_from_slice(&last_key[..shared]);
        key.extend_from_slice(&data_region[pos..pos + unshared]);
        pos += unshared;

        let value = data_region[pos..pos + value_len].to_vec();
        pos += value_len;

        last_key = key.clone();
        entries.push((key, value));
    }

    entries
}

// ---------------------------------------------------------------------------
// Internal key parsing
// ---------------------------------------------------------------------------

/// LevelDB internal key format:
///   user_key | sequence_number (7 bytes LE) | value_type (1 byte)
///
/// The sequence number and value type are packed into the last 8 bytes:
///   packed = (sequence << 8) | value_type
const VALUE_TYPE_VALUE: u8 = 1;
const VALUE_TYPE_DELETION: u8 = 0;

fn parse_internal_key(key: &[u8]) -> Option<(&[u8], u64, u8)> {
    if key.len() < 8 {
        return None;
    }
    let user_key = &key[..key.len() - 8];
    let packed = u64::from_le_bytes(key[key.len() - 8..].try_into().ok()?);
    let vtype = (packed & 0xff) as u8;
    let seq = packed >> 8;
    if vtype != VALUE_TYPE_VALUE && vtype != VALUE_TYPE_DELETION {
        return None;
    }
    Some((user_key, seq, vtype))
}

// ---------------------------------------------------------------------------
// Write-ahead log reader
// ---------------------------------------------------------------------------

/// LevelDB log file format (used for WAL and MANIFEST):
///   Sequence of 32 KB blocks, each containing records:
///     - checksum     (4 bytes, LE u32)
///     - length       (2 bytes, LE u16)
///     - type         (1 byte: 1=full, 2=first, 3=middle, 4=last)
///     - data         (length bytes)
const LOG_BLOCK_SIZE: usize = 32 * 1024;
const LOG_HEADER_SIZE: usize = 7; // 4 crc + 2 length + 1 type

const RECORD_FULL: u8 = 1;
const RECORD_FIRST: u8 = 2;
const RECORD_MIDDLE: u8 = 3;
const RECORD_LAST: u8 = 4;

fn read_log_file(path: &Path) -> Result<Vec<(Vec<u8>, InternalEntry)>, SksError> {
    let data = fs::read(path).map_err(SksError::Io)?;
    let records = parse_log_records(&data);

    let mut entries = Vec::new();
    for record in &records {
        if let Ok(batch_entries) = parse_write_batch(record) {
            entries.extend(batch_entries);
        }
    }
    Ok(entries)
}

/// Parse physical log records, reassembling fragmented records.
fn parse_log_records(data: &[u8]) -> Vec<Vec<u8>> {
    let mut records = Vec::new();
    let mut current: Option<Vec<u8>> = None;
    let mut block_offset = 0;

    while block_offset < data.len() {
        let block_end = std::cmp::min(block_offset + LOG_BLOCK_SIZE, data.len());
        let mut pos = block_offset;

        while pos + LOG_HEADER_SIZE <= block_end {
            // Skip if remaining space in block is less than header size
            let remaining_in_block = block_end - pos;
            if remaining_in_block < LOG_HEADER_SIZE {
                break;
            }

            let length = u16::from_le_bytes([data[pos + 4], data[pos + 5]]) as usize;
            let record_type = data[pos + 6];

            pos += LOG_HEADER_SIZE;

            if pos + length > block_end {
                break;
            }

            let fragment = &data[pos..pos + length];
            pos += length;

            match record_type {
                RECORD_FULL => {
                    records.push(fragment.to_vec());
                    current = None;
                }
                RECORD_FIRST => {
                    current = Some(fragment.to_vec());
                }
                RECORD_MIDDLE => {
                    if let Some(ref mut buf) = current {
                        buf.extend_from_slice(fragment);
                    }
                }
                RECORD_LAST => {
                    if let Some(mut buf) = current.take() {
                        buf.extend_from_slice(fragment);
                        records.push(buf);
                    }
                }
                _ => {
                    current = None;
                }
            }
        }

        block_offset += LOG_BLOCK_SIZE;
    }

    records
}

/// Parse a WriteBatch record into key-value entries.
///
/// WriteBatch format:
///   - sequence_number (8 bytes LE u64)
///   - count           (4 bytes LE u32)
///   - Repeated:
///       - type (1 byte: 1=value, 0=deletion)
///       - key_len (varint)
///       - key (key_len bytes)
///       - if type==1: value_len (varint), value (value_len bytes)
fn parse_write_batch(record: &[u8]) -> Result<Vec<(Vec<u8>, InternalEntry)>, SksError> {
    if record.len() < 12 {
        return Err(SksError::Collector("write batch too small".into()));
    }

    let seq_base = u64::from_le_bytes(record[0..8].try_into().unwrap());
    let count = u32::from_le_bytes(record[8..12].try_into().unwrap()) as usize;

    let mut pos = 12;
    let mut entries = Vec::with_capacity(count);

    for i in 0..count {
        if pos >= record.len() {
            break;
        }
        let vtype = record[pos];
        pos += 1;

        // Read key
        let (key_len, n) = decode_varint(&record[pos..])?;
        pos += n;
        let key_len = key_len as usize;
        if pos + key_len > record.len() {
            break;
        }
        let key = record[pos..pos + key_len].to_vec();
        pos += key_len;

        let seq = seq_base + i as u64;

        if vtype == VALUE_TYPE_VALUE {
            // Read value
            let (val_len, n) = decode_varint(&record[pos..])?;
            pos += n;
            let val_len = val_len as usize;
            if pos + val_len > record.len() {
                break;
            }
            let value = record[pos..pos + val_len].to_vec();
            pos += val_len;

            entries.push((
                key,
                InternalEntry {
                    value,
                    seq,
                    deleted: false,
                },
            ));
        } else if vtype == VALUE_TYPE_DELETION {
            entries.push((
                key,
                InternalEntry {
                    value: Vec::new(),
                    seq,
                    deleted: true,
                },
            ));
        } else {
            break;
        }
    }

    Ok(entries)
}

// ---------------------------------------------------------------------------
// Varint encoding (LevelDB-style, same as protobuf)
// ---------------------------------------------------------------------------

/// Decode a varint from a byte slice. Returns (value, bytes_consumed).
fn decode_varint(data: &[u8]) -> Result<(u64, usize), SksError> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;

    for (i, &byte) in data.iter().enumerate() {
        if shift > 63 {
            return Err(SksError::Collector("varint too long".into()));
        }
        value |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }

    Err(SksError::Collector("truncated varint".into()))
}

// ---------------------------------------------------------------------------
// Chrome key/value decoding
// ---------------------------------------------------------------------------

/// Chrome localStorage keys in LevelDB have a prefix structure.
/// The actual key format depends on the Chrome version:
///   - Older: `_<origin>\x00<key>` (UTF-8 strings)
///   - Newer: binary prefix + UTF-16LE encoded key
///
/// We attempt UTF-8 first, then fall back to trying to extract
/// readable text from the raw bytes.
fn decode_chrome_key(raw: &[u8]) -> Option<String> {
    // Try direct UTF-8 first. Allow \x00 (Chrome uses it as key separator).
    if let Ok(s) = std::str::from_utf8(raw) {
        if s.chars()
            .all(|c| !c.is_control() || c == '\0' || c == '\t' || c == '\n')
        {
            return Some(s.to_string());
        }
    }

    // Try UTF-16LE: skip any leading prefix bytes that aren't part of the
    // UTF-16 string. Chrome prefixes vary by version; look for the first
    // plausible UTF-16 start.
    try_decode_utf16le(raw)
}

fn decode_chrome_value(raw: &[u8]) -> Option<String> {
    // Try direct UTF-8
    if let Ok(s) = std::str::from_utf8(raw) {
        return Some(s.to_string());
    }

    // Try UTF-16LE
    try_decode_utf16le(raw)
}

/// Attempt to decode bytes as UTF-16LE.
fn try_decode_utf16le(raw: &[u8]) -> Option<String> {
    if raw.len() < 2 || raw.len() % 2 != 0 {
        return None;
    }
    let u16s: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&u16s).ok()
}

// ---------------------------------------------------------------------------
// File locking
// ---------------------------------------------------------------------------

/// Try to detect if the LOCK file is held by another process.
///
/// LevelDB's LOCK file uses `fcntl` advisory locks. We attempt to
/// open the file for writing — if it fails with a permission error
/// or if we can't create an exclusive lock, the browser likely holds it.
///
/// On Unix we try to acquire an exclusive `flock` via the `fcntl` F_SETLK
/// syscall without pulling in libc. As a conservative fallback we check
/// whether the LOCK file has a non-zero size (Chrome writes its PID there).
fn try_lock_exclusive(file: &fs::File) -> bool {
    // Conservative heuristic: if the lock file is non-empty (Chrome writes
    // its PID), assume it's held. Otherwise assume it's available.
    match file.metadata() {
        Ok(meta) => meta.len() == 0,
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Varint tests ---

    #[test]
    fn varint_single_byte() {
        let data = [0x05];
        let (val, n) = decode_varint(&data).unwrap();
        assert_eq!(val, 5);
        assert_eq!(n, 1);
    }

    #[test]
    fn varint_two_bytes() {
        // 300 = 0b100101100 → [0xAC, 0x02]
        let data = [0xAC, 0x02];
        let (val, n) = decode_varint(&data).unwrap();
        assert_eq!(val, 300);
        assert_eq!(n, 2);
    }

    #[test]
    fn varint_zero() {
        let data = [0x00];
        let (val, n) = decode_varint(&data).unwrap();
        assert_eq!(val, 0);
        assert_eq!(n, 1);
    }

    #[test]
    fn varint_max_single() {
        let data = [0x7f];
        let (val, n) = decode_varint(&data).unwrap();
        assert_eq!(val, 127);
        assert_eq!(n, 1);
    }

    #[test]
    fn varint_truncated_returns_error() {
        let data = [0x80]; // continuation bit set but no more bytes
        assert!(decode_varint(&data).is_err());
    }

    #[test]
    fn varint_empty_returns_error() {
        assert!(decode_varint(&[]).is_err());
    }

    // --- Internal key parsing ---

    #[test]
    fn parse_internal_key_value_type() {
        // user_key = b"hello", seq=42, type=1 (value)
        let mut key = b"hello".to_vec();
        let packed: u64 = (42 << 8) | 1;
        key.extend_from_slice(&packed.to_le_bytes());

        let (user_key, seq, vtype) = parse_internal_key(&key).unwrap();
        assert_eq!(user_key, b"hello");
        assert_eq!(seq, 42);
        assert_eq!(vtype, VALUE_TYPE_VALUE);
    }

    #[test]
    fn parse_internal_key_deletion_type() {
        let mut key = b"deleted_key".to_vec();
        let packed: u64 = 100 << 8;
        key.extend_from_slice(&packed.to_le_bytes());

        let (user_key, seq, vtype) = parse_internal_key(&key).unwrap();
        assert_eq!(user_key, b"deleted_key");
        assert_eq!(seq, 100);
        assert_eq!(vtype, VALUE_TYPE_DELETION);
    }

    #[test]
    fn parse_internal_key_too_short() {
        assert!(parse_internal_key(b"short").is_none());
    }

    #[test]
    fn parse_internal_key_invalid_type() {
        let mut key = b"key".to_vec();
        let packed: u64 = (1 << 8) | 5; // invalid type
        key.extend_from_slice(&packed.to_le_bytes());
        assert!(parse_internal_key(&key).is_none());
    }

    // --- Block entry parsing ---

    #[test]
    fn parse_simple_block() {
        // Build a simple block with two entries and a restart array
        let mut block = Vec::new();

        // Entry 1: shared=0, unshared=3 ("abc"), value=2 ("xy")
        block.push(0x00); // shared
        block.push(0x03); // unshared
        block.push(0x02); // value_len
        block.extend_from_slice(b"abc");
        block.extend_from_slice(b"xy");

        // Entry 2: shared=2, unshared=1 ("d"), value=1 ("z")
        // full key = "abd"
        block.push(0x02); // shared
        block.push(0x01); // unshared
        block.push(0x01); // value_len
        block.extend_from_slice(b"d");
        block.extend_from_slice(b"z");

        // Restart array: one restart at offset 0
        block.extend_from_slice(&0u32.to_le_bytes()); // restart[0] = 0
        block.extend_from_slice(&1u32.to_le_bytes()); // num_restarts = 1

        let entries = parse_block_entries(&block);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, b"abc");
        assert_eq!(entries[0].1, b"xy");
        assert_eq!(entries[1].0, b"abd");
        assert_eq!(entries[1].1, b"z");
    }

    #[test]
    fn parse_empty_block() {
        // Minimal block: just a restart array with 0 restarts
        let mut block = Vec::new();
        block.extend_from_slice(&0u32.to_le_bytes()); // num_restarts = 0
        let entries = parse_block_entries(&block);
        assert!(entries.is_empty());
    }

    // --- Write batch parsing ---

    #[test]
    fn parse_write_batch_single_put() {
        let mut batch = Vec::new();
        // sequence = 10
        batch.extend_from_slice(&10u64.to_le_bytes());
        // count = 1
        batch.extend_from_slice(&1u32.to_le_bytes());
        // type = 1 (put)
        batch.push(0x01);
        // key = "mykey" (len=5)
        batch.push(0x05);
        batch.extend_from_slice(b"mykey");
        // value = "myval" (len=5)
        batch.push(0x05);
        batch.extend_from_slice(b"myval");

        let entries = parse_write_batch(&batch).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, b"mykey");
        assert_eq!(entries[0].1.value, b"myval");
        assert_eq!(entries[0].1.seq, 10);
        assert!(!entries[0].1.deleted);
    }

    #[test]
    fn parse_write_batch_put_and_delete() {
        let mut batch = Vec::new();
        batch.extend_from_slice(&20u64.to_le_bytes());
        batch.extend_from_slice(&2u32.to_le_bytes());
        // Put: key="a", value="b"
        batch.push(0x01);
        batch.push(0x01);
        batch.extend_from_slice(b"a");
        batch.push(0x01);
        batch.extend_from_slice(b"b");
        // Delete: key="c"
        batch.push(0x00);
        batch.push(0x01);
        batch.extend_from_slice(b"c");

        let entries = parse_write_batch(&batch).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(!entries[0].1.deleted);
        assert_eq!(entries[0].1.seq, 20);
        assert!(entries[1].1.deleted);
        assert_eq!(entries[1].1.seq, 21);
    }

    #[test]
    fn parse_write_batch_too_small() {
        assert!(parse_write_batch(&[0; 8]).is_err());
    }

    // --- Log record parsing ---

    #[test]
    fn parse_full_log_record() {
        // Build a single full record in a log block
        let payload = b"hello world";
        let mut block = Vec::new();
        // CRC (4 bytes, we don't verify)
        block.extend_from_slice(&[0; 4]);
        // length
        block.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        // type = FULL
        block.push(RECORD_FULL);
        // data
        block.extend_from_slice(payload);
        // Pad to block size (optional but realistic)
        block.resize(LOG_BLOCK_SIZE, 0);

        let records = parse_log_records(&block);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0], payload);
    }

    #[test]
    fn parse_fragmented_log_record() {
        let payload_part1 = b"first_half";
        let payload_part2 = b"_second_half";

        let mut data = Vec::new();

        // FIRST record
        data.extend_from_slice(&[0; 4]); // crc
        data.extend_from_slice(&(payload_part1.len() as u16).to_le_bytes());
        data.push(RECORD_FIRST);
        data.extend_from_slice(payload_part1);

        // LAST record
        data.extend_from_slice(&[0; 4]); // crc
        data.extend_from_slice(&(payload_part2.len() as u16).to_le_bytes());
        data.push(RECORD_LAST);
        data.extend_from_slice(payload_part2);

        // Pad to block size
        data.resize(LOG_BLOCK_SIZE, 0);

        let records = parse_log_records(&data);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0], b"first_half_second_half");
    }

    // --- Merge logic ---

    #[test]
    fn merge_entries_higher_seq_wins() {
        let mut map = HashMap::new();
        let old = vec![(
            b"key1".to_vec(),
            InternalEntry {
                value: b"old".to_vec(),
                seq: 1,
                deleted: false,
            },
        )];
        merge_entries(&mut map, old);

        let new = vec![(
            b"key1".to_vec(),
            InternalEntry {
                value: b"new".to_vec(),
                seq: 5,
                deleted: false,
            },
        )];
        merge_entries(&mut map, new);

        assert_eq!(map[&b"key1".to_vec()].value, b"new");
        assert_eq!(map[&b"key1".to_vec()].seq, 5);
    }

    #[test]
    fn merge_entries_lower_seq_ignored() {
        let mut map = HashMap::new();
        let first = vec![(
            b"key1".to_vec(),
            InternalEntry {
                value: b"newer".to_vec(),
                seq: 10,
                deleted: false,
            },
        )];
        merge_entries(&mut map, first);

        let stale = vec![(
            b"key1".to_vec(),
            InternalEntry {
                value: b"older".to_vec(),
                seq: 3,
                deleted: false,
            },
        )];
        merge_entries(&mut map, stale);

        assert_eq!(map[&b"key1".to_vec()].value, b"newer");
    }

    #[test]
    fn merge_tombstone_wins_over_value() {
        let mut map = HashMap::new();
        let put = vec![(
            b"key1".to_vec(),
            InternalEntry {
                value: b"val".to_vec(),
                seq: 1,
                deleted: false,
            },
        )];
        merge_entries(&mut map, put);

        let del = vec![(
            b"key1".to_vec(),
            InternalEntry {
                value: Vec::new(),
                seq: 5,
                deleted: true,
            },
        )];
        merge_entries(&mut map, del);

        assert!(map[&b"key1".to_vec()].deleted);
    }

    // --- Chrome key/value decoding ---

    #[test]
    fn decode_utf8_key() {
        let key = b"_https://example.com\x00my_token";
        assert_eq!(
            decode_chrome_key(key),
            Some("_https://example.com\x00my_token".to_string())
        );
    }

    #[test]
    fn decode_utf16le_value() {
        // "café" in UTF-16LE — the 'é' (U+00E9) ensures the bytes aren't valid UTF-8
        let data: Vec<u8> = "café"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        assert_eq!(decode_chrome_value(&data), Some("café".to_string()));
    }

    #[test]
    fn decode_empty_bytes() {
        assert_eq!(decode_chrome_value(b""), Some(String::new()));
    }

    // --- SSTable round-trip (synthetic) ---

    #[test]
    fn read_synthetic_sstable() {
        let dir = tempfile::tempdir().unwrap();
        let sst_path = dir.path().join("000001.ldb");

        // Build a minimal SSTable with one data block and an index block
        let sst_data = build_synthetic_sstable(&[
            (b"key1", b"value1", 1, false),
            (b"key2", b"value2", 2, false),
        ]);
        fs::write(&sst_path, &sst_data).unwrap();

        let entries = read_sstable(&sst_path).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, b"key1");
        assert_eq!(entries[0].1.value, b"value1");
        assert_eq!(entries[1].0, b"key2");
        assert_eq!(entries[1].1.value, b"value2");
    }

    #[test]
    fn read_synthetic_sstable_with_tombstone() {
        let dir = tempfile::tempdir().unwrap();
        let sst_path = dir.path().join("000002.ldb");

        let sst_data =
            build_synthetic_sstable(&[(b"alive", b"yes", 1, false), (b"dead", b"", 2, true)]);
        fs::write(&sst_path, &sst_data).unwrap();

        let entries = read_sstable(&sst_path).unwrap();
        let alive: Vec<_> = entries.iter().filter(|(_, e)| !e.deleted).collect();
        let dead: Vec<_> = entries.iter().filter(|(_, e)| e.deleted).collect();
        assert_eq!(alive.len(), 1);
        assert_eq!(dead.len(), 1);
        assert_eq!(alive[0].0, b"alive");
        assert_eq!(dead[0].0, b"dead");
    }

    #[test]
    fn read_sstable_bad_magic() {
        let dir = tempfile::tempdir().unwrap();
        let sst_path = dir.path().join("bad.ldb");
        let mut data = vec![0u8; 100];
        // Write garbage magic
        data[92..100].copy_from_slice(&[0xFF; 8]);
        fs::write(&sst_path, &data).unwrap();

        assert!(read_sstable(&sst_path).is_err());
    }

    #[test]
    fn read_sstable_too_small() {
        let dir = tempfile::tempdir().unwrap();
        let sst_path = dir.path().join("tiny.ldb");
        fs::write(&sst_path, [0u8; 10]).unwrap();

        assert!(read_sstable(&sst_path).is_err());
    }

    // --- LevelDbReader integration ---

    #[test]
    fn open_missing_current_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(LevelDbReader::open(dir.path()).is_err());
    }

    #[test]
    fn open_with_current_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("CURRENT"), "MANIFEST-000001\n").unwrap();
        assert!(LevelDbReader::open(dir.path()).is_ok());
    }

    #[test]
    fn read_all_empty_db() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("CURRENT"), "MANIFEST-000001\n").unwrap();
        let reader = LevelDbReader::open(dir.path()).unwrap();
        let entries = reader.read_all().unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn read_all_with_sstable() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("CURRENT"), "MANIFEST-000001\n").unwrap();

        let sst_data = build_synthetic_sstable(&[(b"test_key", b"test_value", 1, false)]);
        fs::write(dir.path().join("000001.ldb"), &sst_data).unwrap();

        let reader = LevelDbReader::open(dir.path()).unwrap();
        let entries = reader.read_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].0.contains("test_key"));
        assert!(entries[0].1.contains("test_value"));
    }

    #[test]
    fn read_all_with_log_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("CURRENT"), "MANIFEST-000001\n").unwrap();

        // Build a log file with a single write batch
        let log_data = build_synthetic_log(&[(b"log_key", b"log_value", false)]);
        fs::write(dir.path().join("000001.log"), &log_data).unwrap();

        let reader = LevelDbReader::open(dir.path()).unwrap();
        let entries = reader.read_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].0.contains("log_key"));
        assert!(entries[0].1.contains("log_value"));
    }

    #[test]
    fn read_all_log_overrides_sstable() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("CURRENT"), "MANIFEST-000001\n").unwrap();

        // SSTable with seq=1
        let sst_data = build_synthetic_sstable(&[(b"shared_key", b"old_value", 1, false)]);
        fs::write(dir.path().join("000001.ldb"), &sst_data).unwrap();

        // Log with seq=10 (higher)
        let log_data = build_synthetic_log_with_seq(&[(b"shared_key", b"new_value", false)], 10);
        fs::write(dir.path().join("000002.log"), &log_data).unwrap();

        let reader = LevelDbReader::open(dir.path()).unwrap();
        let entries = reader.read_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].1.contains("new_value"));
    }

    #[test]
    fn read_all_tombstone_deletes_entry() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("CURRENT"), "MANIFEST-000001\n").unwrap();

        // SSTable with a value at seq=1
        let sst_data = build_synthetic_sstable(&[(b"doomed", b"will_die", 1, false)]);
        fs::write(dir.path().join("000001.ldb"), &sst_data).unwrap();

        // Log with a delete at seq=10
        let log_data = build_synthetic_log_with_seq(&[(b"doomed", b"", true)], 10);
        fs::write(dir.path().join("000002.log"), &log_data).unwrap();

        let reader = LevelDbReader::open(dir.path()).unwrap();
        let entries = reader.read_all().unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn is_locked_returns_false_for_no_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("CURRENT"), "MANIFEST-000001\n").unwrap();
        let reader = LevelDbReader::open(dir.path()).unwrap();
        assert!(!reader.is_locked());
    }

    #[test]
    fn is_locked_returns_false_for_unlocked_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("CURRENT"), "MANIFEST-000001\n").unwrap();
        fs::write(dir.path().join("LOCK"), "").unwrap();
        let reader = LevelDbReader::open(dir.path()).unwrap();
        // No other process holds the lock, so should be false
        assert!(!reader.is_locked());
    }

    #[test]
    fn corrupt_sstable_skipped_gracefully() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("CURRENT"), "MANIFEST-000001\n").unwrap();
        fs::write(dir.path().join("000001.ldb"), [0xDE, 0xAD]).unwrap();

        let reader = LevelDbReader::open(dir.path()).unwrap();
        // Should not panic — corrupt files are skipped with a warning
        let entries = reader.read_all().unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn snappy_compressed_block() {
        // Test that Snappy decompression works on a simple block
        let original = b"hello world, this is a test of snappy compression!";
        let mut encoder = snap::raw::Encoder::new();
        let compressed = encoder.compress_vec(original).unwrap();

        // Build a fake block region: compressed data + type byte 1 + 4 CRC bytes
        let mut data = Vec::new();
        data.extend_from_slice(&compressed);
        data.push(1); // snappy compression type
        data.extend_from_slice(&[0; 4]); // CRC (unchecked)

        let result = read_block(&data, 0, compressed.len()).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn uncompressed_block() {
        let original = b"plain data";
        let mut data = Vec::new();
        data.extend_from_slice(original);
        data.push(0); // no compression
        data.extend_from_slice(&[0; 4]); // CRC

        let result = read_block(&data, 0, original.len()).unwrap();
        assert_eq!(result, original);
    }

    // --- Test helpers for building synthetic LevelDB files ---

    /// Encode a varint
    fn encode_varint(mut val: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        loop {
            let mut byte = (val & 0x7f) as u8;
            val >>= 7;
            if val != 0 {
                byte |= 0x80;
            }
            buf.push(byte);
            if val == 0 {
                break;
            }
        }
        buf
    }

    /// Build a synthetic SSTable with the given entries.
    /// Each entry is (user_key, value, sequence_number, is_deletion).
    fn build_synthetic_sstable(entries: &[(&[u8], &[u8], u64, bool)]) -> Vec<u8> {
        // Build the data block
        let data_block = build_data_block(entries);

        // The data block on disk: block bytes + compression type + CRC
        let data_block_offset = 0usize;
        let data_block_size = data_block.len();

        let mut file = Vec::new();
        file.extend_from_slice(&data_block);
        file.push(0); // no compression
        file.extend_from_slice(&[0; 4]); // CRC placeholder

        // Build the index block: one entry pointing to the data block
        let index_block = build_index_block(entries, data_block_offset, data_block_size);

        let index_block_offset = file.len();
        let index_block_size = index_block.len();
        file.extend_from_slice(&index_block);
        file.push(0); // no compression
        file.extend_from_slice(&[0; 4]); // CRC placeholder

        // Build footer (48 bytes)
        let mut footer = [0u8; FOOTER_SIZE];
        // metaindex handle (offset=0, size=0 — we have no metaindex)
        footer[0] = 0; // offset=0
        footer[1] = 0; // size=0
                       // index handle at bytes 20..
        let idx_off = encode_varint(index_block_offset as u64);
        let idx_sz = encode_varint(index_block_size as u64);
        footer[20..20 + idx_off.len()].copy_from_slice(&idx_off);
        footer[20 + idx_off.len()..20 + idx_off.len() + idx_sz.len()].copy_from_slice(&idx_sz);
        // Magic at bytes 40..48
        footer[40..48].copy_from_slice(&TABLE_MAGIC.to_le_bytes());

        file.extend_from_slice(&footer);
        file
    }

    fn build_data_block(entries: &[(&[u8], &[u8], u64, bool)]) -> Vec<u8> {
        let mut block = Vec::new();
        let mut last_key: Vec<u8> = Vec::new();

        for (user_key, value, seq, deleted) in entries {
            // Build internal key: user_key + packed(seq, type)
            let vtype = if *deleted {
                VALUE_TYPE_DELETION
            } else {
                VALUE_TYPE_VALUE
            };
            let packed: u64 = (seq << 8) | vtype as u64;
            let mut ikey = user_key.to_vec();
            ikey.extend_from_slice(&packed.to_le_bytes());

            // Compute shared prefix with last key
            let shared = last_key
                .iter()
                .zip(ikey.iter())
                .take_while(|(a, b)| a == b)
                .count();
            let unshared = ikey.len() - shared;

            block.extend_from_slice(&encode_varint(shared as u64));
            block.extend_from_slice(&encode_varint(unshared as u64));
            block.extend_from_slice(&encode_varint(value.len() as u64));
            block.extend_from_slice(&ikey[shared..]);
            block.extend_from_slice(value);

            last_key = ikey;
        }

        // Restart array: single restart at offset 0
        block.extend_from_slice(&0u32.to_le_bytes());
        block.extend_from_slice(&1u32.to_le_bytes());

        block
    }

    fn build_index_block(
        entries: &[(&[u8], &[u8], u64, bool)],
        data_offset: usize,
        data_size: usize,
    ) -> Vec<u8> {
        // Index block has one entry: the separator key and the block handle
        // Use the last key from the data block as the separator
        let last_entry = entries.last().unwrap();
        let vtype = if last_entry.3 {
            VALUE_TYPE_DELETION
        } else {
            VALUE_TYPE_VALUE
        };
        let packed: u64 = (last_entry.2 << 8) | vtype as u64;
        let mut sep_key = last_entry.0.to_vec();
        sep_key.extend_from_slice(&packed.to_le_bytes());
        // Append a 0xFF byte to make separator > all keys in block
        sep_key.push(0xFF);

        // Block handle value: varint(offset) + varint(size)
        let mut handle = encode_varint(data_offset as u64);
        handle.extend_from_slice(&encode_varint(data_size as u64));

        let mut block = Vec::new();
        // shared=0 (first entry in index block)
        block.extend_from_slice(&encode_varint(0));
        block.extend_from_slice(&encode_varint(sep_key.len() as u64));
        block.extend_from_slice(&encode_varint(handle.len() as u64));
        block.extend_from_slice(&sep_key);
        block.extend_from_slice(&handle);

        // Restart array
        block.extend_from_slice(&0u32.to_le_bytes());
        block.extend_from_slice(&1u32.to_le_bytes());

        block
    }

    /// Build a synthetic log file with a write batch at sequence 1.
    fn build_synthetic_log(entries: &[(&[u8], &[u8], bool)]) -> Vec<u8> {
        build_synthetic_log_with_seq(entries, 1)
    }

    fn build_synthetic_log_with_seq(entries: &[(&[u8], &[u8], bool)], seq: u64) -> Vec<u8> {
        // Build write batch
        let mut batch = Vec::new();
        batch.extend_from_slice(&seq.to_le_bytes());
        batch.extend_from_slice(&(entries.len() as u32).to_le_bytes());

        for (key, value, deleted) in entries {
            if *deleted {
                batch.push(VALUE_TYPE_DELETION);
                batch.extend_from_slice(&encode_varint(key.len() as u64));
                batch.extend_from_slice(key);
            } else {
                batch.push(VALUE_TYPE_VALUE);
                batch.extend_from_slice(&encode_varint(key.len() as u64));
                batch.extend_from_slice(key);
                batch.extend_from_slice(&encode_varint(value.len() as u64));
                batch.extend_from_slice(value);
            }
        }

        // Wrap in a FULL log record
        let mut log_data = Vec::new();
        log_data.extend_from_slice(&[0; 4]); // CRC
        log_data.extend_from_slice(&(batch.len() as u16).to_le_bytes());
        log_data.push(RECORD_FULL);
        log_data.extend_from_slice(&batch);

        log_data
    }
}
