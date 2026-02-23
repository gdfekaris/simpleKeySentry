//! Shannon entropy analysis for candidate secret strings.
//!
//! Entropy gauges randomness: a genuine secret has high entropy (close to the
//! theoretical maximum for its character set), while placeholders, version
//! strings, and documentation examples tend to have low entropy.
//!
//! Delta logic:
//! - entropy ≥ threshold for the classified character set → **+0.10**
//! - entropy <  threshold, or string too short, or unrecognised charset → **0.0**
//!
//! The entropy analyzer never *penalises* on its own; the `PlaceholderDetection`
//! and `VersionHashPattern` heuristics are better positioned to reduce
//! confidence for known non-secret patterns.

use super::EntropyAnalyzer;

// ---------------------------------------------------------------------------
// Thresholds and minimum lengths
// ---------------------------------------------------------------------------

/// Minimum entropy (bits/char) for a hex string to be considered high-entropy.
const HEX_THRESHOLD: f64 = 3.0;
/// Minimum string length for hex entropy analysis; shorter strings are skipped.
const HEX_MIN_LEN: usize = 32;

/// Minimum entropy (bits/char) for a base64 string to be considered high-entropy.
const BASE64_THRESHOLD: f64 = 4.5;
/// Minimum string length for base64 entropy analysis.
const BASE64_MIN_LEN: usize = 20;

/// Minimum entropy (bits/char) for an alphanumeric string to be considered high-entropy.
const ALPHANUM_THRESHOLD: f64 = 4.0;
/// Minimum string length for alphanumeric entropy analysis.
const ALPHANUM_MIN_LEN: usize = 16;

/// Strings longer than this use sliding-window analysis.
const WINDOW_THRESHOLD: usize = 100;
/// Width of the sliding window for long-string analysis.
const WINDOW_SIZE: usize = 64;

/// Confidence delta awarded when entropy meets or exceeds the threshold.
const HIGH_ENTROPY_DELTA: f64 = 0.10;

// ---------------------------------------------------------------------------
// Character set classification
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
enum CharSet {
    /// All characters are hex digits: `[0-9a-fA-F]`.
    Hex,
    /// Contains at least one base64-only character (`+`, `/`, `=`) and all
    /// characters are in the standard base64 alphabet.
    Base64,
    /// All characters are ASCII alphanumeric (`[A-Za-z0-9]`).
    Alphanumeric,
    /// Mixed or unsupported characters — entropy analysis is skipped.
    Other,
}

fn classify_charset(s: &str) -> CharSet {
    if s.is_empty() {
        return CharSet::Other;
    }
    if s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return CharSet::Hex;
    }
    let has_base64_special = s.bytes().any(|b| matches!(b, b'+' | b'/' | b'='));
    let all_base64 = s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
    if has_base64_special && all_base64 {
        return CharSet::Base64;
    }
    if s.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return CharSet::Alphanumeric;
    }
    CharSet::Other
}

// ---------------------------------------------------------------------------
// Entropy calculation
// ---------------------------------------------------------------------------

/// Computes Shannon entropy (bits per character) for a byte string.
///
/// Uses the standard formula: `H = −∑ p_i · log₂(p_i)` where `p_i` is the
/// proportion of byte value `i` in the string.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let len = s.len() as f64;
    let mut counts = [0u32; 256];
    for byte in s.bytes() {
        counts[byte as usize] += 1;
    }
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// For strings longer than `WINDOW_THRESHOLD`, compute the maximum entropy
/// over all `window_size`-byte sliding windows.
///
/// This catches high-entropy secrets embedded in longer, lower-entropy content
/// (e.g., a 40-char token appended to a URL or log line).
fn max_window_entropy(s: &str, window_size: usize) -> f64 {
    let bytes = s.as_bytes();
    if bytes.len() <= window_size {
        return shannon_entropy(s);
    }
    let mut max = 0.0_f64;
    for start in 0..=(bytes.len() - window_size) {
        // Secrets are ASCII-only; UTF-8 window boundaries should never fail.
        if let Ok(slice) = std::str::from_utf8(&bytes[start..start + window_size]) {
            let h = shannon_entropy(slice);
            if h > max {
                max = h;
            }
        }
    }
    max
}

// ---------------------------------------------------------------------------
// ShannonEntropyAnalyzer
// ---------------------------------------------------------------------------

/// Production entropy analyzer.
///
/// Classifies the candidate string's character set, applies the corresponding
/// minimum-length gate, and computes Shannon entropy (or max windowed entropy
/// for long strings). Returns `+0.10` when entropy meets the threshold, `0.0`
/// otherwise.
pub struct ShannonEntropyAnalyzer;

impl EntropyAnalyzer for ShannonEntropyAnalyzer {
    fn confidence_delta(&self, value: &str) -> f64 {
        let (threshold, min_len) = match classify_charset(value) {
            CharSet::Hex => (HEX_THRESHOLD, HEX_MIN_LEN),
            CharSet::Base64 => (BASE64_THRESHOLD, BASE64_MIN_LEN),
            CharSet::Alphanumeric => (ALPHANUM_THRESHOLD, ALPHANUM_MIN_LEN),
            CharSet::Other => return 0.0,
        };

        if value.len() < min_len {
            return 0.0;
        }

        let entropy = if value.len() > WINDOW_THRESHOLD {
            max_window_entropy(value, WINDOW_SIZE)
        } else {
            shannon_entropy(value)
        };

        if entropy >= threshold {
            HIGH_ENTROPY_DELTA
        } else {
            0.0
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Shannon entropy test vectors ---

    #[test]
    fn entropy_of_uniform_string_is_zero() {
        // Single repeated byte → only one symbol → H = 0.0
        assert!(shannon_entropy("aaaa").abs() < 1e-10);
        assert!(shannon_entropy("AAAAAAAAAAAAAAAA").abs() < 1e-10);
    }

    #[test]
    fn entropy_of_evenly_distributed_hex_is_four() {
        // 16 hex symbols each appearing exactly 4 times in a 64-char string → H = 4.0
        let s = "0123456789abcdef".repeat(4);
        assert_eq!(s.len(), 64);
        let h = shannon_entropy(&s);
        assert!((h - 4.0).abs() < 1e-9, "expected 4.0, got {h}");
    }

    #[test]
    fn entropy_of_two_symbol_string_is_one() {
        // 50/50 split of two symbols → H = 1.0
        let s = "ab".repeat(16); // 32 chars
        let h = shannon_entropy(&s);
        assert!((h - 1.0).abs() < 1e-10, "expected 1.0, got {h}");
    }

    #[test]
    fn entropy_of_empty_string_is_zero() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    // --- Character set classification ---

    #[test]
    fn classify_lowercase_hex() {
        assert_eq!(classify_charset("deadbeef0123456789abcdef"), CharSet::Hex);
    }

    #[test]
    fn classify_uppercase_hex() {
        assert_eq!(classify_charset("DEADBEEF0123456789ABCDEF"), CharSet::Hex);
    }

    #[test]
    fn classify_base64_with_special_chars() {
        assert_eq!(classify_charset("SGVsbG8gV29ybGQ="), CharSet::Base64);
        assert_eq!(classify_charset("abc+def/ghi="), CharSet::Base64);
    }

    #[test]
    fn classify_pure_alphanumeric() {
        assert_eq!(
            classify_charset("AKIAIOSFODNN7EXAMPLE"),
            CharSet::Alphanumeric
        );
        assert_eq!(classify_charset("AbCd1234EfGhIjKl"), CharSet::Alphanumeric);
    }

    #[test]
    fn classify_string_with_underscore_is_other() {
        assert_eq!(classify_charset("SECRET_KEY"), CharSet::Other);
        assert_eq!(classify_charset("hello_world_123"), CharSet::Other);
    }

    #[test]
    fn classify_empty_string_is_other() {
        assert_eq!(classify_charset(""), CharSet::Other);
    }

    // --- Minimum length gates ---

    #[test]
    fn short_hex_below_min_len_returns_zero() {
        let analyzer = ShannonEntropyAnalyzer;
        // 31 chars of hex → below HEX_MIN_LEN (32) → skipped
        let s = "0123456789abcdef0123456789abcde"; // 31 chars
        assert_eq!(s.len(), 31);
        assert_eq!(analyzer.confidence_delta(s), 0.0);
    }

    #[test]
    fn short_alphanumeric_below_min_len_returns_zero() {
        let analyzer = ShannonEntropyAnalyzer;
        // 15 chars → below ALPHANUM_MIN_LEN (16) → skipped
        assert_eq!(analyzer.confidence_delta("AbCdEfGhIjKlMnO"), 0.0);
    }

    // --- Delta: high entropy ---

    #[test]
    fn high_entropy_hex_returns_positive_delta() {
        let analyzer = ShannonEntropyAnalyzer;
        // 64-char hex, all 16 symbols distributed evenly → H = 4.0 ≥ HEX_THRESHOLD 3.0
        let s = "0123456789abcdef".repeat(4);
        assert_eq!(analyzer.confidence_delta(&s), 0.10);
    }

    #[test]
    fn high_entropy_alphanumeric_returns_positive_delta() {
        let analyzer = ShannonEntropyAnalyzer;
        // 20 completely unique uppercase chars → H = log2(20) ≈ 4.32 ≥ ALPHANUM_THRESHOLD 4.0
        assert_eq!(analyzer.confidence_delta("ABCDEFGHIJKLMNOPQRST"), 0.10);
    }

    // --- Delta: low entropy ---

    #[test]
    fn low_entropy_long_hex_returns_zero() {
        let analyzer = ShannonEntropyAnalyzer;
        // All-same character → H = 0.0 < HEX_THRESHOLD 3.0
        let s = "a".repeat(40);
        assert_eq!(analyzer.confidence_delta(&s), 0.0);
    }

    #[test]
    fn low_entropy_alphanumeric_aws_example_returns_zero() {
        let analyzer = ShannonEntropyAnalyzer;
        // "AKIAIOSFODNN7EXAMPLE" has entropy ≈ 3.69, below ALPHANUM_THRESHOLD 4.0
        assert_eq!(analyzer.confidence_delta("AKIAIOSFODNN7EXAMPLE"), 0.0);
    }

    // --- Other character class ---

    #[test]
    fn string_with_special_chars_returns_zero() {
        let analyzer = ShannonEntropyAnalyzer;
        assert_eq!(analyzer.confidence_delta("SECRET_KEY_123456"), 0.0);
        assert_eq!(analyzer.confidence_delta("value with spaces"), 0.0);
    }

    // --- Windowed analysis ---

    #[test]
    fn windowed_analysis_finds_high_entropy_segment_in_long_string() {
        let analyzer = ShannonEntropyAnalyzer;
        // First 50 chars: all 'A' (low entropy).
        // Next 64 chars: 26 uppercase + 26 lowercase + 12 digits = near-maximum entropy.
        let low_part = "A".repeat(50);
        let high_part = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789AB";
        assert_eq!(high_part.len(), 64);
        let value = format!("{low_part}{high_part}");
        assert!(value.len() > WINDOW_THRESHOLD);
        // The window anchored at position 50 has H ≈ 5.94 >> ALPHANUM_THRESHOLD 4.0
        assert_eq!(analyzer.confidence_delta(&value), 0.10);
    }
}
