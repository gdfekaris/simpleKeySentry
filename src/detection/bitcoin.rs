//! Bitcoin-specific validation primitives.
//!
//! This module hosts the building blocks used by Bitcoin pattern validators.
//! Block A ships the base58check decoder, which is enough to validate
//! extended private keys (`xprv`/`yprv`/`zprv`/`tprv`) and WIF private keys
//! at the format level. BIP-39 mnemonic validation will land here in
//! Block C.
//!
//! All routines are pure functions: no I/O, no global state, no panics on
//! adversarial input. Allocations are short-lived and proportional to input
//! size.

use sha2::{Digest, Sha256};

/// Bitcoin's base58 alphabet. Visually ambiguous characters (`0`, `O`, `I`,
/// `l`) are deliberately omitted so handwritten copies are less error-prone.
const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Decode a Base58Check-encoded string and verify its 4-byte trailing
/// checksum.
///
/// On success, returns the decoded payload **with the checksum stripped**.
/// Returns `None` for any of:
///
/// - empty input
/// - a character outside the base58 alphabet (notably `0`, `O`, `I`, `l`)
/// - decoded bytes shorter than 4 (no room for a checksum)
/// - `SHA-256(SHA-256(payload))[..4]` does not match the trailing 4 bytes
///
/// This is a strict, format-agnostic decoder. Callers are responsible for
/// further validation (expected payload length, version byte, key shape).
pub fn base58check_decode(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() {
        return None;
    }

    let bytes = s.as_bytes();

    // Each leading '1' encodes a leading 0x00 byte in the output and is
    // skipped over by the big-int decode loop.
    let leading_ones = bytes.iter().take_while(|&&b| b == b'1').count();

    // Big-endian big-integer accumulator. Each base58 digit multiplies the
    // running value by 58 and adds the digit; carries propagate from the
    // least-significant byte upward, with new high bytes inserted at the
    // front when needed.
    let mut num: Vec<u8> = Vec::with_capacity(bytes.len());
    for &c in &bytes[leading_ones..] {
        let digit = ALPHABET.iter().position(|&a| a == c)? as u32;
        let mut carry = digit;
        for byte in num.iter_mut().rev() {
            let v = u32::from(*byte) * 58 + carry;
            *byte = (v & 0xFF) as u8;
            carry = v >> 8;
        }
        while carry > 0 {
            num.insert(0, (carry & 0xFF) as u8);
            carry >>= 8;
        }
    }

    // Final byte string: leading_ones zero bytes followed by the big-int.
    let mut decoded = Vec::with_capacity(leading_ones + num.len());
    decoded.resize(leading_ones, 0u8);
    decoded.extend_from_slice(&num);

    if decoded.len() < 4 {
        return None;
    }
    let split = decoded.len() - 4;
    let payload = &decoded[..split];
    let checksum = &decoded[split..];

    let hash1 = Sha256::digest(payload);
    let hash2 = Sha256::digest(hash1);
    if &hash2[..4] != checksum {
        return None;
    }

    Some(payload.to_vec())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP-32 test vector 1, master extended private key. The decoded
    /// payload is exactly 78 bytes: 4-byte version (`0x0488ADE4` = mainnet
    /// xprv), 1-byte depth, 4-byte parent fingerprint, 4-byte child number,
    /// 32-byte chain code, then `0x00` followed by the 32-byte private key.
    const BIP32_TEST_XPRV: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

    /// Canonical mainnet uncompressed WIF test vector (Bitcoin wiki).
    /// Payload is 33 bytes: 1-byte version (`0x80`) + 32-byte private key.
    const WIF_UNCOMPRESSED: &str = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";

    /// Canonical mainnet compressed WIF test vector. Payload is 34 bytes:
    /// 1-byte version (`0x80`) + 32-byte private key + 1-byte compression
    /// flag (`0x01`).
    const WIF_COMPRESSED: &str = "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617";

    #[test]
    fn decode_bip32_xprv_yields_78_byte_payload() {
        let decoded = base58check_decode(BIP32_TEST_XPRV).expect("xprv must decode");
        assert_eq!(decoded.len(), 78, "BIP-32 xprv payload is 78 bytes");
        assert_eq!(
            &decoded[..4],
            &[0x04, 0x88, 0xAD, 0xE4],
            "mainnet xprv version bytes"
        );
    }

    #[test]
    fn decode_wif_uncompressed_yields_33_byte_payload() {
        let decoded = base58check_decode(WIF_UNCOMPRESSED).expect("WIF must decode");
        assert_eq!(decoded.len(), 33);
        assert_eq!(decoded[0], 0x80, "mainnet WIF version byte");
    }

    #[test]
    fn decode_wif_compressed_yields_34_byte_payload() {
        let decoded = base58check_decode(WIF_COMPRESSED).expect("WIF must decode");
        assert_eq!(decoded.len(), 34);
        assert_eq!(decoded[0], 0x80, "mainnet WIF version byte");
        assert_eq!(decoded[33], 0x01, "compression flag");
    }

    #[test]
    fn tampered_xprv_checksum_returns_none() {
        // Swap the final char to a different valid base58 digit. The checksum
        // collision probability is ~1/2^32, so this is reliably negative.
        let mut bad = BIP32_TEST_XPRV.to_string();
        let last = bad.pop().unwrap();
        let replacement = if last == 'i' { 'j' } else { 'i' };
        bad.push(replacement);
        assert!(base58check_decode(&bad).is_none());
    }

    #[test]
    fn tampered_wif_checksum_returns_none() {
        let mut bad = WIF_UNCOMPRESSED.to_string();
        let last = bad.pop().unwrap();
        let replacement = if last == 'J' { 'K' } else { 'J' };
        bad.push(replacement);
        assert!(base58check_decode(&bad).is_none());
    }

    #[test]
    fn invalid_alphabet_chars_return_none() {
        // '0', 'O', 'I', 'l' are explicitly excluded from base58.
        assert!(base58check_decode("0OIl").is_none());
        // Real-shape xprv with one banned char mid-string.
        let banned_in_middle = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPP0jiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        assert!(base58check_decode(banned_in_middle).is_none());
    }

    #[test]
    fn empty_string_returns_none() {
        assert!(base58check_decode("").is_none());
    }

    #[test]
    fn too_short_returns_none() {
        // Three valid base58 chars decode to fewer than 4 bytes — there is
        // no room for a 4-byte checksum.
        assert!(base58check_decode("abc").is_none());
    }

    #[test]
    fn single_char_returns_none() {
        // '1' alone decodes to a single 0x00 byte — too short for checksum.
        assert!(base58check_decode("1").is_none());
    }

    /// Well-known mainnet P2PKH address (the "Bitcoin Eater" address). The
    /// leading `1` encodes the `0x00` version byte; the full payload is 21
    /// bytes (1-byte version + 20-byte HASH160).
    #[test]
    fn leading_one_encodes_zero_version_byte() {
        let decoded =
            base58check_decode("1BoatSLRHtKNngkdXEeobR76b53LETtpyT").expect("P2PKH must decode");
        assert_eq!(decoded.len(), 21);
        assert_eq!(decoded[0], 0x00, "leading '1' encodes 0x00 version byte");
    }
}
