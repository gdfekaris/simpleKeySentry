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
// Extended private key (BIP-32 / SLIP-132) validation
// ---------------------------------------------------------------------------

/// SLIP-132 version bytes for the extended private keys we recognise. The
/// regex first-pass restricts matches to `xprv`/`yprv`/`zprv`/`tprv` prefixes;
/// these are the corresponding 4-byte version words at offset 0 of the
/// decoded 78-byte payload.
const XPRV_VERSIONS: &[[u8; 4]] = &[
    [0x04, 0x88, 0xAD, 0xE4], // xprv  — BIP-44 mainnet
    [0x04, 0x9D, 0x78, 0x78], // yprv  — BIP-49 mainnet (P2WPKH-in-P2SH)
    [0x04, 0xB2, 0x43, 0x0C], // zprv  — BIP-84 mainnet (native segwit)
    [0x04, 0x35, 0x83, 0x94], // tprv  — BIP-32 testnet
];

/// Validate an extended private key string.
///
/// Accepts only inputs whose decoded payload is the canonical 78-byte BIP-32
/// extended-key serialisation, whose version bytes are one of
/// `xprv`/`yprv`/`zprv`/`tprv`, and whose private-key sub-field starts with
/// the required `0x00` padding byte.
///
/// The base58check decoder enforces the trailing 4-byte SHA-256d checksum, so
/// random 111-character base58 strings starting with `xprv` etc. are rejected
/// at a rate of ~1 − 1/2^32.
pub fn validate_xprv(s: &str) -> bool {
    let Some(payload) = base58check_decode(s) else {
        return false;
    };
    if payload.len() != 78 {
        return false;
    }
    let version: [u8; 4] = payload[..4].try_into().expect("4-byte slice");
    if !XPRV_VERSIONS.contains(&version) {
        return false;
    }
    // Bytes [45..78] are the 33-byte private-key field. For a private xkey
    // it must begin with 0x00 followed by the 32-byte scalar; this 0x00
    // padding is what distinguishes an xprv payload from an xpub payload at
    // the byte level.
    payload[45] == 0x00
}

// ---------------------------------------------------------------------------
// WIF (Wallet Import Format) validation
// ---------------------------------------------------------------------------

/// Mainnet WIF version byte. The pattern regex restricts the leading
/// character to `5`/`K`/`L`, which only encode mainnet keys, so testnet
/// (`0xEF`, leading `9`/`c`) is intentionally not accepted here.
const WIF_VERSION_MAINNET: u8 = 0x80;

/// Validate a WIF private-key string.
///
/// Accepts:
/// - Uncompressed mainnet WIF: 33-byte payload `0x80 || 32-byte key`,
///   encoding to a 51-character string starting with `5`.
/// - Compressed mainnet WIF: 34-byte payload `0x80 || 32-byte key || 0x01`,
///   encoding to a 52-character string starting with `K` or `L`.
///
/// The base58check decoder verifies the checksum; this routine adds the
/// version-byte and shape checks.
pub fn validate_wif(s: &str) -> bool {
    let Some(payload) = base58check_decode(s) else {
        return false;
    };
    if payload[0] != WIF_VERSION_MAINNET {
        return false;
    }
    match payload.len() {
        33 => true,                // uncompressed
        34 => payload[33] == 0x01, // compressed: trailing flag must be 0x01
        _ => false,
    }
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

    // -----------------------------------------------------------------
    // Test helper: base58check encoder.
    //
    // Used to synthesize valid yprv/zprv/tprv strings from the known-good
    // 78-byte BIP-32 payload by swapping just the 4-byte version prefix
    // and recomputing the checksum. This keeps test vector coverage
    // self-contained — we don't rely on memorising every SLIP-132 vector.
    // -----------------------------------------------------------------
    fn base58check_encode(input: &[u8]) -> String {
        let hash1 = Sha256::digest(input);
        let hash2 = Sha256::digest(hash1);
        let mut full: Vec<u8> = input.to_vec();
        full.extend_from_slice(&hash2[..4]);

        let leading_zeros = full.iter().take_while(|&&b| b == 0).count();

        let mut num = full[leading_zeros..].to_vec();
        let mut digits: Vec<u8> = Vec::new();
        while !num.is_empty() {
            let mut remainder: u32 = 0;
            let mut quotient: Vec<u8> = Vec::with_capacity(num.len());
            let mut started = false;
            for &b in &num {
                let v = (remainder << 8) | u32::from(b);
                let q = (v / 58) as u8;
                remainder = v % 58;
                if started || q != 0 {
                    quotient.push(q);
                    started = true;
                }
            }
            digits.push(ALPHABET[remainder as usize]);
            num = quotient;
        }
        digits.resize(digits.len() + leading_zeros, b'1');
        digits.reverse();
        String::from_utf8(digits).expect("base58 alphabet is ASCII")
    }

    #[test]
    fn encoder_roundtrips_through_decoder() {
        let payload = base58check_decode(BIP32_TEST_XPRV).expect("decode");
        let reencoded = base58check_encode(&payload);
        assert_eq!(reencoded, BIP32_TEST_XPRV);
    }

    /// Build a valid extended private key string with the given version
    /// prefix, reusing the known-good BIP-32 test xprv payload for the rest
    /// of the bytes.
    fn synth_xprv(version: [u8; 4]) -> String {
        let mut payload = base58check_decode(BIP32_TEST_XPRV).expect("decode");
        payload[..4].copy_from_slice(&version);
        base58check_encode(&payload)
    }

    // ----- validate_xprv -----

    #[test]
    fn validate_xprv_accepts_canonical_mainnet_xprv() {
        assert!(validate_xprv(BIP32_TEST_XPRV));
    }

    #[test]
    fn validate_xprv_accepts_yprv_zprv_tprv_versions() {
        assert!(validate_xprv(&synth_xprv([0x04, 0x9D, 0x78, 0x78])), "yprv");
        assert!(validate_xprv(&synth_xprv([0x04, 0xB2, 0x43, 0x0C])), "zprv");
        assert!(validate_xprv(&synth_xprv([0x04, 0x35, 0x83, 0x94])), "tprv");
    }

    #[test]
    fn validate_xprv_rejects_unknown_version_bytes() {
        // xpub mainnet version (0x0488B21E) — same shape, wrong type.
        assert!(!validate_xprv(&synth_xprv([0x04, 0x88, 0xB2, 0x1E])));
    }

    #[test]
    fn validate_xprv_rejects_bad_checksum() {
        let mut bad = BIP32_TEST_XPRV.to_string();
        let last = bad.pop().unwrap();
        bad.push(if last == 'i' { 'j' } else { 'i' });
        assert!(!validate_xprv(&bad));
    }

    #[test]
    fn validate_xprv_rejects_xpub_shape_payload() {
        // Take a valid xprv payload, swap the private-key prefix byte 45
        // from 0x00 (private) to 0x02 (compressed pubkey shape), and
        // re-encode. The result is checksum-valid but fails the structural
        // check for an extended *private* key.
        let mut payload = base58check_decode(BIP32_TEST_XPRV).expect("decode");
        payload[45] = 0x02;
        let pubkey_shaped = base58check_encode(&payload);
        assert!(!validate_xprv(&pubkey_shaped));
    }

    #[test]
    fn validate_xprv_rejects_wrong_length_payload() {
        // A WIF is checksum-valid base58check but only 33 bytes long.
        assert!(!validate_xprv(WIF_UNCOMPRESSED));
    }

    #[test]
    fn validate_xprv_rejects_empty_string() {
        assert!(!validate_xprv(""));
    }

    // ----- validate_wif -----

    #[test]
    fn validate_wif_accepts_uncompressed_mainnet() {
        assert!(validate_wif(WIF_UNCOMPRESSED));
    }

    #[test]
    fn validate_wif_accepts_compressed_mainnet() {
        assert!(validate_wif(WIF_COMPRESSED));
    }

    #[test]
    fn validate_wif_rejects_bad_checksum() {
        let mut bad = WIF_UNCOMPRESSED.to_string();
        let last = bad.pop().unwrap();
        bad.push(if last == 'J' { 'K' } else { 'J' });
        assert!(!validate_wif(&bad));
    }

    #[test]
    fn validate_wif_rejects_testnet_version_byte() {
        // Re-encode the WIF with the testnet version byte 0xEF.
        let mut payload = base58check_decode(WIF_UNCOMPRESSED).expect("decode");
        payload[0] = 0xEF;
        let testnet_wif = base58check_encode(&payload);
        assert!(!validate_wif(&testnet_wif));
    }

    #[test]
    fn validate_wif_rejects_compressed_with_bad_flag() {
        // Re-encode the compressed WIF with a non-0x01 trailing byte.
        let mut payload = base58check_decode(WIF_COMPRESSED).expect("decode");
        payload[33] = 0x00;
        let bad_flag = base58check_encode(&payload);
        assert!(!validate_wif(&bad_flag));
    }

    #[test]
    fn validate_wif_rejects_xprv_payload() {
        // Different secret format, valid checksum, wrong shape.
        assert!(!validate_wif(BIP32_TEST_XPRV));
    }

    #[test]
    fn validate_wif_rejects_empty_string() {
        assert!(!validate_wif(""));
    }
}
