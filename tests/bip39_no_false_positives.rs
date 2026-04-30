//! Acceptance test for the BIP-39 mnemonic pattern's false-positive rate.
//!
//! The pattern's regex first-pass deliberately matches any run of 12–24
//! lowercase ASCII tokens — that's a shape that occurs constantly in
//! ordinary English prose. The validator (BIP-39 wordlist membership +
//! checksum verification) is what makes the detection useful in practice.
//! This test runs the full match → validator pipeline over a sizeable
//! public-domain English prose fixture and asserts zero end-to-end
//! matches.
//!
//! Fixture: opening chapters of Moby Dick (Herman Melville, 1851),
//! Project Gutenberg eBook #2701, public domain. The fixture is trimmed
//! to ~150 KB — large enough to span thousands of long lowercase runs
//! that exercise the regex first-pass, while keeping the repo lean.

use simple_key_sentry::detection::patterns::all_patterns;
use simple_key_sentry::detection::CompiledPattern;
use std::path::PathBuf;

fn prose_fixture() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/prose.txt");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Missing prose fixture at {}: {}", path.display(), e))
}

#[test]
fn bip39_pattern_finds_no_false_positives_in_english_prose() {
    let prose = prose_fixture();
    assert!(
        prose.len() >= 100_000,
        "prose fixture must be at least 100 KB; got {} bytes",
        prose.len()
    );

    let rule = all_patterns()
        .into_iter()
        .find(|r| r.name == "bitcoin-bip39-mnemonic")
        .expect("bitcoin-bip39-mnemonic pattern not found");
    let compiled = CompiledPattern::compile(rule).expect("pattern must compile");
    let validator = compiled
        .rule
        .validator
        .expect("bitcoin-bip39-mnemonic must carry a validator");

    let mut matches = Vec::new();
    for (lineno, line) in prose.lines().enumerate() {
        if let Some(captures) = compiled.regex.captures(line) {
            let value = captures
                .get(1)
                .or_else(|| captures.get(0))
                .map(|m| m.as_str())
                .unwrap_or("");
            if !value.is_empty() && validator(value) {
                matches.push((lineno + 1, value.to_string()));
            }
        }
    }

    assert!(
        matches.is_empty(),
        "expected zero BIP-39 false positives in {} bytes of prose, got {}: {:?}",
        prose.len(),
        matches.len(),
        matches.iter().take(5).collect::<Vec<_>>()
    );
}
