//! HMAC-SHA256 webhook body signer.
//!
//! Signs `<timestamp_secs>.<body_bytes>` per `docs/webhook-protocol.md`.
//! The timestamp is part of the signed payload (anti-replay) so each
//! retry attempt re-signs with a fresh timestamp.
//!
//! Secret is wrapped in `zeroize::Zeroizing<Vec<u8>>` so it's wiped
//! from memory when the Signer is dropped — config-reload + secret
//! rotation paths benefit from this.

use hmac::{Hmac, Mac};
use sha2::Sha256;

pub struct Signer {
    secret: zeroize::Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret — only its length, so logs are useful
        // for diagnosing "did I forget to set the secret?" without
        // leaking material.
        f.debug_struct("Signer")
            .field("secret_len", &self.secret.len())
            .finish()
    }
}

impl Signer {
    pub fn new(secret: impl Into<Vec<u8>>) -> Self {
        Self {
            secret: zeroize::Zeroizing::new(secret.into()),
        }
    }

    /// Compute the `X-PurpleWolf-Signature` header value for a given
    /// timestamp + body. The header format is `sha256=<hex>` per the
    /// protocol spec; lowercase hex so cross-language constant-time
    /// compares are unambiguous.
    pub fn sign(&self, timestamp_secs: u64, body: &[u8]) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.secret)
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(format!("{timestamp_secs}.").as_bytes());
        mac.update(body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-check the signature against a hand-rolled HMAC computation
    /// (independent code path inside this test) — guards against an
    /// accidental change to the input-format string.
    #[test]
    fn signature_matches_independent_implementation() {
        let secret = b"hello";
        let ts = 1748194202u64;
        let body = b"body-bytes";
        let s = Signer::new(secret.to_vec());
        let got = s.sign(ts, body);

        // Recompute from scratch using the same input concatenation
        // the spec mandates.
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).unwrap();
        mac.update(format!("{ts}.").as_bytes());
        mac.update(body);
        let expected = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));

        assert_eq!(got, expected);
        assert!(got.starts_with("sha256="));
        // SHA-256 → 32 bytes → 64 hex chars + "sha256=" prefix.
        assert_eq!(got.len(), 7 + 64);
    }

    #[test]
    fn signature_changes_if_timestamp_changes() {
        let s = Signer::new(b"secret".to_vec());
        let body = b"same-body";
        let a = s.sign(1, body);
        let b = s.sign(2, body);
        assert_ne!(a, b, "timestamp must affect signature (anti-replay)");
    }

    #[test]
    fn signature_changes_if_body_changes() {
        let s = Signer::new(b"secret".to_vec());
        let ts = 100u64;
        assert_ne!(s.sign(ts, b"a"), s.sign(ts, b"b"));
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let s = Signer::new(b"my-very-secret-key".to_vec());
        let debug = format!("{s:?}");
        assert!(!debug.contains("my-very-secret-key"), "{debug}");
        assert!(debug.contains("secret_len"));
    }

    /// Independent reference computation, derived in-test so the
    /// assertion can never silently drift from the implementation —
    /// a refactor of sign() that changes the payload concatenation
    /// will fail this test even if the property tests above still
    /// pass.
    #[test]
    fn reference_payload_format_is_timestamp_dot_body() {
        let secret = b"test-secret";
        let ts = 1700000000u64;
        let body = br#"{"schema":"purple-wolf.audit/v1"}"#;

        let s = Signer::new(secret.to_vec());
        let got = s.sign(ts, body);

        // Build the exact payload `<ts>.<body>` and HMAC it.
        let mut payload = format!("{ts}.").into_bytes();
        payload.extend_from_slice(body);
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).unwrap();
        mac.update(&payload);
        let expected = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        assert_eq!(got, expected);
    }
}
