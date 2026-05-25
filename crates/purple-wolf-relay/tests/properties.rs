//! Property-based invariants for the relay's core data types.
//!
//! - `parser::parse_line` is total — never panics on arbitrary bytes.
//! - `Envelope` JSON round-trips losslessly.
//! - `Signer::sign` changes iff timestamp or body changes.
//! - `CompiledFilter` is monotonic under label additions: if an
//!   envelope `E` matches a filter that requires only some labels,
//!   adding more labels to `E` can never cause the match to fail.

use std::collections::BTreeMap;

use proptest::prelude::*;
use purple_wolf_relay::config::{Severity, SubscriberFilter};
use purple_wolf_relay::envelope::{Envelope, EnvelopeSource};
use purple_wolf_relay::parser::parse_line;
use purple_wolf_relay::signer::Signer;
use purple_wolf_relay::subscribers::filter::CompiledFilter;

proptest! {
    #[test]
    fn parser_is_total_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        // Must not panic, irrespective of result.
        let _ = parse_line(&bytes);
    }

    #[test]
    fn parser_is_total_on_arbitrary_utf8(s in ".{0,4096}") {
        let _ = parse_line(s.as_bytes());
    }

    #[test]
    fn signer_changes_with_timestamp(
        secret in proptest::collection::vec(any::<u8>(), 1..64),
        body in proptest::collection::vec(any::<u8>(), 0..256),
        a in any::<u64>(),
        b in any::<u64>(),
    ) {
        prop_assume!(a != b);
        let s = Signer::new(secret);
        prop_assert_ne!(s.sign(a, &body), s.sign(b, &body));
    }

    #[test]
    fn signer_changes_with_body(
        secret in proptest::collection::vec(any::<u8>(), 1..64),
        ts in any::<u64>(),
        body_a in proptest::collection::vec(any::<u8>(), 0..256),
        body_b in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        prop_assume!(body_a != body_b);
        let s = Signer::new(secret);
        prop_assert_ne!(s.sign(ts, &body_a), s.sign(ts, &body_b));
    }

    #[test]
    fn signer_deterministic_for_same_inputs(
        secret in proptest::collection::vec(any::<u8>(), 1..64),
        ts in any::<u64>(),
        body in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let s = Signer::new(secret);
        prop_assert_eq!(s.sign(ts, &body), s.sign(ts, &body));
    }

    /// Monotonicity: if a filter matches an envelope, adding more
    /// labels to the envelope must not unmatch it. The labels clause
    /// only requires a subset, so any superset is also a match.
    #[test]
    fn filter_match_is_monotonic_in_labels(
        base_labels in proptest::collection::btree_map("[a-z]{1,8}", "[a-z]{1,8}", 0..6),
        extra_labels in proptest::collection::btree_map("[a-z]{1,8}", "[a-z]{1,8}", 0..6),
    ) {
        let filter = SubscriberFilter {
            labels: base_labels.clone(),
            severity_min: None,
            blocked_rule_pattern: None,
        };
        let compiled = CompiledFilter::compile(&filter);

        // env1: exactly the labels the filter requires.
        let env1 = Envelope::new(
            serde_json::json!({}),
            EnvelopeSource { middleware: None, router: None, entry_point: None, relay_instance: "r".into() },
            base_labels.clone(),
        );
        prop_assert!(compiled.matches(&env1));

        // env2: same labels + extras. Must still match.
        let mut merged = base_labels.clone();
        for (k, v) in extra_labels {
            // Don't shadow the operator-set keys — the filter would
            // then fail because the value differs.
            merged.entry(k).or_insert(v);
        }
        let env2 = Envelope::new(
            serde_json::json!({}),
            EnvelopeSource { middleware: None, router: None, entry_point: None, relay_instance: "r".into() },
            merged,
        );
        prop_assert!(compiled.matches(&env2));
    }

    /// Envelope JSON round-trip: parse(serialize(E)) == E for the
    /// subset of fields the relay cares about. The full struct
    /// includes timestamps + ULIDs which are stable across the
    /// round trip.
    #[test]
    fn envelope_round_trip_preserves_event_and_labels(
        labels in proptest::collection::btree_map("[a-z]{1,8}", "[a-z]{1,16}", 0..6),
        action in prop_oneof!["block", "allow"].prop_map(String::from),
    ) {
        let env = Envelope::new(
            serde_json::json!({"action": action, "would_block_rules": []}),
            EnvelopeSource {
                middleware: Some("strict".into()),
                router: Some("checkout".into()),
                entry_point: Some("web".into()),
                relay_instance: "r-1".into(),
            },
            labels.clone(),
        );
        let json = serde_json::to_string(&env).unwrap();
        let decoded: Envelope = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(&decoded.schema, &env.schema);
        prop_assert_eq!(&decoded.event_id, &env.event_id);
        prop_assert_eq!(&decoded.delivery_id, &env.delivery_id);
        prop_assert_eq!(&decoded.labels, &env.labels);
        prop_assert_eq!(&decoded.event["action"], &env.event["action"]);
    }

    /// Tighter severity floors should never *expand* the match set:
    /// if an envelope matches at floor `high`, raising the floor to
    /// `critical` may or may not match, but lowering to `medium`
    /// must still match (modulo the underlying severity).
    #[test]
    fn raising_severity_floor_never_adds_matches(
        sev_str in prop_oneof!["low", "medium", "high", "critical"].prop_map(String::from),
    ) {
        let env = Envelope::new(
            serde_json::json!({
                "action": "block",
                "blocked_rule": "injection/sqli",
                "blocked_severity": sev_str,
                "would_block_rules": []
            }),
            EnvelopeSource { middleware: None, router: None, entry_point: None, relay_instance: "r".into() },
            BTreeMap::new(),
        );
        let f_low = CompiledFilter::compile(&SubscriberFilter {
            severity_min: Some(Severity::Low), ..Default::default()
        });
        let f_high = CompiledFilter::compile(&SubscriberFilter {
            severity_min: Some(Severity::High), ..Default::default()
        });
        // If high matches, low must match too (tighter ⊆ looser).
        prop_assert!(!f_high.matches(&env) || f_low.matches(&env));
    }
}
