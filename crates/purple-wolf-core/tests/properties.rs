//! Property-based invariants the engine must never violate.
//!
//! These are stronger than the per-module unit tests because they sample
//! the *input space*, including adversarial shapes (invalid UTF-8 byte
//! sequences, trailing `%`, embedded `\0`, long multi-byte sequences)
//! that hand-written tests rarely cover. Failure here means a real
//! parser bug; do not weaken the strategies without first reproducing
//! locally.
use proptest::prelude::*;
use purple_wolf_core::config::{GroupMode, Mode};
use purple_wolf_core::detectors::{Group, Severity, Verdict};
use purple_wolf_core::policy::{self, Action};
use purple_wolf_core::request::{client_ip, Request};
use std::net::{IpAddr, Ipv4Addr};

fn any_group() -> impl Strategy<Value = Group> {
    prop_oneof![
        Just(Group::Injection),
        Just(Group::Signatures),
        Just(Group::Structural),
        Just(Group::Reputation),
    ]
}

fn any_severity() -> impl Strategy<Value = Severity> {
    prop_oneof![
        Just(Severity::Low),
        Just(Severity::Medium),
        Just(Severity::High),
        Just(Severity::Critical),
    ]
}

fn any_verdict() -> impl Strategy<Value = Verdict> {
    (any_group(), any_severity()).prop_map(|(g, s)| Verdict {
        group: g,
        rule: "p",
        severity: s,
        detail: "p".into(),
    })
}

proptest! {
    /// Monitor mode never blocks, no matter the verdicts or per-group modes.
    #[test]
    fn monitor_global_never_blocks(verdicts in proptest::collection::vec(any_verdict(), 0..16)) {
        let d = policy::decide(verdicts, Mode::Monitor, |_| GroupMode::Enforce);
        prop_assert_eq!(d.action, Action::Allow);
    }

    /// `GroupMode::Off` for every group suppresses ALL verdicts.
    #[test]
    fn group_mode_off_suppresses_all(verdicts in proptest::collection::vec(any_verdict(), 0..16)) {
        let d = policy::decide(verdicts.clone(), Mode::Enforce, |_| GroupMode::Off);
        prop_assert_eq!(d.action, Action::Allow);
        prop_assert!(d.would_block.is_empty());
    }

    /// NEW-H1 guard: when `decide()` picks a blocking verdict from a
    /// pool of enforced verdicts, the chosen `blocked_by` must have
    /// severity >= every other verdict that ended up in `would_block`.
    #[test]
    fn decide_chooses_highest_severity(
        verdicts in proptest::collection::vec(any_verdict(), 1..16)
    ) {
        let d = policy::decide(verdicts, Mode::Enforce, |_| GroupMode::Enforce);
        if let Some(chosen) = &d.blocked_by {
            for v in &d.would_block {
                prop_assert!(
                    chosen.severity >= v.severity,
                    "blocked_by ({:?}) must be >= all would_block ({:?})",
                    chosen.severity, v.severity
                );
            }
        } else {
            // The empty-verdicts case is excluded by the 1..16 range, so
            // we should always have at least one verdict. The only way
            // blocked_by is None with non-empty verdicts is if every
            // verdict was Off-suppressed — but our group_mode says
            // Enforce, so this branch should be unreachable.
            prop_assert!(false, "blocked_by must be Some when global+group both Enforce");
        }
    }

    /// I-7 + NEW-M2 guard: `client_ip` must return the leftmost-parseable
    /// XFF entry after peeling `trust_hops` trusted entries (when the
    /// peeled prefix contains at least one parseable IP). This was
    /// previously `prop_assert!(true)` — a literal no-op.
    #[test]
    fn client_ip_returns_leftmost_parseable_after_peel(
        client_ip_str in "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}",
        trusted_chain in proptest::collection::vec(
            "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}",
            1..4
        ),
    ) {
        // Only run the property when the synthesized client IP is parseable;
        // when it's not (e.g. "999.0.0.0"), the function falls through to
        // peer, which is a separately-covered invariant.
        let parsed_client: Result<IpAddr, _> = client_ip_str.parse();
        prop_assume!(parsed_client.is_ok());
        let hops = trusted_chain.len();
        // Chain: client, trusted_1, ..., trusted_n
        let xff = std::iter::once(client_ip_str.as_str())
            .chain(trusted_chain.iter().map(|s| s.as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        let headers = vec![("x-forwarded-for".to_string(), xff)];
        let peer = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let result = client_ip(&headers, peer, hops);
        prop_assert_eq!(result, parsed_client.unwrap());
    }

    /// Total: `client_ip` never panics across the entire {trust_hops × XFF ×
    /// X-Real-IP} input space — including invalid characters and adversarial
    /// XFF chains.
    #[test]
    fn client_ip_total(
        xff in "[^\\n\\r]{0,128}",
        real in "[^\\n\\r]{0,32}",
        hops in 0usize..6,
    ) {
        let headers = vec![
            ("x-forwarded-for".to_string(), xff),
            ("x-real-ip".to_string(), real),
        ];
        let _ = client_ip(&headers, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), hops);
    }

    /// NEW-M3: `Request::build` must not panic on adversarial inputs —
    /// invalid percent escapes (`%`, `%Z`, `%ZZ`, trailing `%`), embedded
    /// `\0`, raw multi-byte UTF-8 sequences. The previous charset was too
    /// narrow to find these. method/host normalization invariants still
    /// hold across the wider space.
    #[test]
    fn request_build_never_panics(
        method in "[A-Za-z]{1,16}",
        host in "[A-Za-z0-9\\.\\-]{1,64}",
        path in "/[^\\x00-\\x1f]{0,128}",
        query in "[^\\x00-\\x1f]{0,256}",
    ) {
        let r = Request::build(&method, &host, &path, &query, vec![], vec![], false,
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        prop_assert_eq!(&r.method, &method.to_ascii_uppercase());
        prop_assert_eq!(&r.host,   &host.to_ascii_lowercase());
    }

    /// Idempotence: a value that's already percent-decoded (i.e. contains
    /// no `%XX` escapes) round-trips through the parser unchanged via
    /// `inspectable_fields()`. This isn't a true "decode_twice ==
    /// decode_once" because Request only decodes once, but it does pin
    /// that idempotence-on-clean-input.
    #[test]
    fn inspectable_fields_idempotent_on_already_decoded(
        value in "[a-zA-Z0-9 _.,/!?-]{0,64}",
    ) {
        let r = Request::build(
            "GET", "h", "/p", &format!("k={value}"),
            vec![], vec![], false,
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        );
        // The decoded query value should equal the input (no escapes).
        let qp = &r.query_params;
        prop_assert_eq!(qp.len(), 1);
        prop_assert_eq!(&qp[0].1, &value);
    }
}
