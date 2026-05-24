//! Property-based invariants the engine must never violate.
use proptest::prelude::*;
use purple_wolf_core::config::{GroupMode, Mode};
use purple_wolf_core::detectors::{Group, Severity, Verdict};
use purple_wolf_core::policy::{self, Action};
use purple_wolf_core::request::{Request, client_ip};
use std::net::{IpAddr, Ipv4Addr};

fn any_group() -> impl Strategy<Value = Group> {
    prop_oneof![
        Just(Group::Injection),
        Just(Group::Signatures),
        Just(Group::Structural),
        Just(Group::Reputation),
    ]
}

fn any_verdict() -> impl Strategy<Value = Verdict> {
    any_group().prop_map(|g| Verdict {
        group: g,
        rule: "p",
        severity: Severity::High,
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

    /// Building a Request from arbitrary inputs never panics and the
    /// resulting `method`/`host` are uppercased/lowercased respectively.
    #[test]
    fn request_build_never_panics(
        method in "[A-Za-z]{1,16}",
        host in "[A-Za-z0-9\\.\\-]{1,64}",
        path in "/[A-Za-z0-9/_\\-\\.%]{0,128}",
        query in "[A-Za-z0-9=&%\\-_]{0,256}"
    ) {
        let r = Request::build(&method, &host, &path, &query, vec![], vec![], false,
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        prop_assert_eq!(&r.method, &method.to_ascii_uppercase());
        prop_assert_eq!(&r.host,   &host.to_ascii_lowercase());
    }

    /// `client_ip` always returns SOME IpAddr — never panics.
    #[test]
    fn client_ip_total(xff in "[0-9\\.,\\s]{0,128}", real in "[0-9\\.]{0,32}") {
        let headers = vec![
            ("x-forwarded-for".to_string(), xff),
            ("x-real-ip".to_string(), real),
        ];
        let _ = client_ip(&headers, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        // The function returning any IpAddr is the property.
        prop_assert!(true);
    }
}
