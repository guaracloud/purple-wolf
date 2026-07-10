use criterion::{black_box, criterion_group, criterion_main, Criterion};
use purple_wolf_core::audit::AuditEntry;
use purple_wolf_core::config::{GroupMode, Mode};
use purple_wolf_core::detectors::{
    injection::InjectionDetector, reputation::ReputationDetector, signatures::SignatureDetector,
    structural::StructuralDetector, Detector, Engine, Group,
};
use purple_wolf_core::policy;
use purple_wolf_core::policy::Action;
use purple_wolf_core::request::{client_ip, Request};
use std::net::{IpAddr, Ipv4Addr};

fn benign_request() -> Request {
    Request::build(
        "GET",
        "example.com",
        "/api/v1/users",
        "page=2&limit=20",
        vec![
            ("user-agent".into(), "Mozilla/5.0".into()),
            ("accept".into(), "application/json".into()),
        ],
        vec![],
        false,
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 17)),
    )
}

fn benign_bodyless_get() -> Request {
    Request::build(
        "GET",
        "example.com",
        "/healthz",
        "",
        vec![("user-agent".into(), "Mozilla/5.0".into())],
        vec![],
        false,
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 17)),
    )
}

fn realistic_browser_request() -> Request {
    Request::build(
        "GET",
        "api.example.com",
        "/api/v1/customers",
        "page=2&limit=20",
        vec![
            (
                "User-Agent".into(),
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
                    .into(),
            ),
            ("Accept".into(), "application/json".into()),
            (
                "Authorization".into(),
                "Bearer eyJhbGciOiJIUzI1NiJ9.payload".into(),
            ),
            ("Cookie".into(), "session=abc123; csrf=def456".into()),
            ("X-Request-Id".into(), "01JZQ3PK1A2BCDEF3456789XYZ".into()),
            (
                "X-Forwarded-For".into(),
                "198.51.100.17, 10.0.0.8, 10.0.0.9".into(),
            ),
        ],
        vec![],
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
    )
}

fn sqli_request() -> Request {
    Request::build(
        "GET",
        "example.com",
        "/search",
        "q=1' OR '1'='1",
        vec![("user-agent".into(), "Mozilla/5.0".into())],
        vec![],
        false,
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 17)),
    )
}

fn signature_request() -> Request {
    Request::build(
        "GET",
        "example.com",
        "/download",
        "file=../../etc/passwd",
        vec![("user-agent".into(), "Mozilla/5.0".into())],
        vec![],
        false,
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 17)),
    )
}

fn bench(c: &mut Criterion) {
    let engine = Engine::new(vec![
        Box::new(InjectionDetector),
        Box::new(SignatureDetector::new()),
        Box::new(StructuralDetector),
    ]);
    let groups = &[Group::Injection, Group::Signatures, Group::Structural];

    c.bench_function("inspect/benign", |b| {
        b.iter(|| {
            let r = benign_request();
            let v = engine.inspect(&r, black_box(groups));
            let _ = policy::decide(v, Mode::Enforce, |_| GroupMode::Enforce);
        })
    });

    c.bench_function("inspect/benign_bodyless_get", |b| {
        b.iter(|| {
            let r = benign_bodyless_get();
            let v = engine.inspect(&r, black_box(groups));
            let _ = policy::decide(v, Mode::Enforce, |_| GroupMode::Enforce);
        })
    });

    c.bench_function("inspect/sqli", |b| {
        b.iter(|| {
            let r = sqli_request();
            let v = engine.inspect(&r, black_box(groups));
            let _ = policy::decide(v, Mode::Enforce, |_| GroupMode::Enforce);
        })
    });

    c.bench_function("inspect/signature_hit", |b| {
        b.iter(|| {
            let r = signature_request();
            let v = engine.inspect(&r, black_box(groups));
            let _ = policy::decide(v, Mode::Enforce, |_| GroupMode::Enforce);
        })
    });

    c.bench_function("audit/noteworthy_block", |b| {
        b.iter(|| {
            let r = sqli_request();
            let v = engine.inspect(&r, black_box(groups));
            let decision = policy::decide(v, Mode::Enforce, |_| GroupMode::Enforce);
            if black_box(decision.action) == Action::Block {
                let _ = AuditEntry::from(&r, &decision);
            }
        })
    });

    c.bench_function("detector/injection", |b| {
        b.iter(|| InjectionDetector.inspect(&sqli_request()))
    });
    let browser_request = realistic_browser_request();
    c.bench_function("detector/injection_browser_ua", |b| {
        b.iter(|| InjectionDetector.inspect(black_box(&browser_request)))
    });
    let signature_detector = SignatureDetector::new();
    c.bench_function("detector/signatures", |b| {
        b.iter(|| signature_detector.inspect(&signature_request()))
    });

    c.bench_function("request/build_realistic_headers", |b| {
        b.iter(|| black_box(realistic_browser_request()))
    });

    let xff_headers = vec![(
        "x-forwarded-for".to_string(),
        "198.51.100.17, 10.0.0.8, 10.0.0.9".to_string(),
    )];
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));
    c.bench_function("request/client_ip_xff", |b| {
        b.iter(|| client_ip(black_box(&xff_headers), peer, black_box(2)))
    });

    c.bench_function("reputation/construct_default", |b| {
        b.iter(|| black_box(ReputationDetector::with_capacity(100, Vec::new(), 50_000)))
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
