use criterion::{black_box, criterion_group, criterion_main, Criterion};
use purple_wolf_core::config::{GroupMode, Mode};
use purple_wolf_core::detectors::{
    injection::InjectionDetector, signatures::SignatureDetector, structural::StructuralDetector,
    Detector, Engine, Group,
};
use purple_wolf_core::policy;
use purple_wolf_core::request::Request;
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

    c.bench_function("inspect/sqli", |b| {
        b.iter(|| {
            let r = sqli_request();
            let v = engine.inspect(&r, black_box(groups));
            let _ = policy::decide(v, Mode::Enforce, |_| GroupMode::Enforce);
        })
    });

    c.bench_function("detector/injection", |b| {
        b.iter(|| InjectionDetector.inspect(&sqli_request()))
    });
    c.bench_function("detector/signatures", |b| {
        b.iter(|| SignatureDetector::new().inspect(&sqli_request()))
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
