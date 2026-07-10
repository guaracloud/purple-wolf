use criterion::{black_box, criterion_group, criterion_main, Criterion};
use purple_wolf_relay::parser::parse_line;

const ORDINARY_TAEFIK_LINE: &[u8] = b"2026-07-10T10:00:00Z INF Configuration loaded from flags.";

const PLAIN_AUDIT_LINE: &[u8] = br#"2026-07-10T10:00:00Z INF {"host":"api.example.com","path":"/search","query":"id=1%27","method":"GET","source_ip":"203.0.113.7","action":"block","blocked_rule":"injection/sqli","blocked_severity":"critical","blocked_detail":"SQLi in field: 1'","would_block_rules":[],"labels":{"tenant":"acme"}} entryPointName=web middlewareName=strict-waf@file routerName=api@file"#;

const ANSI_AUDIT_LINE: &[u8] = b"\x1b[90m2026-07-10T10:00:00Z\x1b[0m \x1b[32mINF\x1b[0m \x1b[1m{\"host\":\"api.example.com\",\"path\":\"/search\",\"query\":\"id=1%27\",\"method\":\"GET\",\"source_ip\":\"203.0.113.7\",\"action\":\"block\",\"blocked_rule\":\"injection/sqli\",\"blocked_severity\":\"critical\",\"blocked_detail\":\"SQLi in field: 1'\",\"would_block_rules\":[],\"labels\":{\"tenant\":\"acme\"}}\x1b[0m \x1b[36mentryPointName=\x1b[0mweb \x1b[36mmiddlewareName=\x1b[0mstrict-waf@file \x1b[36mrouterName=\x1b[0mapi@file";

fn bench_parser(c: &mut Criterion) {
    c.bench_function("parser/ordinary_traefik_line", |b| {
        b.iter(|| parse_line(black_box(ORDINARY_TAEFIK_LINE)))
    });
    c.bench_function("parser/plain_audit_line", |b| {
        b.iter(|| parse_line(black_box(PLAIN_AUDIT_LINE)))
    });
    c.bench_function("parser/ansi_audit_line", |b| {
        b.iter(|| parse_line(black_box(ANSI_AUDIT_LINE)))
    });
}

criterion_group!(benches, bench_parser);
criterion_main!(benches);
