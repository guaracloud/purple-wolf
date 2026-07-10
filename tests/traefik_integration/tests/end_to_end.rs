//! Spin up Traefik + a stub upstream in Docker with the built .wasm
//! mounted as a local plugin. Drive real HTTP. Assert WAF behavior.
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

fn build_wasm() {
    if let Some(prebuilt) = std::env::var_os("PURPLE_WOLF_PREBUILT_WASM") {
        let destination = Path::new("../../target/wasm32-wasip1/release/purple_wolf_traefik.wasm");
        std::fs::create_dir_all(destination.parent().expect("destination has parent"))
            .expect("create wasm output directory");
        std::fs::copy(prebuilt, destination).expect("copy prebuilt wasm");
        return;
    }
    let status = Command::new("cargo")
        .args([
            "build",
            "--release",
            "-p",
            "purple-wolf-traefik",
            "--target",
            "wasm32-wasip1",
        ])
        .current_dir("../..")
        .status()
        .expect("cargo build");
    assert!(status.success(), "wasm build failed");
}

fn compose_up() {
    let _ = Command::new("docker")
        .args(["compose", "down", "-v"])
        .current_dir(".")
        .status();
    let status = Command::new("docker")
        .current_dir(".")
        .args(["compose", "up", "-d"])
        .status()
        .expect("docker compose up");
    assert!(status.success());
    std::thread::sleep(Duration::from_secs(5));
}

fn compose_down() {
    let _ = Command::new("docker")
        .current_dir(".")
        .args(["compose", "down", "-v"])
        .status();
}

struct Stack;
impl Drop for Stack {
    fn drop(&mut self) {
        compose_down();
    }
}

fn base_url() -> String {
    let port = std::env::var("PURPLE_WOLF_TRAEFIK_PORT").unwrap_or_else(|_| "8080".into());
    format!("http://127.0.0.1:{port}")
}

fn get(path: &str) -> u16 {
    match ureq::get(&format!("{}{path}", base_url())).call() {
        Ok(r) => r.status(),
        Err(ureq::Error::Status(c, _)) => c,
        Err(_) => 0,
    }
}

fn get_with_header(path: &str, name: &str, value: &str) -> u16 {
    match ureq::get(&format!("{}{path}", base_url()))
        .set(name, value)
        .call()
    {
        Ok(r) => r.status(),
        Err(ureq::Error::Status(c, _)) => c,
        Err(_) => 0,
    }
}

fn response_parts(response: Result<ureq::Response, ureq::Error>) -> (u16, Vec<u8>) {
    let (status, response) = match response {
        Ok(response) => (response.status(), response),
        Err(ureq::Error::Status(status, response)) => (status, response),
        Err(error) => panic!("request failed: {error}"),
    };
    let mut body = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut body)
        .expect("read response body");
    (status, body)
}

fn post(path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    response_parts(
        ureq::post(&format!("{}{path}", base_url()))
            .set("Content-Type", "application/octet-stream")
            .send_bytes(body),
    )
}

fn chunked_post(path: &str, chunks: &[&[u8]]) -> (u16, Vec<u8>) {
    let port = std::env::var("PURPLE_WOLF_TRAEFIK_PORT").unwrap_or_else(|_| "8080".into());
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect to Traefik");
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n"
    )
    .expect("write chunked request headers");
    for chunk in chunks {
        write!(stream, "{:x}\r\n", chunk.len()).expect("write chunk size");
        stream.write_all(chunk).expect("write chunk");
        stream.write_all(b"\r\n").expect("write chunk terminator");
    }
    stream.write_all(b"0\r\n\r\n").expect("write final chunk");
    stream.flush().expect("flush chunked request");

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("read chunked response");
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response has headers");
    let headers = String::from_utf8_lossy(&response[..header_end]);
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("response has numeric status");
    (status, response[header_end + 4..].to_vec())
}

#[test]
#[ignore = "requires docker on PATH; run with --ignored or in CI"]
fn enforce_blocks_sqli_through_real_traefik() {
    build_wasm();
    let _s = Stack;
    compose_up();
    assert_eq!(get("/e/"), 200, "clean through enforce route");
    assert_eq!(
        get("/e/?id=1%27%20OR%20%271%27%3D%271"),
        403,
        "SQLi blocked by enforce"
    );
    assert_eq!(
        get("/m/?id=1%27%20OR%20%271%27%3D%271"),
        200,
        "SQLi passes in monitor"
    );
}

/// Regression guard for v0.2 C-1: the engine must inspect allow-listed
/// request headers (Cookie, Referer, X-*, Host, Authorization, User-Agent)
/// in addition to URL/query/body. Prior to the fix, all of the cases below
/// silently returned 200 with no audit-log entry.
#[test]
#[ignore = "requires docker on PATH; run with --ignored or in CI"]
fn enforce_blocks_header_borne_payloads_through_real_traefik() {
    build_wasm();
    let _s = Stack;
    compose_up();
    assert_eq!(
        get_with_header("/e/", "Cookie", "id=1' OR '1'='1"),
        403,
        "Cookie SQLi must be blocked"
    );
    assert_eq!(
        get_with_header("/e/", "Referer", "http://x/?id=1' OR '1'='1"),
        403,
        "Referer SQLi must be blocked"
    );
    assert_eq!(
        get_with_header("/e/", "X-User", "' OR 1=1 --"),
        403,
        "Custom X-* header SQLi must be blocked"
    );
    // Benign cookies must still pass cleanly — guards against the
    // false-positive risk that header inspection introduces.
    assert_eq!(
        get_with_header("/e/", "Cookie", "sessionid=abc123; csrftoken=xyz789"),
        200,
        "benign cookie should not false-positive"
    );
}

/// The WAF must inspect bodies regardless of HTTP framing and must leave a
/// benign body byte-for-byte readable by the downstream handler.
#[test]
#[ignore = "requires docker on PATH; run with --ignored or in CI"]
fn request_bodies_are_inspected_and_preserved_through_real_traefik() {
    build_wasm();
    let _s = Stack;
    compose_up();

    let benign = b"customer_id=12345&note=hello";
    let (status, echoed) = post("/e/echo", benign);
    assert_eq!(status, 200, "benign fixed-length body must pass");
    assert_eq!(
        echoed, benign,
        "fixed-length body must reach the upstream intact"
    );

    let attack = b"id=1' OR '1'='1";
    assert_eq!(
        post("/e/echo", attack).0,
        403,
        "fixed-length SQLi must block"
    );

    // The strict test Middleware caps inspection at 4 KiB. The host must
    // still restore the complete body, not only the inspected prefix.
    let large_benign = vec![b'a'; 8 * 1024];
    let (status, echoed) = post("/e/echo", &large_benign);
    assert_eq!(status, 200, "over-cap benign body must follow pass policy");
    assert_eq!(
        echoed, large_benign,
        "over-cap body must reach the upstream intact"
    );

    let chunks: &[&[u8]] = &[b"customer_id=12345", b"&note=hello"];
    let (status, echoed) = chunked_post("/e/echo", chunks);
    assert_eq!(status, 200, "benign chunked body must pass");
    assert_eq!(
        echoed, benign,
        "chunked body must reach the upstream intact"
    );

    let attack_chunks: &[&[u8]] = &[b"id=1' OR ", b"'1'='1"];
    assert_eq!(
        chunked_post("/e/echo", attack_chunks).0,
        403,
        "chunked SQLi must block even though no Content-Length is present"
    );
}

/// v0.3: the operator-supplied `labels:` block on the strict-waf
/// Middleware must surface verbatim — alphabetically ordered — in every
/// audit-log line produced for that Middleware. Drives a SQLi attack
/// to force a `block` verdict so we have something noteworthy in the
/// logs, then greps Traefik's stdout for the expected labels field.
#[test]
#[ignore = "requires docker on PATH; run with --ignored or in CI"]
fn audit_log_includes_operator_labels() {
    build_wasm();
    let _s = Stack;
    compose_up();
    // Drive a SQLi hit to force a block-action audit line.
    let status = get("/e/?id=1%27%20OR%20%271%27%3D%271");
    assert_eq!(status, 403, "SQLi must be blocked");
    std::thread::sleep(Duration::from_millis(500));

    let logs = Command::new("docker")
        .args(["compose", "logs", "traefik"])
        .current_dir(".")
        .output()
        .expect("docker compose logs traefik")
        .stdout;
    let text = String::from_utf8_lossy(&logs);
    let line = text
        .lines()
        .find(|l| l.contains("\"action\":\"block\"") && l.contains("\"injection/sqli\""))
        .expect("expected at least one block audit line in traefik stdout");
    assert!(
        line.contains(
            r#""labels":{"environment":"ci","service":"integration-test","tenant":"acme"}"#
        ),
        "audit line missing alphabetically-ordered labels: {line}"
    );
}
