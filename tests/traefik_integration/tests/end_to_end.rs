//! Spin up Traefik + a stub upstream in Docker with the built .wasm
//! mounted as a local plugin. Drive real HTTP. Assert WAF behavior.
use std::process::Command;
use std::time::Duration;

fn build_wasm() {
    let status = Command::new("cargo")
        .args(["build", "--release", "-p", "purple-wolf-traefik",
               "--target", "wasm32-wasip1"])
        .current_dir("../..")
        .status().expect("cargo build");
    assert!(status.success(), "wasm build failed");
}

fn compose_up() {
    let _ = Command::new("docker").args(["compose", "down", "-v"])
        .current_dir(".").status();
    let status = Command::new("docker")
        .current_dir(".")
        .args(["compose", "up", "-d"])
        .status().expect("docker compose up");
    assert!(status.success());
    std::thread::sleep(Duration::from_secs(5));
}

fn compose_down() {
    let _ = Command::new("docker")
        .current_dir(".")
        .args(["compose", "down", "-v"]).status();
}

struct Stack;
impl Drop for Stack { fn drop(&mut self) { compose_down(); } }

fn get(path: &str) -> u16 {
    match ureq::get(&format!("http://127.0.0.1:8080{path}")).call() {
        Ok(r) => r.status(),
        Err(ureq::Error::Status(c, _)) => c,
        Err(_) => 0,
    }
}

fn get_with_header(path: &str, name: &str, value: &str) -> u16 {
    match ureq::get(&format!("http://127.0.0.1:8080{path}"))
        .set(name, value)
        .call()
    {
        Ok(r) => r.status(),
        Err(ureq::Error::Status(c, _)) => c,
        Err(_) => 0,
    }
}

#[test]
#[ignore = "requires docker on PATH; run with --ignored or in CI"]
fn enforce_blocks_sqli_through_real_traefik() {
    build_wasm();
    let _s = Stack;
    compose_up();
    assert_eq!(get("/e/"), 200, "clean through enforce route");
    assert_eq!(get("/e/?id=1%27%20OR%20%271%27%3D%271"), 403,
        "SQLi blocked by enforce");
    assert_eq!(get("/m/?id=1%27%20OR%20%271%27%3D%271"), 200,
        "SQLi passes in monitor");
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
