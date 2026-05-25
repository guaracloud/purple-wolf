//! Full-stack integration: Traefik + WAF + relay + mock subscriber.
//!
//! Marked `#[ignore]` because it requires Docker; run with
//! `cargo test --manifest-path tests/relay_integration/Cargo.toml -- --ignored`
//! or via the relay-integration CI job.

use std::process::Command;
use std::time::Duration;

fn build_wasm() {
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
        .expect("cargo build wasm");
    assert!(status.success(), "wasm build failed");
}

fn build_relay() {
    // The docker-compose relay service runs the debug binary out of
    // the host's target/ directory; build it before bringing the stack
    // up so the bind-mount has something to execute.
    let status = Command::new("cargo")
        .args(["build", "-p", "purple-wolf-relay"])
        .current_dir("../..")
        .status()
        .expect("cargo build relay");
    assert!(status.success(), "relay build failed");
}

fn compose_up() {
    // Clean any previous shared state.
    let _ = std::fs::create_dir_all("shared");
    let _ = std::fs::remove_file("shared/requests.jsonl");
    let _ = Command::new("docker")
        .args(["compose", "down", "-v"])
        .current_dir(".")
        .status();
    let status = Command::new("docker")
        .args(["compose", "up", "-d"])
        .current_dir(".")
        .status()
        .expect("docker compose up");
    assert!(status.success());
    // Allow time for Traefik + relay + subscriber to come up.
    std::thread::sleep(Duration::from_secs(8));
}

fn compose_down() {
    let _ = Command::new("docker")
        .args(["compose", "down", "-v"])
        .current_dir(".")
        .status();
}

struct Stack;
impl Drop for Stack {
    fn drop(&mut self) {
        compose_down();
    }
}

fn drive_sqli() {
    let _ = ureq::get("http://127.0.0.1:8080/e/?id=1%27%20OR%20%271%27%3D%271").call();
}

/// Pump Traefik's container logs into the relay's stdin. Started in a
/// daemon thread; runs until compose_down kills the relay.
fn start_log_pump() {
    std::thread::spawn(|| {
        let _ = Command::new("sh")
            .args([
                "-c",
                "docker compose logs -f --no-color traefik | \
                 docker compose exec -T relay tee /dev/stdin >/dev/null",
            ])
            .current_dir(".")
            .status();
    });
}

#[test]
#[ignore = "requires docker on PATH; run with --ignored or via the relay-integration CI matrix"]
fn full_stack_delivers_envelope_with_labels_to_subscriber() {
    build_wasm();
    build_relay();
    let _s = Stack;
    compose_up();
    start_log_pump();

    drive_sqli();
    std::thread::sleep(Duration::from_secs(3));

    let text = std::fs::read_to_string("shared/requests.jsonl")
        .expect("subscriber didn't record any requests");
    let line = text
        .lines()
        .next()
        .expect("requests.jsonl is empty");
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    let body = &v["body"];
    assert_eq!(body["schema"], "purple-wolf.audit/v1");
    assert_eq!(body["event"]["action"], "block");
    assert_eq!(body["event"]["blocked_rule"], "injection/sqli");
    assert_eq!(body["labels"]["tenant"], "acme");
    assert_eq!(body["labels"]["service"], "integration-test");
    assert_eq!(body["labels"]["environment"], "ci");
}
