//! Full-stack integration: Traefik + WAF + relay + mock subscriber.
//!
//! Marked `#[ignore]` because it requires Docker; run with
//! `cargo test --manifest-path tests/relay_integration/Cargo.toml -- --ignored`
//! or via the relay-integration CI job.

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
        .expect("cargo build wasm");
    assert!(status.success(), "wasm build failed");
}

fn compose_up() {
    // Clean any previous shared state.
    let _ = std::fs::create_dir_all("shared");
    let _ = std::fs::remove_file("shared/requests.jsonl");
    let _ = std::fs::remove_file("shared/traefik.log");
    let _ = std::fs::remove_file("shared/traefik.log.purple-wolf-relay.bookmark");
    let _ = std::fs::remove_file("shared/traefik.log.purple-wolf-relay.bookmark.tmp");
    std::fs::File::create("shared/traefik.log").expect("create shared Traefik log");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions("shared/traefik.log", std::fs::Permissions::from_mode(0o666))
            .expect("make shared Traefik log writable");
    }
    let _ = Command::new("docker")
        .args(["compose", "down", "-v"])
        .current_dir(".")
        .status();
    let status = Command::new("docker")
        .args(["compose", "up", "--build", "-d"])
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
    let port = std::env::var("PURPLE_WOLF_TRAEFIK_PORT").unwrap_or_else(|_| "8080".into());
    let _ = ureq::get(&format!(
        "http://127.0.0.1:{port}/e/?id=1%27%20OR%20%271%27%3D%271"
    ))
    .call();
}

#[test]
#[ignore = "requires docker on PATH; run with --ignored or via the relay-integration CI matrix"]
fn full_stack_delivers_envelope_with_labels_to_subscriber() {
    build_wasm();
    let _s = Stack;
    compose_up();

    drive_sqli();
    std::thread::sleep(Duration::from_secs(3));

    let text = std::fs::read_to_string("shared/requests.jsonl")
        .expect("subscriber didn't record any requests");
    let line = text.lines().next().expect("requests.jsonl is empty");
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    let body = &v["body"];
    assert_eq!(body["schema"], "purple-wolf.audit/v1");
    assert_eq!(body["event"]["action"], "block");
    assert_eq!(body["event"]["blocked_rule"], "injection/sqli");
    assert_eq!(body["labels"]["tenant"], "acme");
    assert_eq!(body["labels"]["service"], "integration-test");
    assert_eq!(body["labels"]["environment"], "ci");
}
