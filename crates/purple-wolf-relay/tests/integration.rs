//! End-to-end relay integration.
//!
//! Spawns the relay binary as a child process, pipes a single
//! Traefik-style audit line into stdin, and asserts a mock HTTP
//! subscriber receives exactly one signed POST that:
//!   - carries the documented headers,
//!   - has a body matching the envelope schema,
//!   - has a signature that verifies against the configured secret.
//!
//! This exercises the full pipeline: stdin source → parser → fan-out
//! → HTTP sink → HMAC signer → reqwest POST.

use std::io::Write;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

use hmac::{Hmac, Mac};
use sha2::Sha256;

const SECRET: &str = "integration-test-secret";

fn verify_signature(secret: &[u8], ts: &str, body: &[u8], header_value: &str) -> bool {
    let Some(hex_part) = header_value.strip_prefix("sha256=") else {
        return false;
    };
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).unwrap();
    mac.update(format!("{ts}.").as_bytes());
    mac.update(body);
    let expected = hex::encode(mac.finalize().into_bytes());
    expected == hex_part
}

#[tokio::test]
async fn end_to_end_delivers_signed_envelope_to_subscriber() {
    let mock = MockServer::start().await;
    // Set up the mock to record every request and respond 200.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock)
        .await;

    // Write the config to a tempfile.
    let cfg_dir = tempfile::tempdir().unwrap();
    let cfg_path = cfg_dir.path().join("relay.yaml");
    let yaml = format!(
        r#"
sources:
  - type: stdin
subscribers:
  - id: e2e
    url: {url}/webhook
    secret_env: INTEGRATION_SECRET
    timeout_ms: 5000
    retry:
      max_attempts: 1
      base_delay_ms: 100
      max_delay_ms: 200
relay:
  instance_id: e2e-relay
"#,
        url = mock.uri()
    );
    std::fs::write(&cfg_path, yaml).unwrap();

    // Locate the relay binary cargo built for this test.
    let bin = env!("CARGO_BIN_EXE_purple-wolf-relay");

    let mut child = Command::new(bin)
        .arg("--config")
        .arg(&cfg_path)
        // Use a per-run admin port so parallel test runs don't collide.
        .arg("--admin-addr")
        .arg("127.0.0.1:0")
        .env("INTEGRATION_SECRET", SECRET)
        // Trim relay noise out of cargo test output unless the test fails.
        .env("RUST_LOG", "warn")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn relay");

    // Wait for the relay to come up (pipeline-ready log appears on
    // stderr). For an integration test, a small sleep is acceptable.
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Pipe a known audit-log line (the exact format the WAF emits).
    let audit_line = br#"{"host":"checkout.acme.example","path":"/api/v1/cart","query":"id=1%27+OR+%271%27%3D%271","method":"POST","source_ip":"203.0.113.7","action":"block","blocked_rule":"injection/sqli","blocked_severity":"critical","blocked_detail":"SQLi","would_block_rules":["reputation/rate_limited"],"labels":{"tenant":"acme","service":"checkout"}}"#;
    {
        let mut stdin = child.stdin.take().expect("stdin");
        use tokio::io::AsyncWriteExt;
        stdin.write_all(audit_line).await.unwrap();
        stdin.write_all(b"\n").await.unwrap();
        stdin.flush().await.unwrap();
        // Dropping stdin closes it → stdin source hits EOF.
        drop(stdin);
    }

    // Wait briefly for the delivery to land at wiremock.
    for _ in 0..40 {
        if !mock
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Snapshot received requests.
    let received = mock.received_requests().await.unwrap();
    assert_eq!(received.len(), 1, "expected exactly one delivery");

    let req = &received[0];
    // Required headers per docs/webhook-protocol.md.
    let h = |name: &str| -> String {
        req.headers
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default()
    };
    assert_eq!(h("x-purplewolf-schema"), "purple-wolf.audit/v1");
    assert_eq!(h("x-purplewolf-attempt"), "1");
    assert!(h("x-purplewolf-event-id").len() > 8);
    assert!(h("x-purplewolf-delivery-id").len() > 8);
    let ts = h("x-purplewolf-timestamp");
    assert!(ts.parse::<u64>().is_ok(), "timestamp not numeric: {ts}");
    let sig = h("x-purplewolf-signature");
    assert!(sig.starts_with("sha256="));

    // Verify the HMAC.
    assert!(
        verify_signature(SECRET.as_bytes(), &ts, &req.body, &sig),
        "signature verification failed"
    );

    // Body shape checks.
    let env: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(env["schema"], "purple-wolf.audit/v1");
    assert_eq!(env["source"]["middleware"], serde_json::Value::Null);
    assert_eq!(env["source"]["relay_instance"], "e2e-relay");
    assert_eq!(env["labels"]["tenant"], "acme");
    assert_eq!(env["labels"]["service"], "checkout");
    assert_eq!(env["event"]["action"], "block");
    assert_eq!(env["event"]["blocked_rule"], "injection/sqli");

    // Tear down: send SIGTERM (or kill on Windows). On Unix we use
    // the public start_kill API.
    let _ = child.kill().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
    // Silence "unused" warning on the writer import.
    let _ = std::io::stderr().flush();
}
