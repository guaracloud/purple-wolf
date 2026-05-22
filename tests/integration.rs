//! End-to-end tests: start a stub upstream + purple-wolf, drive real HTTP.
use std::process::{Child, Command};
use std::time::Duration;

struct Servers {
    upstream: Child,
    waf: Child,
}

impl Drop for Servers {
    fn drop(&mut self) {
        let _ = self.upstream.kill();
        let _ = self.waf.kill();
    }
}

/// Start a stub upstream (echo 200) and purple-wolf with the given config text.
fn start(config: &str, waf_port: u16, upstream_port: u16) -> Servers {
    let dir = std::env::temp_dir().join(format!("pw-test-{waf_port}"));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = dir.join("purple-wolf.toml");
    std::fs::write(&cfg_path, config).unwrap();

    let upstream = Command::new("python3")
        .args(["-m", "http.server", &upstream_port.to_string()])
        .current_dir(&dir)
        .spawn()
        .expect("python3 http.server");

    let waf = Command::new(env!("CARGO_BIN_EXE_purple-wolf"))
        .env("PURPLE_WOLF_CONFIG", &cfg_path)
        .spawn()
        .expect("purple-wolf binary");

    std::thread::sleep(Duration::from_millis(1500));
    Servers { upstream, waf }
}

fn config(mode: &str, waf_port: u16, upstream_port: u16) -> String {
    format!(
        r#"
mode = "{mode}"
fail_mode = "fail_open"
upstream = "http://127.0.0.1:{upstream_port}"
listen = "0.0.0.0:{waf_port}"
[body]
max_inspect_bytes = 1048576
over_cap = "pass"
[groups.injection]
enabled = true
mode = "enforce"
[groups.signatures]
enabled = true
mode = "enforce"
[groups.structural]
enabled = true
mode = "enforce"
[groups.reputation]
enabled = false
mode = "monitor"
"#
    )
}

fn get(port: u16, path: &str) -> u16 {
    let out = Command::new("curl")
        .args(["-s", "-o", "/dev/null", "-w", "%{http_code}",
               &format!("http://127.0.0.1:{port}{path}")])
        .output()
        .expect("curl");
    String::from_utf8_lossy(&out.stdout).trim().parse().unwrap_or(0)
}

#[test]
fn enforce_mode_blocks_sqli_and_allows_clean() {
    let _s = start(&config("enforce", 18081, 13001), 18081, 13001);
    assert_eq!(get(18081, "/"), 200, "clean request should be forwarded");
    assert_eq!(
        get(18081, "/?id=1%27%20OR%20%271%27%3D%271"),
        403,
        "SQLi should be blocked in enforce mode"
    );
}

#[test]
fn monitor_mode_allows_sqli() {
    let _s = start(&config("monitor", 18082, 13002), 18082, 13002);
    assert_eq!(
        get(18082, "/?id=1%27%20OR%20%271%27%3D%271"),
        200,
        "SQLi should pass through in monitor mode"
    );
}

// --- Third test: over-cap body pass-through (guards the Task 13 fix) ---

/// Python echo upstream: accepts POST, responds 200 with the received byte
/// count as the body. Handles BOTH a `Content-Length` body and a `chunked`
/// transfer-encoding body — the latter is required because purple-wolf streams
/// an over-cap body to the upstream, which reqwest sends as `chunked`. Also
/// answers GETs with a couple of distinctive upstream headers (`Set-Cookie`,
/// `X-Pw-Test`) so tests can assert end-to-end header pass-through.
const ECHO_SERVER: &str = r#"import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'ok'
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Set-Cookie', 'pw-test=1; Path=/')
        self.send_header('X-Pw-Test', 'present')
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        te = self.headers.get('Transfer-Encoding', '').lower()
        if 'chunked' in te:
            body = b''
            while True:
                size = int(self.rfile.readline().strip() or b'0', 16)
                if size == 0:
                    self.rfile.readline()
                    break
                body += self.rfile.read(size)
                self.rfile.readline()
        else:
            n = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(n)
        msg = str(len(body)).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(msg)))
        self.end_headers()
        self.wfile.write(msg)
    def log_message(self, *a): pass
http.server.HTTPServer(('127.0.0.1', int(sys.argv[1])), H).serve_forever()
"#;

/// Start the echo upstream + purple-wolf for the over-cap test.
fn start_echo(config: &str, waf_port: u16, upstream_port: u16) -> (Servers, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("pw-test-{waf_port}"));
    std::fs::create_dir_all(&dir).unwrap();

    let cfg_path = dir.join("purple-wolf.toml");
    std::fs::write(&cfg_path, config).unwrap();

    let echo_path = dir.join("echo.py");
    std::fs::write(&echo_path, ECHO_SERVER).unwrap();

    let upstream = Command::new("python3")
        .arg(&echo_path)
        .arg(upstream_port.to_string())
        .current_dir(&dir)
        .spawn()
        .expect("python3 echo server");

    let waf = Command::new(env!("CARGO_BIN_EXE_purple-wolf"))
        .env("PURPLE_WOLF_CONFIG", &cfg_path)
        .spawn()
        .expect("purple-wolf binary");

    std::thread::sleep(Duration::from_millis(1500));
    (Servers { upstream, waf }, dir)
}

/// POST a file via curl and return the response body as a string.
fn post_file(port: u16, path: &str, file: &std::path::Path) -> String {
    let out = Command::new("curl")
        .args(["-s", "-X", "POST", "--data-binary"])
        .arg(format!("@{}", file.display()))
        .arg(format!("http://127.0.0.1:{port}{path}"))
        .output()
        .expect("curl");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// GET a URL and return curl's raw response headers (`-D -`) as a string.
fn get_headers(port: u16, path: &str) -> String {
    let out = Command::new("curl")
        .args(["-s", "-D", "-", "-o", "/dev/null",
               &format!("http://127.0.0.1:{port}{path}")])
        .output()
        .expect("curl");
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn upstream_response_headers_pass_through() {
    let waf_port = 18084;
    let upstream_port = 13004;
    let cfg = format!(
        r#"
mode = "enforce"
fail_mode = "fail_open"
upstream = "http://127.0.0.1:{upstream_port}"
listen = "0.0.0.0:{waf_port}"
[body]
max_inspect_bytes = 1048576
over_cap = "pass"
[groups.injection]
enabled = true
mode = "enforce"
[groups.signatures]
enabled = true
mode = "enforce"
[groups.structural]
enabled = true
mode = "enforce"
[groups.reputation]
enabled = false
mode = "monitor"
"#
    );
    let (_s, _dir) = start_echo(&cfg, waf_port, upstream_port);
    let headers = get_headers(waf_port, "/");
    assert!(
        headers.to_lowercase().contains("set-cookie: pw-test=1"),
        "upstream Set-Cookie must pass through, got: {headers:?}"
    );
    assert!(
        headers.to_lowercase().contains("x-pw-test: present"),
        "custom upstream header must pass through, got: {headers:?}"
    );
}

#[test]
fn over_cap_body_is_forwarded_intact() {
    let waf_port = 18083;
    let upstream_port = 13003;
    let cfg = format!(
        r#"
mode = "enforce"
fail_mode = "fail_open"
upstream = "http://127.0.0.1:{upstream_port}"
listen = "0.0.0.0:{waf_port}"
[body]
max_inspect_bytes = 1024
over_cap = "pass"
[groups.injection]
enabled = true
mode = "enforce"
[groups.signatures]
enabled = true
mode = "enforce"
[groups.structural]
enabled = true
mode = "enforce"
[groups.reputation]
enabled = false
mode = "monitor"
"#
    );

    let (_s, dir) = start_echo(&cfg, waf_port, upstream_port);

    // Build a body far larger than max_inspect_bytes (1024).
    let payload = "x".repeat(50_000);
    let body_path = dir.join("big-body.txt");
    std::fs::write(&body_path, &payload).unwrap();

    let resp = post_file(waf_port, "/", &body_path);
    assert_eq!(
        resp, "50000",
        "over-cap body must be forwarded intact (upstream should report 50000 bytes received), got: {resp:?}"
    );
}
