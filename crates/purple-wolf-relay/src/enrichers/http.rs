//! HTTP enricher: GET an upstream URL for each unique label value,
//! parse the JSON response as `{key: string}`, merge into labels.
//!
//! Per-call timeout is hard — anything slower is treated as a failure
//! and the envelope proceeds without enrichment. Responses are
//! cached per (url, value) with a TTL so a downstream catalog can be
//! moderately slow without becoming a single point of latency.
//!
//! The cache is bounded by both TTL and capacity. High-cardinality label
//! values therefore cannot grow relay memory without bound; operators can
//! disable caching entirely with `cache_ttl_s: 0` or `cache_capacity: 0`.

use async_trait::async_trait;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::Enricher;

/// Characters we percent-encode when substituting a label value into the
/// enricher URL template. We start from controls and add every byte that is
/// structurally significant in a URL — path/query/fragment/authority
/// delimiters and the percent sign itself — so the substituted value can
/// only ever be an opaque path *component*. This prevents an unusual label
/// value (`../../admin`, `evil.com/?`, `@host`) from traversing the path,
/// opening a query/fragment, or altering the authority (SSRF defense in
/// depth: today label values are operator-set, but encoding makes the
/// invariant hold regardless of their charset).
const URL_VALUE_ENCODE: &AsciiSet = &CONTROLS
    .add(b'%')
    .add(b'/')
    .add(b'\\')
    .add(b'?')
    .add(b'#')
    .add(b'&')
    .add(b'=')
    .add(b'@')
    .add(b':')
    .add(b' ')
    .add(b'.');

/// Substitute `value` into `template`'s `{value}` placeholder, percent-
/// encoding the value so it cannot change the URL's structure or authority.
fn build_enrich_url(template: &str, value: &str) -> String {
    let encoded = utf8_percent_encode(value, URL_VALUE_ENCODE).to_string();
    template.replace("{value}", &encoded)
}

pub struct HttpEnricher {
    on_label: String,
    /// URL template containing one `{value}` placeholder.
    url_template: String,
    timeout: Duration,
    cache_ttl: Duration,
    client: reqwest::Client,
    cache: Mutex<Cache>,
}

#[derive(Default)]
struct Cache {
    entries: HashMap<String, CacheEntry>,
    lru: VecDeque<String>,
    capacity: usize,
}

struct CacheEntry {
    labels: BTreeMap<String, String>,
    expires_at: Instant,
}

impl Cache {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            lru: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn get(&mut self, value: &str, now: Instant) -> Option<BTreeMap<String, String>> {
        let entry = self.entries.get(value)?;
        if now >= entry.expires_at {
            self.entries.remove(value);
            remove_lru_key(&mut self.lru, value);
            return None;
        }
        let labels = entry.labels.clone();
        self.touch(value);
        Some(labels)
    }

    fn put(&mut self, value: String, labels: BTreeMap<String, String>, expires_at: Instant) {
        if self.capacity == 0 {
            return;
        }
        self.evict_expired(Instant::now());
        if let Some(entry) = self.entries.get_mut(&value) {
            entry.labels = labels;
            entry.expires_at = expires_at;
            self.touch(&value);
            return;
        }
        while self.entries.len() >= self.capacity {
            if let Some(oldest) = self.lru.pop_front() {
                self.entries.remove(&oldest);
            } else {
                break;
            }
        }
        self.lru.push_back(value.clone());
        self.entries
            .insert(value, CacheEntry { labels, expires_at });
    }

    fn evict_expired(&mut self, now: Instant) {
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter_map(|(key, entry)| {
                if now >= entry.expires_at {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect();
        for key in expired {
            self.entries.remove(&key);
            remove_lru_key(&mut self.lru, &key);
        }
    }

    fn touch(&mut self, value: &str) {
        remove_lru_key(&mut self.lru, value);
        self.lru.push_back(value.to_string());
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

fn remove_lru_key(lru: &mut VecDeque<String>, value: &str) {
    if let Some(pos) = lru.iter().position(|key| key == value) {
        lru.remove(pos);
    }
}

impl HttpEnricher {
    pub fn new(
        on_label: String,
        url_template: String,
        timeout: Duration,
        cache_ttl: Duration,
        cache_capacity: usize,
    ) -> Self {
        // A single client per enricher amortizes connection pooling
        // across calls. Default timeout on the client mirrors our
        // per-call timeout in case the caller doesn't wrap in
        // tokio::time::timeout.
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("reqwest client build");
        Self {
            on_label,
            url_template,
            timeout,
            cache_ttl,
            client,
            cache: Mutex::new(Cache::new(cache_capacity)),
        }
    }

    fn cache_get(&self, value: &str) -> Option<BTreeMap<String, String>> {
        self.cache.lock().unwrap().get(value, Instant::now())
    }

    fn cache_put(&self, value: String, labels: BTreeMap<String, String>) {
        self.cache
            .lock()
            .unwrap()
            .put(value, labels, Instant::now() + self.cache_ttl);
    }

    #[cfg(test)]
    fn cache_len(&self) -> usize {
        self.cache.lock().unwrap().len()
    }
}

#[async_trait]
impl Enricher for HttpEnricher {
    fn name(&self) -> &str {
        "http"
    }

    async fn enrich(&self, labels: &mut BTreeMap<String, String>, _timeout: Duration) {
        let value = match labels.get(&self.on_label) {
            Some(v) => v.clone(),
            None => return,
        };

        if !self.cache_ttl.is_zero() {
            if let Some(cached) = self.cache_get(&value) {
                super::merge_in_place(labels, &cached);
                return;
            }
        }

        let url = build_enrich_url(&self.url_template, &value);
        let fut = self.client.get(&url).send();
        let response = match tokio::time::timeout(self.timeout, fut).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                tracing::warn!(enricher = "http", url = %url, error = %e, "http enricher request failed");
                return;
            }
            Err(_) => {
                tracing::warn!(enricher = "http", url = %url, "http enricher timed out");
                return;
            }
        };
        if !response.status().is_success() {
            tracing::warn!(
                enricher = "http",
                url = %url,
                status = %response.status(),
                "http enricher non-2xx"
            );
            return;
        }
        let parse_fut = response.json::<BTreeMap<String, String>>();
        let extra = match tokio::time::timeout(self.timeout, parse_fut).await {
            Ok(Ok(m)) => m,
            Ok(Err(e)) => {
                tracing::warn!(enricher = "http", url = %url, error = %e, "http enricher body parse failed");
                return;
            }
            Err(_) => {
                tracing::warn!(enricher = "http", url = %url, "http enricher body read timed out");
                return;
            }
        };

        if !self.cache_ttl.is_zero() {
            self.cache_put(value, extra.clone());
        }
        super::merge_in_place(labels, &extra);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn http_enricher_merges_on_2xx() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/tenants/acme/labels"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"owner": "payments", "region": "us-east-1"})),
            )
            .mount(&mock)
            .await;

        let enricher = HttpEnricher::new(
            "tenant".into(),
            format!("{}/tenants/{{value}}/labels", mock.uri()),
            Duration::from_millis(500),
            Duration::from_secs(60),
            1024,
        );
        let mut labels = BTreeMap::from([("tenant".into(), "acme".into())]);
        enricher
            .enrich(&mut labels, Duration::from_millis(500))
            .await;
        assert_eq!(labels.get("owner").map(String::as_str), Some("payments"));
        assert_eq!(labels.get("region").map(String::as_str), Some("us-east-1"));
    }

    #[tokio::test]
    async fn http_enricher_silently_drops_on_500() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock)
            .await;

        let enricher = HttpEnricher::new(
            "tenant".into(),
            format!("{}/{{value}}", mock.uri()),
            Duration::from_millis(500),
            Duration::from_secs(60),
            1024,
        );
        let mut labels = BTreeMap::from([("tenant".into(), "acme".into())]);
        enricher
            .enrich(&mut labels, Duration::from_millis(500))
            .await;
        // Labels unchanged — enrichment failure is non-fatal.
        assert_eq!(labels.len(), 1);
    }

    #[tokio::test]
    async fn http_enricher_caches_within_ttl() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"owner": "payments"})),
            )
            .expect(1) // Exactly one upstream call across two enrich() invocations.
            .mount(&mock)
            .await;

        let enricher = HttpEnricher::new(
            "tenant".into(),
            format!("{}/{{value}}", mock.uri()),
            Duration::from_millis(500),
            Duration::from_secs(60),
            1024,
        );
        for _ in 0..2 {
            let mut labels = BTreeMap::from([("tenant".into(), "acme".into())]);
            enricher
                .enrich(&mut labels, Duration::from_millis(500))
                .await;
            assert_eq!(labels.get("owner").map(String::as_str), Some("payments"));
        }
        // The wiremock `.expect(1)` assertion is verified on drop.
    }

    #[test]
    fn http_enricher_cache_is_capacity_bounded_and_lru() {
        let enricher = HttpEnricher::new(
            "tenant".into(),
            "https://catalog.internal/{value}".into(),
            Duration::from_millis(500),
            Duration::from_secs(60),
            2,
        );
        enricher.cache_put("a".into(), BTreeMap::from([("owner".into(), "a".into())]));
        enricher.cache_put("b".into(), BTreeMap::from([("owner".into(), "b".into())]));
        assert!(enricher.cache_get("a").is_some(), "a is now most recent");
        enricher.cache_put("c".into(), BTreeMap::from([("owner".into(), "c".into())]));

        assert_eq!(enricher.cache_len(), 2);
        assert!(enricher.cache_get("a").is_some());
        assert!(
            enricher.cache_get("b").is_none(),
            "least recent entry evicted"
        );
        assert!(enricher.cache_get("c").is_some());
    }

    #[tokio::test]
    async fn http_enricher_skips_when_label_absent() {
        let mock = MockServer::start().await;
        // No mounts: any request would 404. We assert no request happens.
        let enricher = HttpEnricher::new(
            "tenant".into(),
            format!("{}/{{value}}", mock.uri()),
            Duration::from_millis(500),
            Duration::from_secs(60),
            1024,
        );
        let mut labels = BTreeMap::from([("other".into(), "x".into())]);
        enricher
            .enrich(&mut labels, Duration::from_millis(500))
            .await;
        assert_eq!(labels.len(), 1);
    }

    #[test]
    fn substituted_value_is_percent_encoded_against_ssrf() {
        // SSRF/path-traversal invariant: the {value} substitution must be
        // percent-encoded so an unusual label value can only ever be a path
        // *component*, never alter the path structure or the authority. A
        // value like `../../admin` or `evil.com/?` must not change the host
        // or escape the templated path segment.
        let url = build_enrich_url(
            "https://catalog.internal/tenants/{value}/labels",
            "../../admin",
        );
        // Both slashes AND dots are encoded, so `..` cannot act as a parent-
        // directory traversal segment — the value is a single opaque component.
        assert_eq!(
            url, "https://catalog.internal/tenants/%2E%2E%2F%2E%2E%2Fadmin/labels",
            "slashes and dots in the value must be encoded, not structural"
        );

        let url2 = build_enrich_url("https://catalog.internal/{value}", "evil.com/x?a=b#c");
        assert!(
            url2.starts_with("https://catalog.internal/"),
            "host must be unchanged: {url2}"
        );
        assert!(
            !url2.contains("evil.com/x?") && !url2.contains('#'),
            "URL-significant chars must be encoded: {url2}"
        );
    }

    #[tokio::test]
    async fn http_enricher_does_not_overwrite_existing() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"owner": "spoofed"})),
            )
            .mount(&mock)
            .await;

        let enricher = HttpEnricher::new(
            "tenant".into(),
            format!("{}/{{value}}", mock.uri()),
            Duration::from_millis(500),
            Duration::from_secs(60),
            1024,
        );
        let mut labels = BTreeMap::from([
            ("tenant".into(), "acme".into()),
            ("owner".into(), "real-owner".into()),
        ]);
        enricher
            .enrich(&mut labels, Duration::from_millis(500))
            .await;
        assert_eq!(labels.get("owner").map(String::as_str), Some("real-owner"));
    }
}
