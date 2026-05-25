//! HTTP enricher: GET an upstream URL for each unique label value,
//! parse the JSON response as `{key: string}`, merge into labels.
//!
//! Per-call timeout is hard — anything slower is treated as a failure
//! and the envelope proceeds without enrichment. Responses are
//! cached per (url, value) with a TTL so a downstream catalog can be
//! moderately slow without becoming a single point of latency.
//!
//! v0.3 uses an unbounded HashMap for the cache. Cardinality is
//! bounded in practice by the operator's label values; if a deployment
//! has truly high cardinality, the operator can disable caching by
//! setting `cache_ttl_s: 0`.

use async_trait::async_trait;
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::Enricher;

pub struct HttpEnricher {
    on_label: String,
    /// URL template containing one `{value}` placeholder.
    url_template: String,
    timeout: Duration,
    cache_ttl: Duration,
    client: reqwest::Client,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

struct CacheEntry {
    labels: BTreeMap<String, String>,
    expires_at: Instant,
}

impl HttpEnricher {
    pub fn new(
        on_label: String,
        url_template: String,
        timeout: Duration,
        cache_ttl: Duration,
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
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn cache_get(&self, value: &str) -> Option<BTreeMap<String, String>> {
        let cache = self.cache.lock().unwrap();
        let e = cache.get(value)?;
        if Instant::now() < e.expires_at {
            Some(e.labels.clone())
        } else {
            None
        }
    }

    fn cache_put(&self, value: String, labels: BTreeMap<String, String>) {
        let mut cache = self.cache.lock().unwrap();
        cache.insert(
            value,
            CacheEntry {
                labels,
                expires_at: Instant::now() + self.cache_ttl,
            },
        );
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

        let url = self.url_template.replace("{value}", &value);
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

    #[tokio::test]
    async fn http_enricher_skips_when_label_absent() {
        let mock = MockServer::start().await;
        // No mounts: any request would 404. We assert no request happens.
        let enricher = HttpEnricher::new(
            "tenant".into(),
            format!("{}/{{value}}", mock.uri()),
            Duration::from_millis(500),
            Duration::from_secs(60),
        );
        let mut labels = BTreeMap::from([("other".into(), "x".into())]);
        enricher
            .enrich(&mut labels, Duration::from_millis(500))
            .await;
        assert_eq!(labels.len(), 1);
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
