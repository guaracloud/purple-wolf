//! Enricher trait + concrete kinds.
//!
//! Enrichers run per-envelope after parsing and before fan-out. Each
//! enricher gets a mutable handle to the envelope's labels and a
//! per-call timeout. Failures (timeout, upstream 5xx, anything) MUST
//! NOT propagate into the pipeline: enrichment is degraded service,
//! not a hard dependency.
//!
//! Enrichers never overwrite an existing label key — they only fill
//! in keys the operator (or a previous enricher) didn't already set.
//! This keeps the operator's explicit labels authoritative.

use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

#[async_trait]
pub trait Enricher: Send + Sync {
    /// Human-readable name (e.g., `"lookup"`, `"http"`), used in
    /// metrics labels and structured-log fields.
    fn name(&self) -> &str;
    /// Enrich labels in place. MUST honor `timeout`. Errors and
    /// timeouts are logged + counted but never returned — they go
    /// silently as far as the pipeline is concerned.
    async fn enrich(&self, labels: &mut BTreeMap<String, String>, timeout: Duration);
}

pub mod http;
pub mod lookup;

/// Construct a boxed enricher from a config entry.
pub fn build(cfg: &crate::config::EnricherConfig) -> Arc<dyn Enricher> {
    match cfg {
        crate::config::EnricherConfig::Lookup { on_label, table } => {
            Arc::new(lookup::LookupEnricher::new(on_label.clone(), table.clone()))
        }
        crate::config::EnricherConfig::Http {
            on_label,
            url,
            timeout_ms,
            cache_ttl_s,
            cache_capacity,
        } => Arc::new(http::HttpEnricher::new(
            on_label.clone(),
            url.clone(),
            Duration::from_millis(*timeout_ms),
            Duration::from_secs(*cache_ttl_s),
            *cache_capacity,
        )),
    }
}

/// Insert-only merge: copies entries from `extra` into `labels` for
/// keys that don't exist in `labels` yet. Shared across enricher
/// implementations so the "never overwrites" contract is enforced
/// exactly once.
pub(crate) fn merge_in_place(
    labels: &mut BTreeMap<String, String>,
    extra: &BTreeMap<String, String>,
) {
    for (k, v) in extra {
        labels.entry(k.clone()).or_insert_with(|| v.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_in_place_does_not_overwrite() {
        let mut labels = BTreeMap::from([("tenant".into(), "acme".into())]);
        let extra = BTreeMap::from([
            ("tenant".into(), "spoofed".into()),
            ("region".into(), "us-east-1".into()),
        ]);
        merge_in_place(&mut labels, &extra);
        assert_eq!(labels.get("tenant").map(String::as_str), Some("acme"));
        assert_eq!(labels.get("region").map(String::as_str), Some("us-east-1"));
    }

    #[test]
    fn merge_in_place_handles_empty() {
        let mut labels = BTreeMap::from([("a".into(), "1".into())]);
        merge_in_place(&mut labels, &BTreeMap::new());
        assert_eq!(labels.len(), 1);

        let mut empty = BTreeMap::new();
        merge_in_place(&mut empty, &BTreeMap::from([("a".into(), "1".into())]));
        assert_eq!(empty.get("a").map(String::as_str), Some("1"));
    }
}
