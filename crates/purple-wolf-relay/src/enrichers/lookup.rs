//! Lookup enricher: static `key → labels` table.
//!
//! When an envelope's `labels[on_label]` matches a key in `table`,
//! the corresponding sub-map is merged into the envelope labels
//! (insert-only — operator-set labels win). Pure in-process; the
//! `timeout` parameter is honored only insofar as the work is trivial
//! and the runtime overhead is negligible.

use async_trait::async_trait;
use std::collections::BTreeMap;
use std::time::Duration;

use super::Enricher;

pub struct LookupEnricher {
    on_label: String,
    table: BTreeMap<String, BTreeMap<String, String>>,
}

impl LookupEnricher {
    pub fn new(on_label: String, table: BTreeMap<String, BTreeMap<String, String>>) -> Self {
        Self { on_label, table }
    }
}

#[async_trait]
impl Enricher for LookupEnricher {
    fn name(&self) -> &str {
        "lookup"
    }

    async fn enrich(&self, labels: &mut BTreeMap<String, String>, _timeout: Duration) {
        let key = match labels.get(&self.on_label) {
            Some(v) => v.clone(),
            None => return,
        };
        let extra = match self.table.get(&key) {
            Some(t) => t,
            None => return,
        };
        super::merge_in_place(labels, extra);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lookup_merges_table_entry_when_key_matches() {
        let table = BTreeMap::from([(
            "acme".to_string(),
            BTreeMap::from([
                ("owner".into(), "payments".into()),
                ("oncall".into(), "pager-payments".into()),
            ]),
        )]);
        let enricher = LookupEnricher::new("tenant".into(), table);
        let mut labels = BTreeMap::from([("tenant".into(), "acme".into())]);
        enricher
            .enrich(&mut labels, Duration::from_millis(100))
            .await;
        assert_eq!(labels.get("owner").map(String::as_str), Some("payments"));
        assert_eq!(
            labels.get("oncall").map(String::as_str),
            Some("pager-payments")
        );
    }

    #[tokio::test]
    async fn lookup_noop_when_label_absent() {
        let table = BTreeMap::from([(
            "acme".to_string(),
            BTreeMap::from([("owner".into(), "x".into())]),
        )]);
        let enricher = LookupEnricher::new("tenant".into(), table);
        let mut labels = BTreeMap::from([("other".into(), "v".into())]);
        let before = labels.clone();
        enricher
            .enrich(&mut labels, Duration::from_millis(100))
            .await;
        assert_eq!(labels, before);
    }

    #[tokio::test]
    async fn lookup_noop_when_table_misses() {
        let table = BTreeMap::from([(
            "acme".to_string(),
            BTreeMap::from([("owner".into(), "x".into())]),
        )]);
        let enricher = LookupEnricher::new("tenant".into(), table);
        let mut labels = BTreeMap::from([("tenant".into(), "unknown-tenant".into())]);
        enricher
            .enrich(&mut labels, Duration::from_millis(100))
            .await;
        assert_eq!(labels.get("owner"), None);
    }

    #[tokio::test]
    async fn lookup_never_overwrites_existing_labels() {
        let table = BTreeMap::from([(
            "acme".to_string(),
            BTreeMap::from([("owner".into(), "spoofed".into())]),
        )]);
        let enricher = LookupEnricher::new("tenant".into(), table);
        let mut labels = BTreeMap::from([
            ("tenant".into(), "acme".into()),
            ("owner".into(), "real-owner".into()),
        ]);
        enricher
            .enrich(&mut labels, Duration::from_millis(100))
            .await;
        assert_eq!(
            labels.get("owner").map(String::as_str),
            Some("real-owner"),
            "operator-set label must win"
        );
    }
}
