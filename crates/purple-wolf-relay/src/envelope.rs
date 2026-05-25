//! `purple-wolf.audit/v1` envelope — the typed Rust representation of
//! what the wire protocol delivers to subscribers.
//!
//! See `docs/webhook-protocol.md` for the full schema specification.
//! `event_id` is stable for the lifetime of an audit event; the
//! subscriber dedupes on it. `delivery_id` rolls per attempt so a
//! subscriber's per-delivery logs can distinguish retries from
//! originals.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Schema version string carried in every envelope.
pub const SCHEMA_V1: &str = "purple-wolf.audit/v1";

/// One delivery envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Always `"purple-wolf.audit/v1"` today. Subscribers MUST reject
    /// any unfamiliar major version.
    pub schema: String,
    /// ULID. Stable across retries — subscriber dedupes on this.
    pub event_id: String,
    /// ULID. Changes per attempt; subscriber-side logging key only.
    pub delivery_id: String,
    /// When the relay started this attempt.
    pub delivered_at: chrono::DateTime<chrono::Utc>,
    /// 1-based attempt counter; mirrors the `X-PurpleWolf-Attempt`
    /// header.
    pub attempt: u32,
    /// Operator-supplied labels carried verbatim from the WAF.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Traefik enrichment + this relay's identity.
    pub source: EnvelopeSource,
    /// Purple-wolf audit event, passed through verbatim. Forward-
    /// compatible: minor schema additions land here without bumping
    /// the envelope schema version.
    pub event: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeSource {
    /// Traefik Middleware name without the `@file` / `@kubernetescrd`
    /// suffix. None if the relay couldn't extract it from the log line.
    pub middleware: Option<String>,
    pub router: Option<String>,
    pub entry_point: Option<String>,
    /// Stable identifier for THIS relay instance (from
    /// `config.relay.instance_id` or hostname).
    pub relay_instance: String,
}

impl Envelope {
    /// Build a fresh envelope for a parsed audit event. `event_id`
    /// equals `delivery_id` on the first attempt; later attempts roll
    /// `delivery_id` + `delivered_at` via `with_attempt`.
    pub fn new(
        event: serde_json::Value,
        source: EnvelopeSource,
        labels: BTreeMap<String, String>,
    ) -> Self {
        let id = ulid::Ulid::new().to_string();
        Self {
            schema: SCHEMA_V1.to_string(),
            event_id: id.clone(),
            delivery_id: id,
            delivered_at: chrono::Utc::now(),
            attempt: 1,
            labels,
            source,
            event,
        }
    }

    /// Roll the delivery metadata for a retry attempt. The HMAC
    /// timestamp is part of the signature (anti-replay) so the
    /// subscriber-sink layer re-signs after calling this.
    pub fn with_attempt(mut self, n: u32) -> Self {
        self.delivery_id = ulid::Ulid::new().to_string();
        self.delivered_at = chrono::Utc::now();
        self.attempt = n;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_source() -> EnvelopeSource {
        EnvelopeSource {
            middleware: Some("strict-waf".into()),
            router: Some("checkout".into()),
            entry_point: Some("web".into()),
            relay_instance: "r1".into(),
        }
    }

    #[test]
    fn envelope_round_trips_v1_schema_string() {
        let env = Envelope::new(
            serde_json::json!({"action":"block","blocked_rule":"injection/sqli"}),
            dummy_source(),
            BTreeMap::from([("tenant".into(), "acme".into())]),
        );
        let json = serde_json::to_string(&env).unwrap();
        let decoded: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.schema, SCHEMA_V1);
        assert_eq!(decoded.labels, env.labels);
        assert_eq!(decoded.event_id, env.event_id);
        assert_eq!(decoded.event["action"], "block");
    }

    #[test]
    fn envelope_omits_empty_labels_in_json() {
        let env = Envelope::new(serde_json::json!({}), dummy_source(), BTreeMap::new());
        let json = serde_json::to_string(&env).unwrap();
        assert!(
            !json.contains("\"labels\""),
            "empty labels must be skip-serialized: {json}"
        );
    }

    #[test]
    fn with_attempt_rolls_delivery_id_and_attempt() {
        let env = Envelope::new(serde_json::json!({}), dummy_source(), BTreeMap::new());
        let event_id = env.event_id.clone();
        let delivery_id_1 = env.delivery_id.clone();
        let env2 = env.with_attempt(2);
        assert_eq!(env2.attempt, 2);
        assert_eq!(
            env2.event_id, event_id,
            "event_id is stable across attempts"
        );
        assert_ne!(
            env2.delivery_id, delivery_id_1,
            "delivery_id rolls per attempt"
        );
    }
}
