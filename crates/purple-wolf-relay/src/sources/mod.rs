//! Source abstraction: a stable async trait that produces a stream of
//! `RawEvent`s (one per audit-log line) for the parser to consume.
//!
//! Two source kinds today (`log_tail`, `stdin`). The trait shape lets
//! future Kafka / Loki / Vector / NATS sources land with no pipeline changes — a
//! new source just needs to push `RawEvent`s onto the same mpsc.

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::{broadcast, mpsc};

/// One raw input line + minimal metadata. Parsing happens downstream
/// so a source doesn't need to know about the purple-wolf schema —
/// only how to deliver bytes.
#[derive(Debug, Clone)]
pub struct RawEvent {
    /// Identifier of the source that produced this event (matches the
    /// source's `id()`). Surfaces in metrics labels.
    pub source_id: String,
    /// One raw audit-log line, including any trailing newline; the
    /// parser strips that.
    pub line: Bytes,
    /// When the relay read this line. Useful for downstream
    /// observability — distinct from any timestamp inside the event.
    pub received_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait]
pub trait Source: Send + Sync {
    /// Stable identifier for this source instance.
    fn id(&self) -> &str;
    /// Run the source to completion, emitting `RawEvent`s on `tx`.
    /// Returns on EOF (stdin), shutdown signal, or unrecoverable error.
    /// Errors should be logged with context before returning so the
    /// caller can decide pipeline-level recovery (Phase G Task 23
    /// flips `pwrelay_ready` to 0 on source failure).
    async fn run(
        self: Box<Self>,
        tx: mpsc::Sender<RawEvent>,
        shutdown: broadcast::Receiver<()>,
    ) -> anyhow::Result<()>;
}

pub mod log_tail;
pub mod stdin;

/// Construct a boxed `Source` from a config entry.
pub fn build(cfg: &crate::config::SourceConfig) -> anyhow::Result<Box<dyn Source>> {
    Ok(match cfg {
        crate::config::SourceConfig::LogTail {
            path,
            from_beginning,
        } => Box::new(log_tail::LogTailSource::new(path.clone(), *from_beginning)?),
        crate::config::SourceConfig::Stdin => Box::new(stdin::StdinSource::new()),
    })
}
