//! stdin source: line-buffered read from stdin until EOF.
//!
//! Useful for piping a docker-compose log stream directly into the
//! relay during development, and for the test harness — `StdinSource`
//! is generic over `AsyncBufRead` so tests can substitute an in-memory
//! reader without spawning a subprocess.

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::sync::{broadcast, mpsc};

use super::{RawEvent, Source};

pub struct StdinSource {
    id: String,
}

impl Default for StdinSource {
    fn default() -> Self {
        Self::new()
    }
}

impl StdinSource {
    pub fn new() -> Self {
        Self {
            id: "stdin".to_string(),
        }
    }
}

#[async_trait]
impl Source for StdinSource {
    fn id(&self) -> &str {
        &self.id
    }

    async fn run(
        self: Box<Self>,
        tx: mpsc::Sender<RawEvent>,
        shutdown: broadcast::Receiver<()>,
    ) -> anyhow::Result<()> {
        let reader = BufReader::new(tokio::io::stdin());
        run_reader(&self.id, reader, tx, shutdown).await
    }
}

/// Inner loop, generic over the reader, so tests can drive it with
/// `tokio::io::duplex` instead of stdin.
pub(crate) async fn run_reader<R: AsyncRead + Unpin + Send>(
    source_id: &str,
    mut reader: BufReader<R>,
    tx: mpsc::Sender<RawEvent>,
    mut shutdown: broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    let mut buf = String::new();
    loop {
        buf.clear();
        tokio::select! {
            biased;
            _ = shutdown.recv() => {
                tracing::info!(source = source_id, "stdin source shutting down");
                return Ok(());
            }
            res = reader.read_line(&mut buf) => {
                match res {
                    Ok(0) => {
                        tracing::info!(source = source_id, "stdin source: EOF");
                        return Ok(());
                    }
                    Ok(_) => {
                        let evt = RawEvent {
                            source_id: source_id.to_string(),
                            line: Bytes::copy_from_slice(buf.as_bytes()),
                            received_at: Utc::now(),
                        };
                        // Send dropped only if the parser already exited.
                        if tx.send(evt).await.is_err() {
                            tracing::info!(
                                source = source_id,
                                "downstream channel closed; stdin source exiting"
                            );
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        tracing::warn!(source = source_id, error = %e, "stdin read error");
                        return Err(e.into());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::time::Duration;

    /// Pipe two lines into the inner reader; assert both come out as
    /// `RawEvent`s with the expected source_id.
    #[tokio::test]
    async fn stdin_yields_lines_until_eof() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let (tx, mut rx) = mpsc::channel(8);
        let (_sd_tx, sd_rx) = broadcast::channel::<()>(1);

        let h = tokio::spawn(async move {
            run_reader("stdin-test", BufReader::new(reader), tx, sd_rx).await
        });

        writer.write_all(b"line1\nline2\n").await.unwrap();
        // Close the writer half → reader hits EOF.
        drop(writer);

        let e1 = rx.recv().await.unwrap();
        assert_eq!(&e1.line[..], b"line1\n");
        assert_eq!(e1.source_id, "stdin-test");
        let e2 = rx.recv().await.unwrap();
        assert_eq!(&e2.line[..], b"line2\n");

        // run_reader returns on EOF; spawned task completes.
        h.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn stdin_exits_on_shutdown_signal() {
        let (writer, reader) = tokio::io::duplex(64);
        let (tx, _rx) = mpsc::channel(8);
        let (sd_tx, sd_rx) = broadcast::channel::<()>(1);

        let h = tokio::spawn(async move {
            run_reader("stdin-test", BufReader::new(reader), tx, sd_rx).await
        });

        // Don't write anything; trigger shutdown.
        tokio::time::sleep(Duration::from_millis(20)).await;
        sd_tx.send(()).unwrap();

        // Should return Ok(()) within a reasonable bound.
        tokio::time::timeout(Duration::from_secs(2), h)
            .await
            .expect("stdin source didn't exit on shutdown")
            .expect("task panicked")
            .expect("source returned error");
        // Avoid unused-var warning.
        drop(writer);
    }

    #[tokio::test]
    async fn stdin_exits_when_downstream_closes() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let (tx, rx) = mpsc::channel(8);
        let (_sd_tx, sd_rx) = broadcast::channel::<()>(1);

        let h = tokio::spawn(async move {
            run_reader("stdin-test", BufReader::new(reader), tx, sd_rx).await
        });

        // Close the receiver before any send happens.
        drop(rx);
        writer.write_all(b"line\n").await.unwrap();
        drop(writer);

        tokio::time::timeout(Duration::from_secs(2), h)
            .await
            .expect("source didn't notice downstream close")
            .expect("task panicked")
            .expect("source returned error");
    }
}
