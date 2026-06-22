//! `log_tail` source: tail a file, survive rotation, bookmark across
//! restarts.
//!
//! Polls the file every `POLL_INTERVAL_MS` looking for either appended
//! bytes or a rotation event (inode change / file shrank). On
//! rotation, the old file descriptor is dropped and the source reopens
//! the path from offset 0.
//!
//! Bookmarks: a tiny `<path>.purple-wolf-relay.bookmark` file holds
//! the most recent byte offset, written atomically (via a `.tmp`
//! sibling + rename). On startup, if a bookmark exists and is valid
//! against the current inode, we resume from its offset instead of
//! honoring `from_beginning` or seeking to end. This makes relay
//! restarts continuous: events emitted before the restart are not
//! re-emitted, and events written during the down period are
//! delivered.
//!
//! File-change wakeups use `notify` when the platform watcher can be created,
//! with the 100ms poll retained as a fallback for missed events or unsupported
//! filesystems.

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use notify::Watcher;
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader, SeekFrom};
use tokio::sync::{broadcast, mpsc};

use super::{RawEvent, Source};

const POLL_INTERVAL_MS: u64 = 100;
const BOOKMARK_INTERVAL_EVENTS: u64 = 100;

pub struct LogTailSource {
    id: String,
    path: PathBuf,
    from_beginning: bool,
}

impl LogTailSource {
    pub fn new(path: PathBuf, from_beginning: bool) -> anyhow::Result<Self> {
        let id = format!("log_tail:{}", path.display());
        Ok(Self {
            id,
            path,
            from_beginning,
        })
    }
}

#[async_trait]
impl Source for LogTailSource {
    fn id(&self) -> &str {
        &self.id
    }

    async fn run(
        self: Box<Self>,
        tx: mpsc::Sender<RawEvent>,
        shutdown: broadcast::Receiver<()>,
    ) -> anyhow::Result<()> {
        run_tail(
            self.id.clone(),
            self.path.clone(),
            self.from_beginning,
            tx,
            shutdown,
        )
        .await
    }
}

/// Inner runner, separated so tests can drive it without the trait
/// object dance.
pub(crate) async fn run_tail(
    source_id: String,
    path: PathBuf,
    from_beginning: bool,
    tx: mpsc::Sender<RawEvent>,
    mut shutdown: broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    let bookmark_path = bookmark_path_for(&path);
    let (mut file, mut inode) = open_at_start(&path, from_beginning, &bookmark_path).await?;
    let mut reader = BufReader::new(file);
    let mut buf = String::new();
    let mut position = reader.get_mut().stream_position().await?;
    let mut emitted_since_bookmark: u64 = 0;
    let mut file_watcher = file_change_watcher(&path);

    tracing::info!(
        source = %source_id,
        path = %path.display(),
        position,
        inode,
        "log_tail starting"
    );

    loop {
        buf.clear();
        tokio::select! {
            biased;
            _ = shutdown.recv() => {
                tracing::info!(source = %source_id, "log_tail shutting down");
                let _ = persist_bookmark(&bookmark_path, position, inode).await;
                return Ok(());
            }
            res = reader.read_line(&mut buf) => {
                match res {
                    Ok(0) => {
                        // EOF — wait for a file-change wakeup (or poll fallback),
                        // check rotation, then retry.
                        if wait_for_tail_wakeup(&mut file_watcher, &mut shutdown).await {
                            // Shutdown arrived during the wait.
                            tracing::info!(source = %source_id, "log_tail shutting down");
                            let _ = persist_bookmark(&bookmark_path, position, inode).await;
                            return Ok(());
                        }
                        if let Some((new_file, new_inode)) =
                            detect_rotation(&path, inode, position).await
                        {
                            tracing::info!(
                                source = %source_id,
                                old_inode = inode,
                                new_inode,
                                "log_tail: rotation detected, reopening"
                            );
                            file = new_file;
                            inode = new_inode;
                            position = 0;
                            reader = BufReader::new(file);
                            emitted_since_bookmark = 0;
                            let _ = persist_bookmark(&bookmark_path, position, inode).await;
                        }
                    }
                    Ok(n) => {
                        position += n as u64;
                        let evt = RawEvent {
                            source_id: source_id.clone(),
                            line: Bytes::copy_from_slice(buf.as_bytes()),
                            received_at: Utc::now(),
                        };
                        if tx.send(evt).await.is_err() {
                            tracing::info!(
                                source = %source_id,
                                "downstream closed; log_tail exiting"
                            );
                            let _ = persist_bookmark(&bookmark_path, position, inode).await;
                            return Ok(());
                        }
                        emitted_since_bookmark += 1;
                        if emitted_since_bookmark >= BOOKMARK_INTERVAL_EVENTS {
                            let _ = persist_bookmark(&bookmark_path, position, inode).await;
                            emitted_since_bookmark = 0;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(source = %source_id, error = %e, "log_tail read error");
                        return Err(e.into());
                    }
                }
            }
        }
    }
}

struct FileChangeWatcher {
    #[allow(dead_code)]
    watcher: notify::RecommendedWatcher,
    rx: mpsc::Receiver<()>,
}

fn file_change_watcher(path: &Path) -> Option<FileChangeWatcher> {
    let (tx, rx) = mpsc::channel(1);
    let mut watcher = match notify::recommended_watcher(
        move |event: notify::Result<notify::Event>| {
            if event.is_ok() {
                let _ = tx.try_send(());
            }
        },
    ) {
        Ok(watcher) => watcher,
        Err(e) => {
            tracing::debug!(path = %path.display(), error = %e, "log_tail notify watcher unavailable; polling");
            return None;
        }
    };
    let watch_path = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(path);
    if let Err(e) = watcher.watch(watch_path, notify::RecursiveMode::NonRecursive) {
        tracing::debug!(
            path = %path.display(),
            watch_path = %watch_path.display(),
            error = %e,
            "log_tail notify watch failed; polling"
        );
        return None;
    }
    Some(FileChangeWatcher { watcher, rx })
}

async fn wait_for_tail_wakeup(
    watcher: &mut Option<FileChangeWatcher>,
    shutdown: &mut broadcast::Receiver<()>,
) -> bool {
    let poll = tokio::time::sleep(tokio::time::Duration::from_millis(POLL_INTERVAL_MS));
    tokio::pin!(poll);

    if let Some(watcher) = watcher.as_mut() {
        tokio::select! {
            biased;
            _ = shutdown.recv() => true,
            _ = watcher.rx.recv() => false,
            _ = &mut poll => false,
        }
    } else {
        tokio::select! {
            biased;
            _ = shutdown.recv() => true,
            _ = &mut poll => false,
        }
    }
}

/// Bookmark path sits alongside the tailed file. Operators only need
/// to give us write access to the directory containing the log.
fn bookmark_path_for(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(".purple-wolf-relay.bookmark");
    PathBuf::from(p)
}

#[derive(Debug, Clone, Copy)]
struct Bookmark {
    inode: u64,
    position: u64,
}

async fn read_bookmark(path: &Path) -> Option<Bookmark> {
    let text = tokio::fs::read_to_string(path).await.ok()?;
    let mut parts = text.split_whitespace();
    let inode: u64 = parts.next()?.parse().ok()?;
    let position: u64 = parts.next()?.parse().ok()?;
    Some(Bookmark { inode, position })
}

async fn persist_bookmark(path: &Path, position: u64, inode: u64) -> anyhow::Result<()> {
    let tmp = {
        let mut p = path.as_os_str().to_owned();
        p.push(".tmp");
        PathBuf::from(p)
    };
    tokio::fs::write(&tmp, format!("{inode} {position}\n")).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

/// Open the file and decide the initial position. Bookmark resumes
/// only if its inode matches the current file's inode; otherwise it's
/// from a rotated-out file and we ignore it.
async fn open_at_start(
    path: &Path,
    from_beginning: bool,
    bookmark_path: &Path,
) -> anyhow::Result<(File, u64)> {
    let file = File::open(path).await?;
    let inode = inode_of(&file).await?;

    let mut file = file;
    if let Some(bm) = read_bookmark(bookmark_path).await {
        if bm.inode == inode {
            let len = file.metadata().await?.len();
            // Bookmark may be stale (file was truncated between
            // restarts). If the saved position is past EOF, treat as
            // EOF and proceed from there rather than blowing up.
            let pos = bm.position.min(len);
            file.seek(SeekFrom::Start(pos)).await?;
            return Ok((file, inode));
        }
    }
    if !from_beginning {
        file.seek(SeekFrom::End(0)).await?;
    }
    Ok((file, inode))
}

#[cfg(unix)]
async fn inode_of(file: &File) -> anyhow::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    Ok(file.metadata().await?.ino())
}
#[cfg(not(unix))]
async fn inode_of(_file: &File) -> anyhow::Result<u64> {
    // Best-effort placeholder for non-Unix targets. v0.3 is Linux/Mac
    // first-class; Windows support can refine this with the file-id
    // BY_HANDLE_FILE_INFORMATION call.
    Ok(0)
}

/// Detect rotation/truncation: returns the new file + inode if the
/// path now points to a different inode, or if the current file's
/// length shrank below our last position (truncation in place).
async fn detect_rotation(path: &Path, current_inode: u64, position: u64) -> Option<(File, u64)> {
    let new_file = File::open(path).await.ok()?;
    let new_inode = inode_of(&new_file).await.ok()?;
    if new_inode != current_inode {
        return Some((new_file, new_inode));
    }
    // Same inode — but the file may have been truncated in place.
    let len = new_file.metadata().await.ok()?.len();
    if len < position {
        return Some((new_file, new_inode));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::Duration;

    fn write_line(path: &Path, line: &str) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open append");
        writeln!(f, "{line}").unwrap();
    }

    #[tokio::test]
    async fn log_tail_emits_lines_appended_after_start() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        std::fs::write(&path, "preexisting\n").unwrap();

        let (tx, mut rx) = mpsc::channel(8);
        let (sd_tx, sd_rx) = broadcast::channel::<()>(1);
        let p = path.clone();
        let h = tokio::spawn(async move { run_tail("test".into(), p, false, tx, sd_rx).await });

        // Give the source a tick to open + seek-to-end.
        tokio::time::sleep(Duration::from_millis(150)).await;
        write_line(&path, "line2");

        let event = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("timed out waiting for line2")
            .expect("channel closed");
        assert_eq!(&event.line[..], b"line2\n");

        sd_tx.send(()).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), h).await;
    }

    #[tokio::test]
    async fn log_tail_from_beginning_emits_existing_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        std::fs::write(&path, "line1\nline2\n").unwrap();

        let (tx, mut rx) = mpsc::channel(8);
        let (sd_tx, sd_rx) = broadcast::channel::<()>(1);
        let p = path.clone();
        let h = tokio::spawn(async move { run_tail("test".into(), p, true, tx, sd_rx).await });

        let e1 = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let e2 = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&e1.line[..], b"line1\n");
        assert_eq!(&e2.line[..], b"line2\n");

        sd_tx.send(()).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), h).await;
    }

    /// Rotation: write line1, rename the file out, create a new file,
    /// append line2 to the new file, expect line2 to come through.
    /// macOS APFS supports rename across same-fs, so this works on
    /// dev laptops and Linux CI alike.
    #[tokio::test]
    async fn log_tail_survives_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        let rotated = dir.path().join("test.log.1");
        std::fs::write(&path, "line1\n").unwrap();

        let (tx, mut rx) = mpsc::channel(8);
        let (sd_tx, sd_rx) = broadcast::channel::<()>(1);
        let p = path.clone();
        let h = tokio::spawn(async move { run_tail("test".into(), p, false, tx, sd_rx).await });

        // Let it seek to end of the original file.
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Rotate: rename current file out, create a new one in its
        // place. This is the typical logrotate behavior.
        std::fs::rename(&path, &rotated).unwrap();
        std::fs::write(&path, "").unwrap();
        // Give the source a poll cycle to notice the rotation.
        tokio::time::sleep(Duration::from_millis(250)).await;
        write_line(&path, "line2");

        let event = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("timed out waiting for post-rotation line")
            .expect("channel closed");
        assert_eq!(&event.line[..], b"line2\n");

        sd_tx.send(()).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), h).await;
    }

    /// Bookmark resume: run the source, write lines, kill it; restart
    /// against the same file with `from_beginning: false` and assert
    /// previously-emitted lines do not re-emit (the bookmark wins).
    #[tokio::test]
    async fn log_tail_resumes_from_bookmark() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        std::fs::write(&path, "old\n").unwrap();

        // First run: from_beginning so we definitely emit `old`,
        // advancing the position; then write a bookmark via graceful
        // shutdown.
        let (tx1, mut rx1) = mpsc::channel(8);
        let (sd1_tx, sd1_rx) = broadcast::channel::<()>(1);
        let p1 = path.clone();
        let h1 = tokio::spawn(async move { run_tail("test".into(), p1, true, tx1, sd1_rx).await });
        let _ = tokio::time::timeout(Duration::from_secs(2), rx1.recv())
            .await
            .expect("first run didn't emit")
            .unwrap();
        sd1_tx.send(()).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), h1).await;

        // Append a new line while the source is "down".
        write_line(&path, "new");

        // Second run, from_beginning: true — but bookmark should win.
        let (tx2, mut rx2) = mpsc::channel(8);
        let (sd2_tx, sd2_rx) = broadcast::channel::<()>(1);
        let p2 = path.clone();
        let h2 = tokio::spawn(async move { run_tail("test".into(), p2, true, tx2, sd2_rx).await });

        let evt = tokio::time::timeout(Duration::from_secs(3), rx2.recv())
            .await
            .expect("second run didn't emit")
            .expect("channel closed");
        assert_eq!(
            &evt.line[..],
            b"new\n",
            "must skip the already-emitted line and resume at `new`"
        );

        sd2_tx.send(()).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), h2).await;
    }
}
