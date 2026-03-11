use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileLock {
    pub file_path: String,
    pub session_id: String,
    pub pid: u32,
    pub acquired_at: String,
    pub last_heartbeat: String,
}

#[derive(Debug)]
pub struct LockConflict {
    pub file_path: String,
    pub held_by: String,
    pub last_active_secs: u64,
}

impl std::fmt::Display for LockConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let short = if self.held_by.len() > 4 {
            &self.held_by[self.held_by.len() - 4..]
        } else {
            &self.held_by
        };
        write!(
            f,
            "File locked by session ...{} (active {}s ago): {}",
            short, self.last_active_secs, self.file_path
        )
    }
}

const STALE_TIMEOUT_SECS: u64 = 60;

/// Return the global lock directory: ~/.railyard/locks
pub fn lock_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".railyard")
        .join("locks")
}

/// Deterministic lock file path for a given file path.
fn lock_file_path(lock_dir: &Path, file_path: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(file_path.as_bytes());
    let hash = hex::encode(hasher.finalize());
    lock_dir.join(format!("{}.json", &hash[..16]))
}

/// Canonicalize a file path best-effort (resolve symlinks, ../, etc).
fn canonicalize(file_path: &str) -> String {
    std::fs::canonicalize(file_path)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| file_path.to_string())
}

/// Check if a PID is still alive.
fn pid_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

/// Check if a lock is stale (heartbeat too old or PID dead).
pub fn is_stale(lock: &FileLock) -> bool {
    if !pid_alive(lock.pid) {
        return true;
    }
    let now = chrono::Utc::now();
    if let Ok(hb) = chrono::DateTime::parse_from_rfc3339(&lock.last_heartbeat) {
        let elapsed = now.signed_duration_since(hb).num_seconds();
        return elapsed > STALE_TIMEOUT_SECS as i64;
    }
    true // can't parse timestamp, treat as stale
}

/// Try to acquire a lock on a file for a session.
/// Returns Ok(()) if acquired (or already owned), Err(LockConflict) if held by another session.
pub fn acquire(file_path: &str, session_id: &str) -> Result<(), LockConflict> {
    let canonical = canonicalize(file_path);
    let dir = lock_dir();
    fs::create_dir_all(&dir).ok();

    let lock_path = lock_file_path(&dir, &canonical);
    let now = chrono::Utc::now().to_rfc3339();
    let pid = std::process::id();

    // Try atomic create
    match OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&lock_path)
    {
        Ok(mut f) => {
            let lock = FileLock {
                file_path: canonical,
                session_id: session_id.to_string(),
                pid,
                acquired_at: now.clone(),
                last_heartbeat: now,
            };
            let json = serde_json::to_string(&lock).unwrap_or_default();
            let _ = f.write_all(json.as_bytes());
            return Ok(());
        }
        Err(_) => {
            // File exists — check who owns it
        }
    }

    // Read existing lock
    let existing = match read_lock(&lock_path) {
        Some(l) => l,
        None => {
            // Can't read it — remove and retry once
            let _ = fs::remove_file(&lock_path);
            return acquire(file_path, session_id);
        }
    };

    // Same session — update heartbeat
    if existing.session_id == session_id {
        heartbeat_at(&lock_path, session_id, pid);
        return Ok(());
    }

    // Different session — check staleness
    if is_stale(&existing) {
        let _ = fs::remove_file(&lock_path);
        // Retry — only one concurrent caller will win the create_new
        return acquire_once(file_path, session_id);
    }

    // Lock is held by a live session
    let elapsed = {
        let now = chrono::Utc::now();
        chrono::DateTime::parse_from_rfc3339(&existing.last_heartbeat)
            .map(|hb| now.signed_duration_since(hb).num_seconds().max(0) as u64)
            .unwrap_or(0)
    };

    Err(LockConflict {
        file_path: canonical,
        held_by: existing.session_id,
        last_active_secs: elapsed,
    })
}

/// Single attempt to acquire (no recursive retry on stale).
fn acquire_once(file_path: &str, session_id: &str) -> Result<(), LockConflict> {
    let canonical = canonicalize(file_path);
    let dir = lock_dir();
    let lock_path = lock_file_path(&dir, &canonical);
    let now = chrono::Utc::now().to_rfc3339();
    let pid = std::process::id();

    match OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&lock_path)
    {
        Ok(mut f) => {
            let lock = FileLock {
                file_path: canonical,
                session_id: session_id.to_string(),
                pid,
                acquired_at: now.clone(),
                last_heartbeat: now,
            };
            let json = serde_json::to_string(&lock).unwrap_or_default();
            let _ = f.write_all(json.as_bytes());
            Ok(())
        }
        Err(_) => {
            // Someone else won the race
            let existing = read_lock(&lock_path).unwrap_or(FileLock {
                file_path: canonical.clone(),
                session_id: "unknown".to_string(),
                pid: 0,
                acquired_at: now.clone(),
                last_heartbeat: now,
            });
            Err(LockConflict {
                file_path: canonical,
                held_by: existing.session_id,
                last_active_secs: 0,
            })
        }
    }
}

/// Update the heartbeat timestamp for a lock.
pub fn heartbeat(file_path: &str, session_id: &str) {
    let canonical = canonicalize(file_path);
    let dir = lock_dir();
    let lock_path = lock_file_path(&dir, &canonical);
    let pid = std::process::id();
    heartbeat_at(&lock_path, session_id, pid);
}

fn heartbeat_at(lock_path: &Path, session_id: &str, pid: u32) {
    if let Some(mut lock) = read_lock(lock_path) {
        if lock.session_id == session_id {
            lock.last_heartbeat = chrono::Utc::now().to_rfc3339();
            lock.pid = pid;
            write_lock(lock_path, &lock);
        }
    }
}

/// Release a specific file lock if owned by this session.
pub fn release(file_path: &str, session_id: &str) {
    let canonical = canonicalize(file_path);
    let dir = lock_dir();
    let lock_path = lock_file_path(&dir, &canonical);

    if let Some(lock) = read_lock(&lock_path) {
        if lock.session_id == session_id {
            let _ = fs::remove_file(&lock_path);
        }
    }
}

/// Release all locks held by a session.
pub fn release_all(session_id: &str) {
    let dir = lock_dir();
    if !dir.exists() {
        return;
    }
    for lock in list_locks() {
        if lock.session_id == session_id {
            let lock_path = lock_file_path(&dir, &lock.file_path);
            let _ = fs::remove_file(&lock_path);
        }
    }
}

/// List all current locks.
pub fn list_locks() -> Vec<FileLock> {
    let dir = lock_dir();
    if !dir.exists() {
        return vec![];
    }

    let mut locks = Vec::new();
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "json") {
                if let Some(lock) = read_lock(&path) {
                    locks.push(lock);
                }
            }
        }
    }
    locks
}

/// List all active (non-stale) locks, cleaning up stale ones.
pub fn list_active_locks() -> Vec<FileLock> {
    let dir = lock_dir();
    let locks = list_locks();
    let mut active = Vec::new();

    for lock in locks {
        if is_stale(&lock) {
            // Clean up stale lock
            let lock_path = lock_file_path(&dir, &lock.file_path);
            let _ = fs::remove_file(&lock_path);
        } else {
            active.push(lock);
        }
    }
    active
}

/// Get all locks for a specific session.
pub fn locks_for_session(session_id: &str) -> Vec<FileLock> {
    list_active_locks()
        .into_iter()
        .filter(|l| l.session_id == session_id)
        .collect()
}

fn read_lock(path: &Path) -> Option<FileLock> {
    let data = fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

fn write_lock(path: &Path, lock: &FileLock) {
    let tmp = path.with_extension("tmp");
    if let Ok(json) = serde_json::to_string(lock) {
        if fs::write(&tmp, json).is_ok() {
            let _ = fs::rename(&tmp, path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn with_lock_dir(f: impl FnOnce(&Path)) {
        let dir = TempDir::new().unwrap();
        // Override lock_dir for testing by using the functions directly
        f(dir.path());
    }

    #[test]
    fn test_lock_file_path_deterministic() {
        let dir = Path::new("/tmp/test-locks");
        let p1 = lock_file_path(dir, "/foo/bar.rs");
        let p2 = lock_file_path(dir, "/foo/bar.rs");
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_lock_file_path_different_files() {
        let dir = Path::new("/tmp/test-locks");
        let p1 = lock_file_path(dir, "/foo/bar.rs");
        let p2 = lock_file_path(dir, "/foo/baz.rs");
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_stale_lock_detection() {
        let lock = FileLock {
            file_path: "/test".to_string(),
            session_id: "s1".to_string(),
            pid: 999999999, // non-existent PID
            acquired_at: "2020-01-01T00:00:00Z".to_string(),
            last_heartbeat: "2020-01-01T00:00:00Z".to_string(),
        };
        assert!(is_stale(&lock));
    }

    #[test]
    fn test_fresh_lock_not_stale() {
        let lock = FileLock {
            file_path: "/test".to_string(),
            session_id: "s1".to_string(),
            pid: std::process::id(), // our own PID — alive
            acquired_at: chrono::Utc::now().to_rfc3339(),
            last_heartbeat: chrono::Utc::now().to_rfc3339(),
        };
        assert!(!is_stale(&lock));
    }

    #[test]
    fn test_acquire_and_release() {
        // Use a unique file path to avoid test interference
        let test_file = format!("/tmp/railyard-test-{}", std::process::id());
        let session = "test-session-acquire";

        // Acquire
        assert!(acquire(&test_file, session).is_ok());

        // Same session can re-acquire (idempotent)
        assert!(acquire(&test_file, session).is_ok());

        // Release
        release(&test_file, session);

        // After release, another session can acquire
        assert!(acquire(&test_file, "other-session").is_ok());
        release(&test_file, "other-session");
    }

    #[test]
    fn test_conflict_detection() {
        let test_file = format!("/tmp/railyard-test-conflict-{}", std::process::id());
        let session_a = "session-a-conflict";
        let session_b = "session-b-conflict";

        // Session A acquires
        assert!(acquire(&test_file, session_a).is_ok());

        // Session B gets conflict
        let result = acquire(&test_file, session_b);
        assert!(result.is_err());

        let conflict = result.unwrap_err();
        assert_eq!(conflict.held_by, session_a);

        // Clean up
        release(&test_file, session_a);
    }

    #[test]
    fn test_release_all() {
        let base = format!("/tmp/railyard-test-releaseall-{}", std::process::id());
        let session = "session-releaseall";

        acquire(&format!("{}-a", base), session).ok();
        acquire(&format!("{}-b", base), session).ok();

        let locks = locks_for_session(session);
        assert!(locks.len() >= 2);

        release_all(session);

        let locks = locks_for_session(session);
        assert_eq!(locks.len(), 0);
    }
}
