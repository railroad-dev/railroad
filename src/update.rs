use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, Duration};

const REMOTE_URL: &str = "https://github.com/railyarddev/railyard.git";
const CHECK_INTERVAL: Duration = Duration::from_secs(7 * 24 * 60 * 60); // 1 week
const BUILD_HASH: &str = env!("RAILYARD_GIT_HASH");

/// Check if a newer version of Railyard is available.
/// Runs at most once per week. Returns a message if an update exists.
pub fn check_for_update(cwd: &Path) -> Option<String> {
    let marker = cwd.join(".railyard/last-update-check");

    // Rate limit: skip if checked recently
    if let Ok(meta) = fs::metadata(&marker) {
        if let Ok(modified) = meta.modified() {
            if let Ok(elapsed) = SystemTime::now().duration_since(modified) {
                if elapsed < CHECK_INTERVAL {
                    return None;
                }
            }
        }
    }

    // Touch the marker file regardless of outcome
    let _ = fs::create_dir_all(cwd.join(".railyard"));
    let _ = fs::write(&marker, "");

    // Get latest commit hash from remote
    let output = Command::new("git")
        .args(["ls-remote", REMOTE_URL, "refs/heads/main"])
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let remote_hash = String::from_utf8(output.stdout)
        .ok()?
        .split_whitespace()
        .next()?
        .to_string();

    // Compare with build hash
    if BUILD_HASH == "unknown" || remote_hash.starts_with(BUILD_HASH) || BUILD_HASH.starts_with(&remote_hash) {
        return None;
    }

    Some(
        "A new version of Railyard is available. \
         Run `cargo install --git https://github.com/railyarddev/railyard.git` to update."
            .to_string(),
    )
}
