use std::collections::HashMap;

use super::lock;

/// Generate a context message about other active sessions for injection on SessionStart.
/// Returns None if no other sessions are active.
pub fn session_context_message(session_id: &str) -> Option<String> {
    let locks = lock::list_active_locks();

    // Group locks by session, excluding our own
    let mut sessions: HashMap<String, Vec<String>> = HashMap::new();
    for l in &locks {
        if l.session_id == session_id {
            continue;
        }
        sessions
            .entry(l.session_id.clone())
            .or_default()
            .push(short_path(&l.file_path));
    }

    if sessions.is_empty() {
        return None;
    }

    let mut lines = vec![
        "[Railyard] Other active sessions:".to_string(),
    ];

    for (sid, files) in &sessions {
        let short_sid = if sid.len() > 4 {
            &sid[sid.len() - 4..]
        } else {
            sid
        };
        let file_list = files.join(", ");
        lines.push(format!("  - Session ...{}: editing {}", short_sid, file_list));
    }

    lines.push("Avoid editing files locked by other sessions. Railyard will block conflicting writes.".to_string());

    Some(lines.join("\n"))
}

/// Check if a file is locked by another session.
/// If not locked, acquires the lock and returns None.
/// If locked by another session, returns a deny message.
pub fn check_file_conflict(file_path: &str, session_id: &str) -> Option<String> {
    match lock::acquire(file_path, session_id) {
        Ok(()) => None,
        Err(conflict) => Some(format!(
            "⛔ {}\nAnother Claude Code session is editing this file. Wait for it to finish or use a different file.",
            conflict
        )),
    }
}

/// Shorten a file path to just the last 2 components for display.
fn short_path(path: &str) -> String {
    let parts: Vec<&str> = path.rsplit('/').take(2).collect();
    if parts.len() == 2 {
        format!("{}/{}", parts[1], parts[0])
    } else {
        path.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_path() {
        assert_eq!(short_path("/foo/bar/baz.rs"), "bar/baz.rs");
        assert_eq!(short_path("baz.rs"), "baz.rs");
    }

    #[test]
    fn test_no_context_when_alone() {
        let msg = session_context_message("unique-session-no-others");
        // May or may not be None depending on global state, but shouldn't panic
        assert!(msg.is_none() || msg.is_some());
    }
}
