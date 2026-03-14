use std::path::Path;

use crate::memory::{classifier, conflict, provenance};
use crate::types::{MemoryClassification, MemoryConfig, MemoryDecision};

/// Pattern to identify Claude Code memory paths.
/// Memory files live under ~/.claude/projects/*/memory/
const MEMORY_PATH_PATTERN: &str = ".claude/projects/";
const MEMORY_DIR_SEGMENT: &str = "/memory/";
const MEMORY_INDEX: &str = "MEMORY.md";

/// Check if a file path is a Claude Code memory path.
pub fn is_memory_path(file_path: &str) -> bool {
    // Expand ~ to home dir for matching
    let expanded = if file_path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            format!("{}{}", home.display(), &file_path[1..])
        } else {
            file_path.to_string()
        }
    } else {
        file_path.to_string()
    };

    expanded.contains(MEMORY_PATH_PATTERN) && expanded.contains(MEMORY_DIR_SEGMENT)
}

/// Check a memory write operation and decide whether to allow, block, or ask.
pub fn check_memory_write(
    config: &MemoryConfig,
    tool_name: &str,
    file_path: &str,
    tool_input: &serde_json::Value,
    session_id: &str,
    cwd: &Path,
) -> MemoryDecision {
    if !config.enabled {
        return MemoryDecision::Allow;
    }

    // Extract content from the tool input
    let content = extract_content(tool_name, tool_input);

    // For Read operations, just verify integrity and allow
    if tool_name == "Read" {
        if config.verify_on_read {
            if let Some(entry) = provenance::latest_entry_for_file(cwd, file_path) {
                if let Ok(current_content) = std::fs::read_to_string(file_path) {
                    let current_hash = provenance::hash_content(&current_content);
                    if entry.content_hash != current_hash {
                        // File was tampered — still allow read, but this will be reported at session start
                    }
                }
            }
        }
        return MemoryDecision::Allow;
    }

    // Check for Bash rm commands targeting memory files
    if tool_name == "Bash" {
        if let Some(cmd) = tool_input.get("command").and_then(|v| v.as_str()) {
            if is_memory_delete_command(cmd) {
                return MemoryDecision::Block(
                    "Memory Safety: Agents cannot delete memory files. Memory is append-only."
                        .to_string(),
                );
            }
        }
        // Other bash commands touching memory paths — block
        return MemoryDecision::Block(
            "Memory Safety: Memory files must be managed through Write/Edit tools, not Bash."
                .to_string(),
        );
    }

    // For Write/Edit, get the content to classify
    let content = match content {
        Some(c) => c,
        None => {
            // Can't determine content — ask for approval
            return MemoryDecision::Approve(
                "Memory Safety: Cannot determine memory content — requires approval.".to_string(),
            );
        }
    };

    // === CONTENT CLASSIFICATION ===
    let classification = classifier::classify(&content);

    match classification {
        MemoryClassification::Secret => {
            if config.block_secrets {
                return MemoryDecision::Block(
                    "Memory Safety: Memory contains secrets or credentials. \
                     Secrets must not be stored in memory files."
                        .to_string(),
                );
            }
        }
        MemoryClassification::Behavioral => {
            if config.require_approval_for_behavioral {
                return MemoryDecision::Approve(format!(
                    "Memory Safety: Memory contains behavioral directives that will influence future sessions. \
                     Content: {}",
                    truncate(&content, 200)
                ));
            }
        }
        MemoryClassification::Factual => {
            // Factual content — continue to further checks
        }
    }

    // === APPEND-ONLY GUARD ===
    if config.append_only && (tool_name == "Edit" || tool_name == "Write") {
        let file_exists = Path::new(file_path).exists();
        if file_exists {
            // Check if this is MEMORY.md (the index) — allow edits to it
            if file_path.ends_with(MEMORY_INDEX) {
                // Allow index updates
            } else if tool_name == "Write" {
                // Full overwrite of existing memory — requires approval
                return MemoryDecision::Approve(format!(
                    "Memory Safety: Agent wants to overwrite existing memory file '{}'. \
                     Memory is append-only — modifications require approval.",
                    short_path(file_path)
                ));
            } else if tool_name == "Edit" {
                // Edit of existing memory — requires approval
                return MemoryDecision::Approve(format!(
                    "Memory Safety: Agent wants to modify existing memory file '{}'. \
                     Memory is append-only — modifications require approval.",
                    short_path(file_path)
                ));
            }
        }
    }

    // === CONFLICT DETECTION ===
    if let Some(memory_dir) = extract_memory_dir(file_path) {
        if let Some((conflicting_file, reason)) =
            conflict::check_conflicts(Path::new(&memory_dir), file_path, &content)
        {
            return MemoryDecision::Approve(format!(
                "Memory Safety: Potential conflict detected. {} (conflicts with '{}')",
                reason,
                short_path(&conflicting_file)
            ));
        }
    }

    // === SIGN PROVENANCE ===
    let classification_label = classifier::classification_label(&classification);
    let _ = provenance::sign(
        cwd,
        session_id,
        file_path,
        &content,
        classification_label,
        false, // not human-approved (auto-allowed)
    );

    MemoryDecision::Allow
}

/// Handle post-approval provenance signing.
/// Call this after a human approves a memory write.
pub fn sign_approved_write(
    cwd: &Path,
    session_id: &str,
    file_path: &str,
    content: &str,
    classification: &str,
) {
    let _ = provenance::sign(cwd, session_id, file_path, content, classification, true);
}

/// Verify all memory files and return warnings for tampered ones.
pub fn verify_memory_integrity(cwd: &Path) -> Vec<String> {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return vec![],
    };

    let claude_projects = home.join(".claude/projects");
    if !claude_projects.exists() {
        return vec![];
    }

    let mut warnings = Vec::new();

    // Scan all project memory directories
    let pattern = format!("{}/**/memory", claude_projects.display());
    if let Ok(paths) = glob::glob(&pattern) {
        for memory_dir in paths.flatten() {
            if memory_dir.is_dir() {
                let issues = provenance::verify_all(cwd, &memory_dir);
                for (file_path, issue) in issues {
                    warnings.push(format!("{}: {}", short_path(&file_path), issue));
                }
            }
        }
    }

    warnings
}

/// Extract content from tool input based on tool type.
fn extract_content(tool_name: &str, tool_input: &serde_json::Value) -> Option<String> {
    match tool_name {
        "Write" => tool_input
            .get("content")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        "Edit" => {
            // For edits, we care about the new_string being introduced
            tool_input
                .get("new_string")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        }
        _ => None,
    }
}

/// Check if a bash command is trying to delete memory files.
fn is_memory_delete_command(cmd: &str) -> bool {
    let delete_patterns = [r"\brm\s+", r"\bunlink\s+", r"\bmv\s+.*\s+/dev/null"];
    for pattern in &delete_patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if re.is_match(cmd) {
                return true;
            }
        }
    }
    false
}

/// Extract the memory directory from a memory file path.
fn extract_memory_dir(file_path: &str) -> Option<String> {
    if let Some(idx) = file_path.rfind("/memory/") {
        Some(file_path[..idx + 8].to_string())
    } else {
        None
    }
}

/// Shorten a path for display by showing just the relevant parts.
fn short_path(path: &str) -> String {
    if let Some(idx) = path.find(".claude/projects/") {
        format!("~/{}", &path[idx..])
    } else if let Some(idx) = path.rfind("/memory/") {
        path[idx + 1..].to_string()
    } else {
        path.to_string()
    }
}

/// Truncate a string for display.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_memory_path() {
        let home = dirs::home_dir().unwrap();
        let path = format!(
            "{}/.claude/projects/-Users-test-myproject/memory/db_info.md",
            home.display()
        );
        assert!(is_memory_path(&path));
    }

    #[test]
    fn test_is_memory_path_tilde() {
        assert!(is_memory_path(
            "~/.claude/projects/-Users-test-myproject/memory/db_info.md"
        ));
    }

    #[test]
    fn test_not_memory_path() {
        assert!(!is_memory_path("/tmp/some_file.md"));
        assert!(!is_memory_path(
            "/Users/test/.claude/settings.json"
        ));
        assert!(!is_memory_path(
            "/Users/test/.claude/projects/-Users-test/CLAUDE.md"
        ));
    }

    #[test]
    fn test_extract_memory_dir() {
        assert_eq!(
            extract_memory_dir("/Users/test/.claude/projects/foo/memory/bar.md"),
            Some("/Users/test/.claude/projects/foo/memory/".to_string())
        );
    }

    #[test]
    fn test_short_path() {
        let path = "/Users/test/.claude/projects/-Users-test/memory/db_info.md";
        assert_eq!(
            short_path(path),
            "~/.claude/projects/-Users-test/memory/db_info.md"
        );
    }

    #[test]
    fn test_block_secrets() {
        let config = MemoryConfig::default();
        let cwd = Path::new("/tmp");
        let tool_input = serde_json::json!({
            "file_path": "/Users/test/.claude/projects/foo/memory/secret.md",
            "content": "The API key is sk-ant-abc123def456ghi789jkl012mno345pqr"
        });

        let decision =
            check_memory_write(&config, "Write", "/tmp/memory/secret.md", &tool_input, "s1", cwd);
        assert!(matches!(decision, MemoryDecision::Block(_)));
    }

    #[test]
    fn test_approve_behavioral() {
        let config = MemoryConfig::default();
        let cwd = Path::new("/tmp");
        let tool_input = serde_json::json!({
            "file_path": "/tmp/memory/feedback.md",
            "content": "---\nname: test\ntype: feedback\n---\nAlways use snake_case."
        });

        let decision = check_memory_write(
            &config,
            "Write",
            "/tmp/memory/feedback.md",
            &tool_input,
            "s1",
            cwd,
        );
        assert!(matches!(decision, MemoryDecision::Approve(_)));
    }

    #[test]
    fn test_allow_factual() {
        let config = MemoryConfig::default();
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();
        let tool_input = serde_json::json!({
            "file_path": "/tmp/memory/project.md",
            "content": "---\nname: db\ntype: project\n---\nUses PostgreSQL 15."
        });

        let decision = check_memory_write(
            &config,
            "Write",
            "/tmp/memory/project.md",
            &tool_input,
            "s1",
            cwd,
        );
        assert!(matches!(decision, MemoryDecision::Allow));
    }

    #[test]
    fn test_block_bash_delete() {
        let config = MemoryConfig::default();
        let cwd = Path::new("/tmp");
        let tool_input = serde_json::json!({
            "command": "rm ~/.claude/projects/foo/memory/old.md"
        });

        let decision =
            check_memory_write(&config, "Bash", "/tmp/memory/old.md", &tool_input, "s1", cwd);
        assert!(matches!(decision, MemoryDecision::Block(_)));
    }

    #[test]
    fn test_disabled_config() {
        let config = MemoryConfig {
            enabled: false,
            ..Default::default()
        };
        let cwd = Path::new("/tmp");
        let tool_input = serde_json::json!({
            "file_path": "/tmp/memory/secret.md",
            "content": "api_key: sk-ant-abc123def456ghi789jkl012mno345pqr"
        });

        let decision =
            check_memory_write(&config, "Write", "/tmp/memory/secret.md", &tool_input, "s1", cwd);
        assert!(matches!(decision, MemoryDecision::Allow));
    }

    #[test]
    fn test_is_memory_delete_command() {
        assert!(is_memory_delete_command("rm ~/.claude/projects/foo/memory/old.md"));
        assert!(is_memory_delete_command("rm -f /path/to/memory.md"));
        assert!(!is_memory_delete_command("cat /path/to/memory.md"));
    }
}
