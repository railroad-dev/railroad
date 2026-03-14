use std::fs;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::types::MemoryEntry;

/// Directory where provenance data is stored.
fn provenance_dir(cwd: &Path) -> PathBuf {
    cwd.join(".railroad/memory")
}

/// Path to the provenance manifest file.
fn provenance_path(cwd: &Path) -> PathBuf {
    provenance_dir(cwd).join("provenance.jsonl")
}

/// Compute SHA256 hash of content.
pub fn hash_content(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hex::encode(hasher.finalize())
}

/// Record a memory write in the provenance manifest.
pub fn sign(
    cwd: &Path,
    session_id: &str,
    file_path: &str,
    content: &str,
    classification: &str,
    human_approved: bool,
) -> Result<MemoryEntry, String> {
    let dir = provenance_dir(cwd);
    fs::create_dir_all(&dir).map_err(|e| format!("Failed to create provenance dir: {}", e))?;

    let entry = MemoryEntry {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        session_id: session_id.to_string(),
        file_path: file_path.to_string(),
        content_hash: hash_content(content),
        classification: classification.to_string(),
        human_approved,
        provenance: if human_approved {
            "human-confirmed".to_string()
        } else {
            "agent-created".to_string()
        },
    };

    let path = provenance_path(cwd);
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("Failed to open provenance file: {}", e))?;

    let json =
        serde_json::to_string(&entry).map_err(|e| format!("Failed to serialize entry: {}", e))?;
    writeln!(file, "{}", json).map_err(|e| format!("Failed to write provenance: {}", e))?;

    Ok(entry)
}

/// Load all provenance entries.
pub fn load_entries(cwd: &Path) -> Vec<MemoryEntry> {
    let path = provenance_path(cwd);
    let file = match fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => return vec![],
    };

    let reader = std::io::BufReader::new(file);
    let mut entries = Vec::new();
    for line in reader.lines() {
        if let Ok(line) = line {
            if let Ok(entry) = serde_json::from_str::<MemoryEntry>(&line) {
                entries.push(entry);
            }
        }
    }
    entries
}

/// Get the latest provenance entry for a given file path.
pub fn latest_entry_for_file(cwd: &Path, file_path: &str) -> Option<MemoryEntry> {
    let entries = load_entries(cwd);
    entries
        .into_iter()
        .filter(|e| e.file_path == file_path)
        .last()
}

/// Verify integrity of all memory files.
/// Returns a list of (file_path, issue) for any tampered or untracked files.
pub fn verify_all(cwd: &Path, memory_dir: &Path) -> Vec<(String, String)> {
    let mut issues = Vec::new();

    // Scan all .md files in the memory directory
    let md_files = match glob::glob(&format!("{}/**/*.md", memory_dir.display())) {
        Ok(paths) => paths,
        Err(_) => return issues,
    };

    for entry in md_files.flatten() {
        let file_path = entry.display().to_string();

        // Skip MEMORY.md index file
        if entry
            .file_name()
            .map(|f| f == "MEMORY.md")
            .unwrap_or(false)
        {
            continue;
        }

        let content = match fs::read_to_string(&entry) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let current_hash = hash_content(&content);

        match latest_entry_for_file(cwd, &file_path) {
            Some(prov_entry) => {
                if prov_entry.content_hash != current_hash {
                    issues.push((
                        file_path,
                        "modified outside guarded session".to_string(),
                    ));
                }
            }
            None => {
                issues.push((file_path, "no provenance record (untracked)".to_string()));
            }
        }
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_content() {
        let hash = hash_content("hello world");
        assert_eq!(hash.len(), 64); // SHA256 hex is 64 chars
        // Same content should produce same hash
        assert_eq!(hash, hash_content("hello world"));
        // Different content should produce different hash
        assert_ne!(hash, hash_content("hello world!"));
    }

    #[test]
    fn test_sign_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();

        let entry = sign(
            cwd,
            "session-123",
            "/tmp/test_memory.md",
            "Project uses PostgreSQL",
            "factual",
            false,
        )
        .unwrap();

        assert_eq!(entry.session_id, "session-123");
        assert_eq!(entry.classification, "factual");
        assert!(!entry.human_approved);
        assert_eq!(entry.provenance, "agent-created");

        let entries = load_entries(cwd);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].file_path, "/tmp/test_memory.md");
    }

    #[test]
    fn test_latest_entry_for_file() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();

        sign(cwd, "s1", "/tmp/a.md", "v1", "factual", false).unwrap();
        sign(cwd, "s2", "/tmp/a.md", "v2", "factual", false).unwrap();
        sign(cwd, "s1", "/tmp/b.md", "other", "factual", false).unwrap();

        let latest = latest_entry_for_file(cwd, "/tmp/a.md").unwrap();
        assert_eq!(latest.session_id, "s2");
        assert_eq!(latest.content_hash, hash_content("v2"));
    }
}
