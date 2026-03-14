use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// Check if a new memory file might conflict with existing memories.
/// Returns Some((conflicting_file, reason)) if a conflict is detected.
pub fn check_conflicts(
    memory_dir: &Path,
    new_file_path: &str,
    new_content: &str,
) -> Option<(String, String)> {
    let new_keywords = extract_keywords_from_content(new_content);
    if new_keywords.is_empty() {
        return None;
    }

    let new_name = extract_frontmatter_field(new_content, "name");
    let new_description = extract_frontmatter_field(new_content, "description");

    // Scan existing memory files
    let md_files = match glob::glob(&format!("{}/**/*.md", memory_dir.display())) {
        Ok(paths) => paths,
        Err(_) => return None,
    };

    for entry in md_files.flatten() {
        let existing_path = entry.display().to_string();

        // Skip the file being written (in case of overwrite)
        if existing_path == new_file_path {
            continue;
        }

        // Skip MEMORY.md index
        if entry
            .file_name()
            .map(|f| f == "MEMORY.md")
            .unwrap_or(false)
        {
            continue;
        }

        let existing_content = match fs::read_to_string(&entry) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let existing_keywords = extract_keywords_from_content(&existing_content);
        if existing_keywords.is_empty() {
            continue;
        }

        // Calculate keyword overlap
        let overlap: HashSet<_> = new_keywords.intersection(&existing_keywords).collect();
        let total = new_keywords.len().min(existing_keywords.len());

        if total > 0 {
            let overlap_ratio = overlap.len() as f64 / total as f64;
            if overlap_ratio > 0.5 {
                // Also check if names/descriptions are similar
                let existing_name = extract_frontmatter_field(&existing_content, "name");

                let file_name = entry
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_default();

                let reason = if new_name.is_some()
                    && existing_name.is_some()
                    && new_name == existing_name
                {
                    format!(
                        "New memory has same name '{}' as existing memory '{}'",
                        new_name.unwrap(),
                        file_name
                    )
                } else {
                    let shared: Vec<_> = overlap.into_iter().take(5).cloned().collect();
                    let desc_note = if let Some(ref desc) = new_description {
                        format!(" ({})", desc)
                    } else {
                        String::new()
                    };
                    format!(
                        "New memory{} shares significant keyword overlap with '{}': [{}]",
                        desc_note,
                        file_name,
                        shared.join(", ")
                    )
                };

                return Some((existing_path, reason));
            }
        }
    }

    None
}

/// Extract meaningful keywords from memory content (name, description, body).
fn extract_keywords_from_content(content: &str) -> HashSet<String> {
    let mut keywords = HashSet::new();

    // Extract from frontmatter fields
    if let Some(name) = extract_frontmatter_field(content, "name") {
        for word in tokenize(&name) {
            keywords.insert(word);
        }
    }
    if let Some(desc) = extract_frontmatter_field(content, "description") {
        for word in tokenize(&desc) {
            keywords.insert(word);
        }
    }

    // Extract from body (after frontmatter)
    let body = strip_frontmatter(content);
    for word in tokenize(&body) {
        keywords.insert(word);
    }

    keywords
}

/// Extract a field value from YAML frontmatter.
fn extract_frontmatter_field(content: &str, field: &str) -> Option<String> {
    let trimmed = content.trim_start();
    if !trimmed.starts_with("---") {
        return None;
    }
    if let Some(end) = trimmed[3..].find("---") {
        let frontmatter = &trimmed[3..3 + end];
        let pattern = format!(r"(?m)^\s*{}:\s*(.+?)\s*$", regex::escape(field));
        if let Ok(re) = regex::Regex::new(&pattern) {
            if let Some(caps) = re.captures(frontmatter) {
                return caps.get(1).map(|m| m.as_str().to_string());
            }
        }
    }
    None
}

/// Strip YAML frontmatter from content, returning the body.
fn strip_frontmatter(content: &str) -> String {
    let trimmed = content.trim_start();
    if !trimmed.starts_with("---") {
        return content.to_string();
    }
    if let Some(end) = trimmed[3..].find("---") {
        trimmed[3 + end + 3..].to_string()
    } else {
        content.to_string()
    }
}

/// Tokenize text into lowercase words, filtering noise.
fn tokenize(text: &str) -> Vec<String> {
    let stop_words: HashSet<&str> = [
        "the", "a", "an", "is", "are", "was", "were", "be", "been", "being", "have", "has",
        "had", "do", "does", "did", "will", "would", "could", "should", "may", "might", "shall",
        "can", "to", "of", "in", "for", "on", "with", "at", "by", "from", "as", "into",
        "through", "during", "before", "after", "above", "below", "between", "out", "off", "over",
        "under", "and", "but", "or", "nor", "not", "so", "yet", "both", "either", "neither",
        "each", "every", "all", "any", "few", "more", "most", "other", "some", "such", "no",
        "only", "own", "same", "than", "too", "very", "this", "that", "these", "those", "it",
        "its",
    ]
    .into_iter()
    .collect();

    text.split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_')
        .map(|w| w.to_lowercase())
        .filter(|w| w.len() > 2 && !stop_words.contains(w.as_str()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_frontmatter_field() {
        let content = "---\nname: test-memory\ntype: project\n---\nBody here.";
        assert_eq!(
            extract_frontmatter_field(content, "name"),
            Some("test-memory".to_string())
        );
        assert_eq!(
            extract_frontmatter_field(content, "type"),
            Some("project".to_string())
        );
        assert_eq!(extract_frontmatter_field(content, "missing"), None);
    }

    #[test]
    fn test_strip_frontmatter() {
        let content = "---\nname: test\n---\nBody content here.";
        assert_eq!(strip_frontmatter(content), "\nBody content here.");
    }

    #[test]
    fn test_tokenize() {
        let tokens = tokenize("This project uses PostgreSQL for the database");
        assert!(tokens.contains(&"project".to_string()));
        assert!(tokens.contains(&"postgresql".to_string()));
        assert!(tokens.contains(&"database".to_string()));
        // Stop words filtered
        assert!(!tokens.contains(&"the".to_string()));
        assert!(!tokens.contains(&"for".to_string()));
    }

    #[test]
    fn test_conflict_detection() {
        let dir = tempfile::tempdir().unwrap();
        let memory_dir = dir.path();

        // Create an existing memory file
        let existing = memory_dir.join("db-info.md");
        std::fs::write(
            &existing,
            "---\nname: db-info\ndescription: Database configuration for project\ntype: project\n---\nThis project uses PostgreSQL database for primary storage configuration.",
        )
        .unwrap();

        // New memory with heavily overlapping content
        let new_content = "---\nname: db-info\ndescription: Database configuration for project\ntype: project\n---\nThe project uses PostgreSQL database for primary storage configuration.";

        let conflict = check_conflicts(memory_dir, "/new/memory.md", new_content);
        assert!(conflict.is_some());
    }

    #[test]
    fn test_no_conflict_different_topics() {
        let dir = tempfile::tempdir().unwrap();
        let memory_dir = dir.path();

        let existing = memory_dir.join("db-info.md");
        std::fs::write(
            &existing,
            "---\nname: db-info\ntype: project\n---\nThis project uses PostgreSQL for the database.",
        )
        .unwrap();

        let new_content =
            "---\nname: deploy-process\ntype: project\n---\nDeployments go through GitHub Actions CI/CD pipeline.";

        let conflict = check_conflicts(memory_dir, "/new/memory.md", new_content);
        assert!(conflict.is_none());
    }
}
