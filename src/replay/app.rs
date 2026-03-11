use crate::types::TraceEntry;

pub struct ReplayApp {
    pub session_id: String,
    pub entries: Vec<TraceEntry>,
    pub selected: usize,
    pub detail_view: bool,
    pub show_help: bool,
}

impl ReplayApp {
    pub fn new(session_id: String, entries: Vec<TraceEntry>) -> Self {
        ReplayApp {
            session_id,
            entries,
            selected: 0,
            detail_view: false,
            show_help: false,
        }
    }

    pub fn scroll_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    pub fn scroll_down(&mut self) {
        let max = self.entries.len().saturating_sub(1);
        if self.selected < max {
            self.selected += 1;
        }
    }

    pub fn jump_to_end(&mut self) {
        self.selected = self.entries.len().saturating_sub(1);
    }

    pub fn jump_to_start(&mut self) {
        self.selected = 0;
    }

    pub fn toggle_detail(&mut self) {
        self.detail_view = !self.detail_view;
    }

    pub fn summary(&self) -> ReplaySummary {
        let total = self.entries.len();
        let allowed = self.entries.iter().filter(|e| e.decision == "allow" || e.decision == "completed").count();
        let blocked = self.entries.iter().filter(|e| e.decision == "block").count();
        let approved = self.entries.iter().filter(|e| e.decision == "approve" || e.decision == "warn").count();

        let duration = if self.entries.len() >= 2 {
            let first = &self.entries[0].timestamp;
            let last = &self.entries[self.entries.len() - 1].timestamp;
            if let (Ok(f), Ok(l)) = (
                chrono::DateTime::parse_from_rfc3339(first),
                chrono::DateTime::parse_from_rfc3339(last),
            ) {
                let secs = l.signed_duration_since(f).num_seconds().max(0) as u64;
                format!("{}m {:02}s", secs / 60, secs % 60)
            } else {
                "?".to_string()
            }
        } else {
            "0s".to_string()
        };

        // Unique files touched
        let files: std::collections::HashSet<&str> = self.entries.iter()
            .filter(|e| matches!(e.tool.as_str(), "Write" | "Edit" | "Read"))
            .map(|e| e.input_summary.as_str())
            .collect();

        ReplaySummary {
            total,
            allowed,
            blocked,
            approved,
            duration,
            files_touched: files.len(),
        }
    }
}

pub struct ReplaySummary {
    pub total: usize,
    pub allowed: usize,
    pub blocked: usize,
    pub approved: usize,
    pub duration: String,
    pub files_touched: usize,
}
