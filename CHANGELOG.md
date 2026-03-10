# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-03-09

Initial release.

### Features

- **Smart defaults:** destructive commands require approval, evasion attempts are hard-blocked, everything else flows through instantly
- **Command blocking:** 13 default rules covering terraform destroy, rm -rf, DROP TABLE, git force-push, drizzle-kit push --force, and more
- **Evasion detection:** base64 decoding, variable expansion, shell unwrapping, hex decoding, eval concatenation, multi-variable concat, rev|sh shape detection, Python/Ruby interpreter obfuscation
- **Threat escalation:** 3-tier system — pattern detection (Tier 1, instant kill), behavioral analysis (Tier 2, warn then kill), retry detection (Tier 3)
- **Path fencing:** restrict agent to project directory, deny ~/.ssh, ~/.aws, ~/.gnupg, /etc
- **OS-level sandboxing:** `railyard-shell` binary transparently wraps every Bash command in `sandbox-exec` (macOS) or `bwrap` (Linux)
- **Sandbox launcher:** `railyard` / `railyard launch` wraps entire Claude Code process in kernel sandbox
- **Snapshots & rollback:** per-edit file backups with undo by steps, file, snapshot ID, or entire session
- **Trace logging:** structured audit log of every tool call and decision
- **Self-protection:** agent cannot uninstall hooks, edit settings.json, remove binary, or edit policy without human approval
- **Uninstall safety:** requires interactive terminal + native OS dialog (AppleScript/zenity/kdialog)
- **AI-assisted configuration:** Claude Code can propose policy changes, user approves via standard permission prompt
- **Claude Code integration:** hooks (PreToolUse, PostToolUse, SessionStart), CLAUDE.md injection, CLAUDE_CODE_SHELL env var
- **Per-project policy:** `railyard.yaml` with directory walk-up (like .gitignore)
- **Interactive setup:** `railyard configure` TUI and `railyard chat` policy assistant
- **141 tests:** 78 unit + 36 attack simulation + 15 rollback + 12 threat detection
