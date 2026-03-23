# Changelog

All notable changes to this project will be documented in this file.

## [0.5.1] - 2026-03-22

### Fixed

- **Approval prompts now visible to the user** — `permissionDecisionReason` was not being set on `ask` responses, so Claude Code showed the generic "Hook requires confirmation" message instead of Railguard's explanation. Now both `permissionDecisionReason` (shown to user) and `additionalContext` (shown to Claude) are set.

## [0.5.0] - 2026-03-22 — Graceful Fail-Safe

Railguard no longer permanently kills sessions or silently blocks without explanation. Every decision now tells you who's asking, why, and what to do about it.

### Added

- **Claude Code plugin support** — Railguard can now be loaded as a native Claude Code plugin (`claude --plugin-dir`). Includes `.claude-plugin/plugin.json` manifest, `hooks/hooks.json`, `settings.json`, and `CLAUDE.md`. No need to run `railguard install` when using as a plugin.
- **`railguard plugin` command** — prints the plugin directory path for easy use with `claude --plugin-dir $(railguard plugin)`.
- **Session resume** — terminated sessions now ask the user for approval to resume instead of permanently blocking all tool calls. If approved, all threat state (suspicion, warnings, block history) is fully reset so the session starts clean.
- **Descriptive approval prompts** — every approval prompt now starts with "🛡️ RAILGUARD is asking (not Claude Code's permission system)" so users understand why they're being prompted despite skip-permissions mode. Each prompt includes the specific rule or pattern that triggered it and a preview of the command.
- **Informative termination messages** — deny messages on terminated sessions now include the specific reason, session ID, and `railguard log` command. Terminal output on kill explains it's Railguard (not Claude Code) and provides both `log` and `context` review commands.

### Changed

- **No more permanent session kills** — previously, a terminated session blocked every subsequent tool call with a hard deny. Now it asks the user to approve resuming, making accidental kills (like legitimate `python3 -c` with `chr()`) recoverable without starting a new session.
- **Approval messages are context-rich** — Tier 1/2/3 evasion, path fence, policy rules, and memory guard prompts all explain what triggered them and what approving means.

## [0.3.4] - 2026-03-12

### Added

- **`railguard update` command** — checks GitHub for the latest release, compares semver versions, shows changelog, downloads prebuilt binary (or falls back to `cargo install`), and re-registers hooks automatically. Use `--check` to check without installing.

### Fixed

- **Path fence blocked writes to project directory** — when `allowed_paths` was set in `railguard.yaml`, the project directory (CWD) was not implicitly allowed, causing all file writes to be denied. CWD is now always permitted regardless of `allowed_paths` configuration.

## [0.3.0] - 2026-03-11

### Added

- **Coordination layer** — multi-agent file locking across concurrent Claude Code sessions
  - Automatic lock acquisition on Write/Edit tool calls
  - Self-healing locks: expire on PID death or 60s inactivity timeout
  - `railguard locks` command to view all active file locks
  - Shared context injection on SessionStart — each agent is told what other sessions are working on
- **Session replay** — `railguard replay --session <id>` TUI to browse a session's complete timeline with tool calls, decisions, relative timestamps, and expandable detail view
- **151 tests** (was 142)

## [0.2.1] - 2026-03-11

### Added

- **Live TUI dashboard** — `railguard dashboard` launches a full terminal UI showing all tool calls and decisions in real time. Search (`/`), filter (`f`), expand details (`Enter`), vim-style navigation.
- **Global trace directory** — all traces now write to `~/.railguard/traces/` instead of per-project `.railguard/traces/`. Dashboard and `railguard log` work from any directory and see all sessions across all projects.
- **Streaming mode** — `railguard dashboard --stream` for plain text output (old default behavior).

### Fixed

- **Dashboard shows no output** — traces were written relative to the project where Claude Code was running, but the dashboard read relative to where it was launched. Global traces fix this.
- **Config-edit rule too broad** — `railguard-config-edit` used `tool: *` which triggered approval on any tool call mentioning `railguard.yaml` (including `find` and `grep`). Now scoped to `Write` and `Edit` tools only.
- **TUI crash leaves terminal broken** — added panic hook to restore terminal state on crash.
- **Text invisible on light terminals** — replaced hardcoded `Color::White` with `Color::Reset` (terminal default foreground).

### Changed

- **Dashboard TUI is now the default** — `railguard dashboard` launches TUI. Use `--stream` for the old streaming behavior.
- **142 tests** (was 141)

## [0.2.0] - 2026-03-10

### Changed

- **Removed wrapper/launch CLI** — shell shim (`railguard-shell`) is now the only sandboxing approach. `railguard launch` and `railguard sandbox` commands removed.
- **Path fence: outside-project paths now prompt for approval** — explicitly denied paths (~/.ssh, ~/.aws, /etc) are still hard-blocked, but paths outside the project directory ask you instead of blocking outright.
- **Removed chill/hardcore modes** — single configurable ruleset. All features (threat detection, path fencing, evasion detection) always active.
- **Destructive commands block instead of approve** — terraform destroy, rm -rf, DROP TABLE etc. are denied automatically so the agent finds a safer approach. No babysitting.

### Added

- **13 new default rules** (26 total) — database migration resets, cloud CLI deletions (AWS, GCP, Azure), IaC destroy (CDK, Pulumi, CloudFormation), Redis/MongoDB wipes, gsutil recursive delete
- **Weekly update check** — on SessionStart, checks for new versions via Claude Code's hook system. Non-spammy: once per week.
- **Emergency security patches** — checks a `security` tag every session (<100ms). Maintainers push `git tag -f security` and every user's next session sees it immediately.
- **Customizable policy messaging** — if defaults are too strict, override once in `railguard.yaml` and it persists across sessions.

## [0.1.0] - 2026-03-09

Initial release.

### Features

- **Smart defaults:** destructive commands are blocked, sensitive operations require approval, everything else flows through instantly
- **13 default rules** covering terraform destroy, rm -rf, DROP TABLE, git force-push, drizzle-kit push --force, and more
- **Evasion detection:** base64 decoding, variable expansion, shell unwrapping, hex decoding, eval concatenation, multi-variable concat, rev|sh shape detection, Python/Ruby interpreter obfuscation
- **Threat escalation:** 3-tier system — pattern detection (Tier 1, instant kill), behavioral analysis (Tier 2, warn then kill), retry detection (Tier 3)
- **Path fencing:** restrict agent to project directory, deny ~/.ssh, ~/.aws, ~/.gnupg, /etc
- **OS-level sandboxing:** `railguard-shell` binary transparently wraps every Bash command in `sandbox-exec` (macOS) or `bwrap` (Linux)
- **Snapshots & rollback:** per-edit file backups with undo by steps, file, snapshot ID, or entire session
- **Trace logging:** structured audit log of every tool call and decision
- **Self-protection:** agent cannot uninstall hooks, edit settings.json, remove binary, or edit policy without human approval
- **Uninstall safety:** requires interactive terminal + native OS dialog (AppleScript/zenity/kdialog)
- **AI-assisted configuration:** Claude Code can propose policy changes, user approves via standard permission prompt
- **Claude Code integration:** hooks (PreToolUse, PostToolUse, SessionStart), CLAUDE.md injection, CLAUDE_CODE_SHELL env var
- **Per-project policy:** `railguard.yaml` with directory walk-up (like .gitignore)
- **Interactive setup:** `railguard configure` TUI and `railguard chat` policy assistant
- **141 tests:** 78 unit + 36 attack simulation + 15 rollback + 12 threat detection
