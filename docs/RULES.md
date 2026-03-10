# Default Rules & Configuration

Railyard ships with sensible defaults. Destructive commands require your approval. Evasion attempts are hard-blocked. Everything else flows through instantly.

## Default rules

### Destructive commands (approve — you decide)

| Rule | What it catches | Why |
|------|----------------|-----|
| `terraform-destroy` | `terraform destroy`, `apply -auto-approve` | 1.9M row deletion incident |
| `rm-rf-critical` | `rm -rf /`, `~/`, `$HOME` | Home directory wipes |
| `sql-drop` | `DROP TABLE`, `DATABASE`, `SCHEMA` | Production database loss |
| `git-force-push` | `git push --force` | Overwrites remote history |
| `git-reset-hard` | `git reset --hard` | Destroys uncommitted work |
| `git-clean-force` | `git clean -f` | Removes untracked files |
| `drizzle-force` | `drizzle-kit push --force` | 60-table drop incident |
| `k8s-delete-ns` | `kubectl delete namespace` | Namespace deletion |
| `aws-s3-rm-recursive` | `aws s3 rm --recursive` | S3 data loss |
| `docker-system-prune` | `docker system prune -a` | Removes all images |
| `chmod-777-recursive` | `chmod -R 777 /` | Security disaster |
| `npm-publish` | `npm publish` | Accidental publishes |

### Hard blocks (never legitimate from an agent)

| Rule | What it catches |
|------|----------------|
| `disk-format` | `mkfs`, `dd of=/dev/` |
| `network-curl-pipe-sh` | `curl \| sh` / `curl \| bash` |
| `network-nc` | `nc` / `netcat` / `ncat` |
| `base64-to-shell` | `base64 -d \| sh` |
| `printf-hex-exec` | `$(printf '\x...')` in command position |
| `transform-pipe-to-shell` | `rev \| sh`, `tr \| sh`, `sed \| sh` |
| `interpreter-obfuscation` | Python/Ruby with chr(), b64decode, system() |
| `git-config-global-write` | `git config --global` writes |

### Self-protection (hard block)

| Rule | What it catches |
|------|----------------|
| `railyard-uninstall` | `railyard uninstall` |
| `railyard-tamper-settings` | Edits to `.claude/settings.json` |
| `railyard-remove-binary` | `rm` targeting railyard binary |
| `railyard-config-edit` | Edits to `railyard.yaml` (approve) |

### Network & credentials (approve)

| Rule | What it catches |
|------|----------------|
| `network-curl-post` | `curl -X POST` / `curl --data` |
| `network-wget` | `wget` |
| `network-ssh-scp` | `ssh` / `scp` / `rsync` |
| `env-dump` | `env` / `printenv` |
| `eval-dynamic` | `eval` with variable expansion |
| `symlink-to-outside` | Symlinks to absolute paths |

## Evasion detection

Agents have been [documented trying to bypass safety rules](https://github.com/anthropics/claude-code/issues/29691). Railyard normalizes commands before matching:

```
Direct:     terraform destroy                           → ⚠️  asks you
Base64:     echo dGVycmFmb3Jt... | base64 -d | sh      → ⛔ blocked
Double b64: echo ZEdW... | base64 -d | base64 -d | sh  → ⛔ blocked + SESSION KILLED
Variable:   CMD="terraform destroy"; $CMD               → expanded   → ⚠️  asks you
Shell wrap: sh -c "terraform destroy"                   → unwrapped  → ⚠️  asks you
Eval:       eval "ter""raform destroy"                  → joined     → ⚠️  asks you
Hex:        $'\x74\x65\x72\x72...'                      → decoded    → ⛔ blocked
Rev pipe:   rev <<< 'yortsed mrofarret' | sh            → shape      → ⛔ SESSION KILLED
ROT13:      tr 'a-z' 'n-za-m' <<< '...' | sh           → shape      → ⛔ SESSION KILLED
Python:     python3 -c "...b64decode..." / "...chr(..." → detected   → ⛔ SESSION KILLED
```

## Threat escalation

| Tier | Trigger | Action |
|------|---------|--------|
| **1** | `rev\|sh`, `base64\|base64`, `python -c chr()`, `printf \x` | Immediate session kill |
| **2** | Variable-then-exec, `eval $var`, multi-variable concat | Warning, then kill on repeat |
| **3** | Retried blocked command with different syntax | Behavioral detection, then kill |

## Path fencing

When enabled (default), restricts file access:

```
Your project directory     ✅ read/write
~/.ssh/                    ⛔ denied
~/.aws/                    ⛔ denied
~/.gnupg/                  ⛔ denied
~/.config/gcloud/          ⛔ denied
/etc/                      ⛔ denied
```

## Customizing

Edit `railyard.yaml` or run `railyard configure`:

```yaml
# Block a command entirely
blocklist:
  - name: no-deploy
    tool: Bash
    pattern: "deploy-to-prod"
    action: block

# Require approval
approve:
  - name: terraform-apply
    tool: Bash
    pattern: "terraform\\s+apply"
    action: approve

# Skip a default rule
allowlist:
  - name: allow-git-force
    tool: Bash
    pattern: "git push --force"
    action: allow
```

Changes take effect immediately. No restart needed.
