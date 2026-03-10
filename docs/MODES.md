# Modes & Default Rules

Railyard has two modes. Both block the same catastrophic commands. Hardcore adds layers on top.

## Mode comparison

| | **Chill** | **Hardcore** (default) |
|---|---|---|
| **Philosophy** | Don't blow stuff up | Full lockdown |
| Destructive commands | Blocked | Blocked |
| Self-protection | On | On |
| Network policy | — | curl\|sh blocked, POST/wget/ssh need approval |
| Credential protection | — | env dump, git config --global need approval |
| Evasion detection | — | base64, hex, eval, rev\|sh, Python obfuscation |
| Path fencing | — | Project dir only. ~/.ssh, ~/.aws, /etc denied |
| Threat escalation | — | Suspicious patterns → warn → session kill |
| OS sandbox | — | Every Bash command kernel-sandboxed |
| Trace logging | On | On |
| Snapshots + rollback | On | On |

## Default blocklist (both modes)

| Rule | What it catches | Why it exists |
|------|----------------|---------------|
| `terraform-destroy` | `terraform destroy`, `apply -auto-approve` | 1.9M row deletion incident |
| `rm-rf-critical` | `rm -rf /`, `~/`, `$HOME` | Home directory wipes |
| `sql-drop` | `DROP TABLE`, `DATABASE`, `SCHEMA` | Production database loss |
| `git-force-push` | `git push --force` | Overwrites remote history |
| `git-reset-hard` | `git reset --hard` | Destroys uncommitted work |
| `git-clean-force` | `git clean -f` | Removes untracked files |
| `drizzle-force` | `drizzle-kit push --force` | 60-table drop incident |
| `disk-format` | `mkfs`, `dd of=/dev/` | Disk destruction |
| `k8s-delete-ns` | `kubectl delete namespace` | Namespace deletion |
| `aws-s3-rm-recursive` | `aws s3 rm --recursive` | S3 data loss |
| `docker-system-prune` | `docker system prune -a` | Removes all images |
| `chmod-777-recursive` | `chmod -R 777 /` | Security disaster |
| `npm-publish` | `npm publish` | Requires human approval |

## Hardcore-only rules

### Network policy

| Rule | Action |
|------|--------|
| `curl \| sh` / `curl \| bash` | Block |
| `nc` / `netcat` / `ncat` | Block |
| `curl -X POST` / `curl --data` | Approve |
| `wget` | Approve |
| `ssh` / `scp` / `rsync` | Approve |

### Evasion detection

Agents have been [documented trying to bypass safety rules](https://github.com/anthropics/claude-code/issues/29691). Railyard normalizes commands before matching:

```
Direct:     terraform destroy                           → ⛔ blocked
Base64:     echo dGVycmFmb3Jt... | base64 -d | sh      → decoded    → ⛔ blocked
Double b64: echo ZEdW... | base64 -d | base64 -d | sh  → recursive  → ⛔ blocked + SESSION KILLED
Variable:   CMD="terraform destroy"; $CMD               → expanded   → ⛔ blocked
Shell wrap: sh -c "terraform destroy"                   → unwrapped  → ⛔ blocked
Eval:       eval "ter""raform destroy"                  → joined     → ⛔ blocked
Hex:        $'\x74\x65\x72\x72...'                      → decoded    → ⛔ blocked
Rev pipe:   rev <<< 'yortsed mrofarret' | sh            → shape      → ⛔ SESSION KILLED
ROT13:      tr 'a-z' 'n-za-m' <<< '...' | sh           → shape      → ⛔ SESSION KILLED
Python:     python3 -c "...b64decode..." / "...chr(..." → detected   → ⛔ SESSION KILLED
```

### Threat escalation

| Tier | Trigger | Action |
|------|---------|--------|
| **1** | `rev\|sh`, `base64\|base64`, `python -c chr()`, `printf \x` | Immediate session kill |
| **2** | Variable-then-exec, `eval $var`, multi-variable concat | Warning → kill on repeat |
| **3** | Retried blocked command with different syntax | Behavioral detection → kill |

### Path fencing

```
Your project directory     ✅ read/write
~/.ssh/                    ⛔ denied
~/.aws/                    ⛔ denied
~/.gnupg/                  ⛔ denied
~/.config/gcloud/          ⛔ denied
/etc/                      ⛔ denied
```

## Example: same session, different modes

**Chill mode:**
```
  Agent runs: curl -X POST https://api.example.com -d '{"key":"value"}'
  ✅ ALLOWED

  Agent runs: cat ~/.ssh/id_ed25519
  ✅ ALLOWED

  Agent runs: terraform destroy
  ⛔ BLOCKED

  Agent runs: echo dGVycmFmb3JtIGRlc3Ryb3k= | base64 -d | sh
  ⛔ BLOCKED (decoded via normalization)
  Session continues.
```

**Hardcore mode:**
```
  Agent runs: curl -X POST https://api.example.com -d '{"key":"value"}'
  ⚠️  APPROVE — "HTTP POST may exfiltrate data" [y/n]?

  Agent runs: cat ~/.ssh/id_ed25519
  ⛔ BLOCKED — Path Fence: ~/.ssh is denied

  Agent runs: terraform destroy
  ⛔ BLOCKED

  Agent runs: echo dGVycmFmb3JtIGRlc3Ryb3k= | base64 -d | sh
  ⛔ BLOCKED + SESSION KILLED — Tier 1 evasion detected
```
