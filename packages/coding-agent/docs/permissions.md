# Permissions

Pi can gate tool calls behind a per-tool approval layer. Before a built-in tool (read, edit, write, bash — plus the read helpers ls/grep/find) or an extension tool runs, pi checks it against the current mode and the active rule lists, then either allows it, blocks it, or asks you to approve it.

This is an approval guardrail, not a security boundary or a sandbox. It reduces accidental or unwanted tool actions — an edit outside the workspace, a destructive shell command, a read of a secret file — but it does not contain a motivated adversary and does not isolate the pi process from your filesystem, shell, or credentials. For real isolation, see [Security](security.md) and [Containerization](containerization.md).

The layer is on by default. Disable it entirely with `permissions.enabled: false` in settings.

## Modes

The permission mode is session-only: it is never persisted across sessions, and rules persist separately. When you do not set a mode, it is derived from project trust — an untrusted project starts in `default`, a trusted project starts in `acceptEdits`.

| Mode | Behavior |
|------|----------|
| `plan` | Read-only exploration. Reads and built-in read-only shell commands are allowed; every edit, write, and other command is denied. |
| `default` | Standard. Edits, writes, and non-read-only commands ask for approval unless an allow rule already covers them. |
| `acceptEdits` | Auto-accepts edits and writes inside the workspace root; everything else asks. |
| `dontAsk` | Auto-denies edits, writes, and non-read-only commands that aren't pre-approved by an allow rule; reads and read-only shell commands are still allowed. |
| `bypass` | Skips ordinary prompts. The circuit breaker still applies: it asks interactively and denies when non-interactive. |

In every mode, reads and built-in read-only shell commands (such as `ls`, `git status`, `cat`) are allowed unless an explicit `deny` or `ask` rule matches, and an `allow` rule can pre-approve a call in any mode (allow is checked before the mode default). The mode only governs what happens to writes, edits, and non-read-only commands that no rule already covers.

Set the mode for a run with `--permission-mode <mode>`, or change it mid-session with `/permission <mode>` (`/permission` with no argument opens a selector).

## Rules

A rule is a per-tool specifier assigned to one of three lists: `allow`, `ask`, or `deny`. When a tool call is checked, the lists are consulted in fixed priority order — **deny, then ask, then allow** — and the first match wins, so a deny always overrides an ask or allow for the same call.

A rule targets a tool by name, optionally with a specifier in parentheses. A bare tool name with no specifier matches every call to that tool.

- **Command specifiers** — `bash(git push *)`. Matched against the normalized command text. `*` matches any run of characters (including spaces); a `*` immediately after a literal space enforces a word boundary there, so `bash(ls *)` matches `ls -la` but not `lsof`.
- **Path specifiers** — `read(./.env)`, `edit(/src/**)`. Gitignore-style, with four anchors:

| Prefix | Anchor | Example |
|--------|--------|---------|
| `//abs` | Filesystem-absolute | `read(//etc/hosts)` |
| `~/x` | Home-relative | `read(~/.ssh/**)` |
| `/rel` | Project-root-relative | `edit(/src/**)` |
| `x` or `./x` | cwd-relative; a bare name with no `/` matches at any depth | `read(./.env)` |

Within a path, `*` matches a single segment and `**` crosses directories.

A `read(...)` deny or ask rule also binds bash commands that read those paths. `deny read(.env)` blocks both the `read` tool on `.env` and a `bash` call such as `cat .env`, because the analyzer extracts the file arguments of read-like commands (`cat`, `head`, `tail`, `grep`, `ls`).

## Scopes and storage

Rules come from four scopes, merged for every check:

| Scope | Source | Lifetime |
|-------|--------|----------|
| `cli` | `--allow` / `--deny` flags | This run only |
| `session` | Added in-memory during the session | Until the session ends |
| `project-local` | `~/.pi/agent/permissions.json`, keyed by canonical project path | Persisted, per project |
| `user` | `~/.pi/agent/settings.json` under `permissions.rules` | Persisted, all projects |

When you choose "always allow" at an approval prompt, pi persists the resulting allow rule to the project-local store, keyed by the canonical path of the current project. That file lives under your home directory, not in the repository, so approvals are neither committed nor shared.

## Command line and slash command

- `--permission-mode <mode>` — set the session mode (`plan`, `default`, `acceptEdits`, `dontAsk`, `bypass`).
- `--allow <specifier>` — pre-approve a tool or rule for this run, e.g. `--allow "bash(git push *)"`. Repeatable.
- `--deny <specifier>` — block a tool or rule for this run, e.g. `--deny "read(.env)"`. Repeatable.
- `/permission [mode]` — change the mode mid-session; with no argument it opens a mode selector.

## Headless behavior

Without an interactive UI (for example `-p`, `--mode json`, or `--mode rpc`) there is no one to answer a prompt. For back-compat, headless sessions run with a `bypass` non-interactive default, so an uncovered `ask` resolves to **allow** rather than failing closed — an unattended run will proceed with an edit or command that would have prompted interactively.

What still blocks headlessly: the circuit breaker (always denied when non-interactive, even under `bypass`), any explicit `deny` rule, and modes whose default is to deny (`plan`, `dontAsk`). If you need a headless run to refuse uncovered edits and commands, use `--permission-mode plan` or `--permission-mode dontAsk`, or add explicit `deny` rules.

## Circuit breaker

Independent of the allow list, pi treats a few shell commands as too dangerous to auto-approve: `rm` or `rmdir` targeting the filesystem root (`/`), the home directory (`~` / `$HOME`), or a key system path (`/etc`, `/usr`, `/bin`, `/System`, `/Library`). These sit above the allow list — even an explicit `allow bash(rm *)` cannot silently pass one. Interactively the circuit breaker still asks; non-interactively it denies.

This is a literal-string check on the command text, not a resolved-path check, so it guards against obvious mistakes rather than guaranteeing a path is safe.

## Escape hatches

- Run with `--permission-mode bypass` to skip ordinary prompts for a session (the circuit breaker still applies).
- Set `permissions.enabled: false` in settings to turn the layer off entirely.

## Not a security boundary

The permission layer reduces accidental and unwanted tool actions. It does not sandbox the pi process, does not contain a motivated adversary, and does not make untrusted prompts, untrusted repository content, or untrusted model output safe. It runs in-process with the same access as pi itself. When you need real isolation — for untrusted repositories, unattended automation, or code you will not review closely — run pi inside a container, VM, or micro-VM as described in [Security](security.md) and [Containerization](containerization.md).
