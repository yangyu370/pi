/**
 * Analyzes a bash command STRING into the resource access it represents, for
 * the permission rule engine (later PRs) to match rules/mode defaults
 * against. Pure and dependency-free: no filesystem access, no cwd/home
 * context — only lexical analysis of the command text itself.
 *
 * Semantics implemented here (docs/superpowers/specs/2026-07-01-permission-check-design.md §12):
 * - Built-in read-only set (fixed, not configurable): `ls cat echo pwd head
 *   tail grep wc which diff stat du` + read-only `git` forms
 *   (status/diff/log/show). `find`/`sed` are never auto-read-only (Phase 1
 *   default: ask); `find -exec`/`find -delete` are always high-risk.
 * - Top-level compound commands split only on `&&`, `||`, `;`, newline,
 *   outside quotes. A top-level pipe / subshell / command-substitution /
 *   backtick substitution / background `&` / unparseable quoting anywhere in
 *   the command degrades the WHOLE command to a single high-risk,
 *   non-readonly access instead of being split or read-only-classified —
 *   Phase 1 does not reason about pipelines/subshells per-branch (known
 *   tradeoff: `cat x | grep y` asks even though both sides are read-only;
 *   see spec §11.1).
 * - `rm`/`rmdir` targeting `/`, the home dir (`~`/`$HOME`), or a key system
 *   path trips the circuit breaker. This is a pure string function (no
 *   cwd/home passed in), so only literal forms are recognized — an absolute
 *   path that happens to resolve to the real home dir is not caught here;
 *   that requires the cwd/home anchors the engine layer already carries.
 *
 * Positioning: this is an approval guardrail, not a security boundary (see
 * ./types.ts). Parse "failure" never throws — it degrades to an empty,
 * non-readonly, unclassified access.
 */

import type { CommandAccess } from "./types.ts";

/** Fixed, non-configurable built-in read-only command set (spec §12). */
export const READONLY_COMMANDS: ReadonlySet<string> = new Set([
	"ls",
	"cat",
	"echo",
	"pwd",
	"head",
	"tail",
	"grep",
	"wc",
	"which",
	"diff",
	"stat",
	"du",
]);

/** `git` subcommands that never mutate the repo or working tree. */
const READONLY_GIT_SUBCOMMANDS: ReadonlySet<string> = new Set(["status", "diff", "log", "show"]);

/** Leading programs that run/throttle another command indirectly; always high-risk (spec §12). */
const HIGH_RISK_LEADING_PROGRAMS: ReadonlySet<string> = new Set(["watch", "setsid", "ionice", "flock"]);

/** Programs whose simple non-flag args are extracted into `readPaths`. */
const READ_PATH_COMMANDS: ReadonlySet<string> = new Set(["cat", "head", "tail", "grep", "ls"]);

/** Programs whose simple non-flag args are extracted into `mutatePaths`. */
const MUTATE_PATH_COMMANDS: ReadonlySet<string> = new Set(["rm", "mv", "cp"]);

/** Programs checked against the rm/rmdir-on-critical-path circuit breaker. */
const CIRCUIT_BREAKER_PROGRAMS: ReadonlySet<string> = new Set(["rm", "rmdir"]);

/** Absolute prefixes that are never safe `rm -rf` targets (spec §12: "关键系统路径...等"). */
const CRITICAL_SYSTEM_PATH_PREFIXES: readonly string[] = ["/etc", "/usr", "/bin", "/System", "/Library"];

/** Shell glob metacharacters (pathname expansion) — deliberately excludes `{}` brace expansion. */
const GLOB_CHARS_RE = /[*?[]/;

/**
 * True if `args` (the tokens following `git`) form one of the fixed
 * read-only git forms: `status`, `diff`, `log`, `show`. Only the immediate
 * subcommand is checked — Phase 1 does not strip leading global flags (e.g.
 * `-C <dir>`, `--no-pager`), consistent with "no wrapper stripping"
 * elsewhere in this module (spec §11.1). `git --no-pager diff` is simply not
 * auto-classified read-only; it falls through to the normal ask/mode
 * default, never mis-allowed.
 */
export function isReadonlyGitSubcommand(args: string[]): boolean {
	return args.length > 0 && READONLY_GIT_SUBCOMMANDS.has(args[0]);
}

/** A single whitespace-separated word from a subcommand, quote-stripped. */
interface Token {
	/** Dequoted value (quote delimiters stripped, contents preserved). */
	value: string;
	/** True if any part of this token came from inside a quoted span. */
	quoted: boolean;
}

/**
 * Splits a single already top-level-split, quote-balanced subcommand into
 * whitespace-separated words, stripping single/double quote delimiters while
 * preserving their contents. Not a full shell word-splitter (no brace,
 * variable, or tilde expansion) — deliberately minimal per Phase 1 scope.
 */
function tokenizeWords(text: string): Token[] {
	const tokens: Token[] = [];
	let value = "";
	let quoted = false;
	let active = false;
	let quote: '"' | "'" | undefined;
	const n = text.length;
	let i = 0;

	const pushToken = () => {
		if (active) tokens.push({ value, quoted });
		value = "";
		quoted = false;
		active = false;
	};

	while (i < n) {
		const ch = text[i];
		if (quote) {
			if (ch === quote) {
				quote = undefined;
			} else {
				value += ch;
			}
			active = true;
			i++;
			continue;
		}
		if (ch === '"' || ch === "'") {
			quote = ch;
			quoted = true;
			active = true;
			i++;
			continue;
		}
		if (/\s/.test(ch)) {
			pushToken();
			i++;
			continue;
		}
		value += ch;
		active = true;
		i++;
	}
	pushToken();
	return tokens;
}

/** Collapses redundant whitespace for stable `bash(...)` specifier matching. */
function normalizeWhitespace(text: string): string {
	return text.trim().replace(/\s+/g, " ");
}

/**
 * Scans a full (possibly compound) bash command once, tracking single/double
 * quote state, to find top-level split points (`&&`, `||`, `;`, newline)
 * outside any quotes, AND any top-level high-risk shell structure (pipe,
 * subshell, command substitution, backtick substitution, background `&`) or
 * unbalanced/unparseable quoting anywhere in the command.
 *
 * If `highRiskReason` comes back set, the caller must ignore `segments`
 * entirely and treat the whole original command as one opaque unit (spec
 * §11.1) — this function still finishes the scan in that case, but the
 * partial segments it collected are meaningless once a structural risk is
 * found.
 */
function splitTopLevel(command: string): { highRiskReason?: string; segments: string[] } {
	const segments: string[] = [];
	let current = "";
	let quote: '"' | "'" | undefined;
	let highRiskReason: string | undefined;
	const n = command.length;
	let i = 0;

	const flush = () => {
		const trimmed = current.trim();
		if (trimmed.length > 0) segments.push(trimmed);
		current = "";
	};

	while (i < n) {
		const ch = command[i];
		if (quote) {
			current += ch;
			if (ch === quote) quote = undefined;
			i++;
			continue;
		}
		if (ch === '"' || ch === "'") {
			quote = ch;
			current += ch;
			i++;
			continue;
		}
		if (ch === "`") {
			highRiskReason ??= "top-level command substitution (`...`)";
			current += ch;
			i++;
			continue;
		}
		if (ch === "(") {
			highRiskReason ??= "top-level subshell or command substitution ( ... )";
			current += ch;
			i++;
			continue;
		}
		if (ch === "|") {
			if (command[i + 1] === "|") {
				flush();
				i += 2;
				continue;
			}
			highRiskReason ??= "top-level pipe (|)";
			current += ch;
			i++;
			continue;
		}
		if (ch === "&") {
			if (command[i + 1] === "&") {
				flush();
				i += 2;
				continue;
			}
			highRiskReason ??= "top-level background execution (&)";
			current += ch;
			i++;
			continue;
		}
		if (ch === ";" || ch === "\n") {
			flush();
			i++;
			continue;
		}
		current += ch;
		i++;
	}
	if (quote) {
		highRiskReason ??= "unparseable quoting (unbalanced quote)";
	}
	flush();
	return { highRiskReason, segments };
}

/**
 * Placeholder hook for a per-command "write-capable flag" check (spec §10
 * step 5b: readonly requires "无 write-capable flag"). None of the fixed
 * READONLY_COMMANDS (ls cat echo pwd head tail grep wc which diff stat du)
 * has a flag that mutates filesystem state today, so this is vacuously
 * false. Kept as an explicit named call site (rather than omitted) so a
 * future addition to READONLY_COMMANDS can wire in a real flag check here
 * without touching the readonly computation itself.
 */
function hasWriteCapableFlag(_program: string, _args: readonly Token[]): boolean {
	return false;
}

/**
 * Returns a human-readable reason if `target` (a raw rm/rmdir argument) is
 * the filesystem root, the home directory, or under a key system path.
 * Pure string matching only (no cwd/home resolution available here) — an
 * absolute path that happens to equal the real home directory is NOT
 * caught; only the literal `~`/`$HOME` forms are.
 */
function criticalPathReason(target: string): string | undefined {
	const normalized = target.replace(/\/+$/, "") || "/";
	if (normalized === "/") {
		return `rm/rmdir target is the filesystem root ("${target}")`;
	}
	if (normalized === "~" || normalized === "$HOME") {
		return `rm/rmdir target is the home directory ("${target}")`;
	}
	for (const prefix of CRITICAL_SYSTEM_PATH_PREFIXES) {
		if (normalized === prefix || normalized.startsWith(`${prefix}/`)) {
			return `rm/rmdir target is under the system path ${prefix} ("${target}")`;
		}
	}
	return undefined;
}

/**
 * Analyzes one already top-level-split subcommand. Guaranteed free of
 * top-level pipe/subshell/substitution/backtick/background — those are
 * handled by {@link splitTopLevel} before this is ever called.
 */
function analyzeSingleCommand(segment: string): CommandAccess {
	const command = segment.trim();
	const normalizedCommand = normalizeWhitespace(command);
	const tokens = tokenizeWords(command);

	if (tokens.length === 0) {
		return { command, normalizedCommand, readPaths: [], mutatePaths: [], readonly: false };
	}

	const program = tokens[0].value;
	const args = tokens.slice(1);
	const nonFlagValues = args.filter((t) => !t.value.startsWith("-")).map((t) => t.value);
	const bareGlob = args.find((t) => !t.quoted && GLOB_CHARS_RE.test(t.value));

	let highRiskReason: string | undefined;
	if (HIGH_RISK_LEADING_PROGRAMS.has(program)) {
		highRiskReason = `"${program}" runs or throttles another command indirectly and is always treated as high-risk`;
	} else if (program === "find" && args.some((t) => t.value === "-exec" || t.value === "-delete")) {
		highRiskReason = "find with -exec/-delete can execute or delete arbitrary matched files";
	}
	if (!highRiskReason && bareGlob) {
		highRiskReason = `unquoted glob argument "${bareGlob.value}" — shell expansion could change the command's meaning`;
	}

	let circuitBreakerReason: string | undefined;
	if (CIRCUIT_BREAKER_PROGRAMS.has(program)) {
		for (const value of nonFlagValues) {
			circuitBreakerReason = criticalPathReason(value);
			if (circuitBreakerReason) break;
		}
	}

	const isReadonlyProgram =
		READONLY_COMMANDS.has(program) || (program === "git" && isReadonlyGitSubcommand(args.map((t) => t.value)));
	const readonly = isReadonlyProgram && !highRiskReason && !hasWriteCapableFlag(program, args);

	return {
		command,
		normalizedCommand,
		readPaths: READ_PATH_COMMANDS.has(program) ? nonFlagValues : [],
		mutatePaths: MUTATE_PATH_COMMANDS.has(program) ? nonFlagValues : [],
		readonly,
		circuitBreakerReason,
		highRiskReason,
	};
}

/**
 * Analyzes a (possibly compound) bash command string into one
 * `CommandAccess` per top-level subcommand. Pure and dependency-free; never
 * throws.
 *
 * Top-level structural risk (pipe `|`, subshell/command-substitution
 * `(...)`, backtick substitution, background `&`, or unbalanced/unparseable
 * quoting) anywhere in `command` short-circuits: the whole original command
 * is returned as a SINGLE high-risk, non-readonly access instead of being
 * split (spec §11.1).
 */
export function analyzeBashCommand(command: string): CommandAccess[] {
	const { highRiskReason, segments } = splitTopLevel(command);
	const trimmed = command.trim();

	if (highRiskReason) {
		return [
			{
				command: trimmed,
				normalizedCommand: normalizeWhitespace(trimmed),
				readPaths: [],
				mutatePaths: [],
				readonly: false,
				highRiskReason,
			},
		];
	}
	if (segments.length === 0) {
		return [
			{
				command: trimmed,
				normalizedCommand: normalizeWhitespace(trimmed),
				readPaths: [],
				mutatePaths: [],
				readonly: false,
			},
		];
	}
	return segments.map(analyzeSingleCommand);
}
