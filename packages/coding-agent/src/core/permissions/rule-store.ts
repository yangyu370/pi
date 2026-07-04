/**
 * Persistence + layering for permission rules.
 *
 * The "project-local" scope deliberately lives OUTSIDE the repo, in a single
 * global file `<agentDir>/permissions.json` keyed by canonical project path
 * (structurally like `trust.json`), so approving a rule for one checkout never
 * commits it into the repo. This is a different mechanism from
 * `SettingsManager`'s in-repo `"project"` scope (see integration-map §6).
 *
 * Everything here is total w.r.t. reads: an absent or corrupt `permissions.json`
 * degrades to an empty rule set rather than throwing, so a garbled file can
 * never crash the tool-call path. Writes DO throw on failure — the caller
 * (the permission service) is responsible for catching and falling back to
 * in-memory session rules.
 *
 * Positioning: this is an approval guardrail, not a security boundary (see
 * ./types.ts).
 */

import { mkdirSync, readFileSync, renameSync, rmdirSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseRule } from "./rule-matcher.ts";
import type { Rule, RuleList, Scope } from "./types.ts";

/** On-disk shape of `<agentDir>/permissions.json`. */
type PermissionsFile = Record<string, unknown[]>;

const FILE_NAME = "permissions.json";
const VALID_LISTS: ReadonlySet<string> = new Set<RuleList>(["allow", "ask", "deny"]);
const VALID_SCOPES: ReadonlySet<string> = new Set<Scope>(["cli", "project-local", "user", "session"]);

/** Spin-lock acquisition budget and staleness threshold (ms). */
const LOCK_TIMEOUT_MS = 5000;
const LOCK_STALE_MS = 30_000;
const LOCK_SPIN_MS = 20;

function filePath(agentDir: string): string {
	return join(agentDir, FILE_NAME);
}

function lockPath(agentDir: string): string {
	return join(agentDir, `${FILE_NAME}.lock`);
}

/** Busy-waits for the spin-lock window without a timer (writes are rare + human-triggered). */
function spinWait(deadline: number): void {
	const until = Date.now() + LOCK_SPIN_MS;
	while (Date.now() < until && Date.now() < deadline) {
		// Intentionally tight: the lock holder is doing a single sync read-modify-write.
	}
}

/**
 * Cross-process mutex via an exclusive `mkdir` (atomic on POSIX + Windows). Spins
 * until acquired or the timeout elapses; reclaims a lock whose directory mtime is
 * older than {@link LOCK_STALE_MS} (a crashed holder). Throws on timeout so the
 * caller keeps rules in-session rather than risking a torn write.
 */
function acquireLock(agentDir: string): string {
	const lock = lockPath(agentDir);
	const deadline = Date.now() + LOCK_TIMEOUT_MS;
	mkdirSync(agentDir, { recursive: true });
	for (;;) {
		try {
			mkdirSync(lock);
			return lock;
		} catch {
			try {
				if (Date.now() - statSync(lock).mtimeMs > LOCK_STALE_MS) {
					rmdirSync(lock);
					continue;
				}
			} catch {
				// Lock vanished between mkdir failure and stat: retry immediately.
			}
			if (Date.now() >= deadline) {
				throw new Error(`permissions.json lock busy after ${LOCK_TIMEOUT_MS}ms`);
			}
			spinWait(deadline);
		}
	}
}

function releaseLock(lock: string): void {
	try {
		rmdirSync(lock);
	} catch {
		// Already gone (e.g. reclaimed as stale): nothing to release.
	}
}

/**
 * Writes `contents` to `target` atomically: a same-directory temp file is written
 * then `rename`d over the target (atomic on the same filesystem, no EXDEV). Cleans
 * up the temp file if the rename fails, then rethrows so the caller can fall back.
 */
function atomicWrite(target: string, contents: string): void {
	const tmp = `${target}.${process.pid}.tmp`;
	writeFileSync(tmp, contents, "utf8");
	try {
		renameSync(tmp, target);
	} catch (err) {
		try {
			unlinkSync(tmp);
		} catch {
			// Best-effort cleanup; surface the original rename failure.
		}
		throw err;
	}
}

/** Runs `mutate` under the file lock, always releasing it (even on throw). */
function withLock<T>(agentDir: string, mutate: () => T): T {
	const lock = acquireLock(agentDir);
	try {
		return mutate();
	} finally {
		releaseLock(lock);
	}
}

/** Reads the raw path-keyed map; any read/parse failure degrades to `{}`. */
function readFile(agentDir: string): PermissionsFile {
	try {
		const parsed = JSON.parse(readFileSync(filePath(agentDir), "utf8"));
		if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
			return parsed as PermissionsFile;
		}
		return {};
	} catch {
		return {};
	}
}

/** Stable identity for on-disk dedup: two entries are "the same rule" iff same raw + list. */
function rawListKey(entry: unknown): string {
	if (entry !== null && typeof entry === "object") {
		const e = entry as Record<string, unknown>;
		return JSON.stringify([String(e.raw ?? ""), String(e.list ?? "")]);
	}
	return JSON.stringify([String(entry), ""]);
}

/** Turns a raw stored entry into a normalized {@link Rule}; returns null if unusable. */
function normalizeStored(entry: unknown): Rule | null {
	if (entry === null || typeof entry !== "object") return null;
	const e = entry as Record<string, unknown>;
	if (typeof e.raw !== "string") return null;
	if (typeof e.list !== "string" || !VALID_LISTS.has(e.list)) return null;
	// The raw text is authoritative; re-derive tool/specifier so a hand-edited
	// file with a mismatched tool/specifier still matches what the user typed.
	const { tool, specifier } = parseRule(e.raw);
	const scope: Scope = typeof e.scope === "string" && VALID_SCOPES.has(e.scope) ? (e.scope as Scope) : "project-local";
	return {
		raw: e.raw,
		tool,
		...(specifier !== undefined ? { specifier } : {}),
		list: e.list as RuleList,
		scope,
	};
}

/**
 * Loads the project-local rules stored for `canonicalDir`. Absent file, corrupt
 * JSON, missing key, or malformed entries all degrade to `[]` (never throws).
 */
export function loadProjectLocalRules(agentDir: string, canonicalDir: string): Rule[] {
	const bucket = readFile(agentDir)[canonicalDir];
	if (!Array.isArray(bucket)) return [];
	const out: Rule[] = [];
	for (const entry of bucket) {
		const rule = normalizeStored(entry);
		if (rule) out.push(rule);
	}
	return out;
}

/**
 * Read-modify-writes `<agentDir>/permissions.json`, appending `rules` under
 * `canonicalDir` and de-duplicating by (raw, list). Existing entries win over
 * incoming duplicates. The whole read-modify-write runs under a cross-process
 * file lock and commits via an atomic temp+rename, so a concurrent writer (a
 * second agent process) can never lose rules or leave a torn file. Throws on
 * write/lock failure (caller handles the fallback); a pre-existing corrupt file
 * is treated as empty rather than throwing.
 */
export function appendProjectLocalRules(agentDir: string, canonicalDir: string, rules: Rule[]): void {
	withLock(agentDir, () => {
		const map = readFile(agentDir);
		const existing = Array.isArray(map[canonicalDir]) ? map[canonicalDir] : [];
		const seen = new Set<string>();
		const merged: unknown[] = [];
		for (const entry of [...existing, ...rules]) {
			const key = rawListKey(entry);
			if (seen.has(key)) continue;
			seen.add(key);
			merged.push(entry);
		}
		map[canonicalDir] = merged;
		atomicWrite(filePath(agentDir), `${JSON.stringify(map, null, 2)}\n`);
	});
}

/** Removes exact rules (matched by raw + list) from the project-local scope. Throws on write failure. */
export function removeProjectLocalRules(agentDir: string, canonicalDir: string, rules: Rule[]): void {
	withLock(agentDir, () => {
		const map = readFile(agentDir);
		const existing = Array.isArray(map[canonicalDir]) ? map[canonicalDir] : [];
		const removeKeys = new Set(rules.map((entry) => rawListKey(entry)));
		map[canonicalDir] = existing.filter((entry) => !removeKeys.has(rawListKey(entry)));
		atomicWrite(filePath(agentDir), `${JSON.stringify(map, null, 2)}\n`);
	});
}

/**
 * Merges the four rule layers into a single de-duplicated list in fixed
 * priority order (session -> cli -> project-local -> user). Dedup collapses
 * rules that are identical in (tool, specifier, list) regardless of scope,
 * keeping the highest-priority copy; rules on different lists (e.g. an allow
 * and a deny for the same target) are preserved so the engine's list-priority
 * pipeline can resolve the conflict.
 */
export function mergeRules(layers: { session?: Rule[]; cli?: Rule[]; projectLocal?: Rule[]; user?: Rule[] }): Rule[] {
	const ordered = [
		...(layers.session ?? []),
		...(layers.cli ?? []),
		...(layers.projectLocal ?? []),
		...(layers.user ?? []),
	];
	const seen = new Set<string>();
	const out: Rule[] = [];
	for (const rule of ordered) {
		const key = JSON.stringify([rule.tool, rule.specifier ?? "", rule.list]);
		if (seen.has(key)) continue;
		seen.add(key);
		out.push(rule);
	}
	return out;
}
