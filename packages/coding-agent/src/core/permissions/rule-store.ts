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

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseRule } from "./rule-matcher.ts";
import type { Rule, RuleList, Scope } from "./types.ts";

/** On-disk shape of `<agentDir>/permissions.json`. */
type PermissionsFile = Record<string, unknown[]>;

const FILE_NAME = "permissions.json";
const VALID_LISTS: ReadonlySet<string> = new Set<RuleList>(["allow", "ask", "deny"]);
const VALID_SCOPES: ReadonlySet<string> = new Set<Scope>(["cli", "project-local", "user", "session"]);

function filePath(agentDir: string): string {
	return join(agentDir, FILE_NAME);
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
 * incoming duplicates. Throws on write failure (caller handles the fallback);
 * a pre-existing corrupt file is treated as empty rather than throwing.
 */
export function appendProjectLocalRules(agentDir: string, canonicalDir: string, rules: Rule[]): void {
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
	mkdirSync(agentDir, { recursive: true });
	writeFileSync(filePath(agentDir), `${JSON.stringify(map, null, 2)}\n`, "utf8");
}

/** Removes exact rules (matched by raw + list) from the project-local scope. Throws on write failure. */
export function removeProjectLocalRules(agentDir: string, canonicalDir: string, rules: Rule[]): void {
	const map = readFile(agentDir);
	const existing = Array.isArray(map[canonicalDir]) ? map[canonicalDir] : [];
	const removeKeys = new Set(rules.map((entry) => rawListKey(entry)));
	map[canonicalDir] = existing.filter((entry) => !removeKeys.has(rawListKey(entry)));
	mkdirSync(agentDir, { recursive: true });
	writeFileSync(filePath(agentDir), `${JSON.stringify(map, null, 2)}\n`, "utf8");
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
