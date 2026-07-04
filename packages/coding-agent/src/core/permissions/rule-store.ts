import { mkdirSync, readFileSync, renameSync, rmdirSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseRule } from "./rule-matcher.ts";
import type { Rule, RuleList, Scope } from "./types.ts";

type PermissionsFile = Record<string, unknown[]>;

const FILE_NAME = "permissions.json";
const VALID_LISTS: ReadonlySet<string> = new Set<RuleList>(["allow", "ask", "deny"]);
const VALID_SCOPES: ReadonlySet<string> = new Set<Scope>(["cli", "project-local", "user", "session"]);

const LOCK_TIMEOUT_MS = 5000;
const LOCK_STALE_MS = 30_000;
const LOCK_SPIN_MS = 20;

function filePath(agentDir: string): string {
	return join(agentDir, FILE_NAME);
}

function lockPath(agentDir: string): string {
	return join(agentDir, `${FILE_NAME}.lock`);
}

function spinWait(deadline: number): void {
	const until = Date.now() + LOCK_SPIN_MS;
	while (Date.now() < until && Date.now() < deadline) {
		// spin
	}
}

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
				// retry
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
		// ignore
	}
}

function atomicWrite(target: string, contents: string): void {
	const tmp = `${target}.${process.pid}.tmp`;
	writeFileSync(tmp, contents, "utf8");
	try {
		renameSync(tmp, target);
	} catch (err) {
		try {
			unlinkSync(tmp);
		} catch {
			// ignore
		}
		throw err;
	}
}

function withLock<T>(agentDir: string, mutate: () => T): T {
	const lock = acquireLock(agentDir);
	try {
		return mutate();
	} finally {
		releaseLock(lock);
	}
}

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

function rawListKey(entry: unknown): string {
	if (entry !== null && typeof entry === "object") {
		const e = entry as Record<string, unknown>;
		return JSON.stringify([String(e.raw ?? ""), String(e.list ?? "")]);
	}
	return JSON.stringify([String(entry), ""]);
}

function normalizeStored(entry: unknown): Rule | null {
	if (entry === null || typeof entry !== "object") return null;
	const e = entry as Record<string, unknown>;
	if (typeof e.raw !== "string") return null;
	if (typeof e.list !== "string" || !VALID_LISTS.has(e.list)) return null;
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

export function removeProjectLocalRules(agentDir: string, canonicalDir: string, rules: Rule[]): void {
	withLock(agentDir, () => {
		const map = readFile(agentDir);
		const existing = Array.isArray(map[canonicalDir]) ? map[canonicalDir] : [];
		const removeKeys = new Set(rules.map((entry) => rawListKey(entry)));
		map[canonicalDir] = existing.filter((entry) => !removeKeys.has(rawListKey(entry)));
		atomicWrite(filePath(agentDir), `${JSON.stringify(map, null, 2)}\n`);
	});
}

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
