/**
 * The permission decision core: `check(snapshot)` runs the fixed-priority
 * decision pipeline (spec §10) and returns an allow / deny / ask outcome.
 *
 * Design constraints:
 * - **Pure & total.** No I/O, no `process.cwd()`; every path anchor comes from
 *   the snapshot. It must never throw for a valid snapshot — on any unexpected
 *   internal error it fails safe to `ask` (spec §18: prefer asking over
 *   silently allowing).
 * - **Rule-driven.** The command-analyzer only supplies read-only / circuit-
 *   breaker / high-risk facts; the actual decision comes from deny/ask/allow
 *   rules and the mode default here (spec §12 positioning note).
 *
 * Pipeline per unit (first match wins):
 *   1. deny rule            → deny
 *   2. circuit breaker      → ask (above allow; even `allow bash(rm *)` can't pass)
 *   3. ask rule             → ask
 *   4. allow rule           → allow (high-risk needs an *exact*, non-wildcard allow)
 *   5a. read-capable tool   → allow
 *   5b. read-only bash      → allow (any mode)
 *   6. mode default (by capability)
 *   7. fallback             → ask
 *
 * A composite bash command is one unit per top-level subcommand; the units are
 * combined as: any deny → deny; any ask → ask; all allow → allow.
 *
 * Positioning: this is an approval guardrail, not a security boundary (see ./types.ts).
 */

import { resolvePath } from "../../utils/paths.ts";
import { matchBashCommand, matchPath, matchToolName, specifierHasWildcard } from "./rule-matcher.ts";
import type { CheckResult, CommandAccess, Decision, PolicySnapshot, Resource, Rule } from "./types.ts";

/** Path anchors the rule-matcher needs to resolve gitignore-style specifiers. */
type Anchors = { cwd: string; home: string; workspaceRoot: string };

/** One decision unit fed through the pipeline. */
type Unit = { kind: "command"; access: CommandAccess } | { kind: "paths"; paths: string[] } | { kind: "none" };

/** A per-unit outcome; `suggestedRules` is only meaningful when `decision === "ask"`. */
type UnitResult = Required<Pick<CheckResult, "decision">> & {
	reason?: string;
	suggestedRules?: NonNullable<CheckResult["suggestedRules"]>;
};

/**
 * Resolves a raw tool/command path argument to an absolute path using the
 * snapshot's cwd/home anchors (never the process cwd), so rule matching and
 * workspace-root containment are deterministic w.r.t. the snapshot. Total:
 * degrades to the raw input if resolution ever fails.
 */
function resolveTarget(rawPath: string, snapshot: PolicySnapshot): string {
	try {
		return resolvePath(rawPath, snapshot.cwd, {
			normalizeUnicodeSpaces: true,
			stripAtPrefix: true,
			homeDir: snapshot.home,
		});
	} catch {
		return rawPath;
	}
}

function toPosix(path: string): string {
	return path.replace(/\\/g, "/");
}

/** True if `target` (absolute) is `root` itself or nested under it. */
function isWithinRoot(target: string, root: string): boolean {
	const t = toPosix(target);
	const r = toPosix(root).replace(/\/+$/, "");
	if (r === "") return true; // root is the filesystem root: contains everything.
	return t === r || t.startsWith(`${r}/`);
}

/**
 * Suggests the `bash(...)` specifier to offer as an "always allow" choice for a
 * command that needs approval (spec §24.1): a high-risk command must be pinned
 * to its exact normalized text (so a later wildcard can't silently widen it);
 * an ordinary command generalizes to its first ≤2 tokens plus ` *`
 * (e.g. `git push *`, `npm run *`, `ls *`).
 */
export function suggestBashSpecifier(access: CommandAccess): string {
	if (access.highRiskReason) return access.normalizedCommand;
	const prefix = access.normalizedCommand.split(" ").filter(Boolean).slice(0, 2).join(" ");
	return prefix.length > 0 ? `${prefix} *` : "*";
}

/**
 * Whether `rule` applies to `unit` for this snapshot. A rule applies when its
 * tool-name pattern matches AND its specifier (if any) matches the unit's
 * resource. For a `command` unit, `read(...)` rules additionally match against
 * the command's extracted `readPaths` (spec §10: a read deny/ask on those
 * paths overrides the bash allow).
 */
function ruleApplies(rule: Rule, unit: Unit, snapshot: PolicySnapshot, anchors: Anchors): boolean {
	if (unit.kind === "command") {
		if (matchToolName(rule.tool, snapshot.tool)) {
			return rule.specifier === undefined || matchBashCommand(rule.specifier, unit.access.normalizedCommand);
		}
		// A read(...) rule can bind to the paths a bash command reads.
		if (matchToolName(rule.tool, "read") && unit.access.readPaths.length > 0) {
			if (rule.specifier === undefined) return true;
			return unit.access.readPaths.some((p) =>
				matchPath(rule.specifier as string, resolveTarget(p, snapshot), anchors),
			);
		}
		return false;
	}
	if (unit.kind === "paths") {
		if (!matchToolName(rule.tool, snapshot.tool)) return false;
		if (rule.specifier === undefined) return true;
		return unit.paths.some((p) => matchPath(rule.specifier as string, resolveTarget(p, snapshot), anchors));
	}
	// `none`: only bare tool-name rules (no specifier) apply.
	return matchToolName(rule.tool, snapshot.tool) && rule.specifier === undefined;
}

/** Suggested "always allow" rules to offer when a unit resolves to `ask`. */
function suggestForUnit(unit: Unit, snapshot: PolicySnapshot): UnitResult["suggestedRules"] {
	if (unit.kind === "command") {
		return [{ tool: "bash", specifier: suggestBashSpecifier(unit.access), list: "allow" }];
	}
	if (unit.kind === "paths") {
		return unit.paths
			.filter((p) => p.length > 0)
			.map((p) => ({ tool: snapshot.tool, specifier: resolveTarget(p, snapshot), list: "allow" as const }));
	}
	return undefined;
}

/** Runs the mode default (spec §10 step 6) for a unit that reached it. */
function modeDefault(unit: Unit, snapshot: PolicySnapshot, anchors: Anchors): UnitResult {
	switch (snapshot.mode) {
		case "bypass":
			return { decision: "allow" };
		case "dontAsk":
			return { decision: "deny", reason: "dontAsk mode denies anything not explicitly allowed" };
		case "plan":
			// read / read-only already allowed at step 5; only mutate/exec reach here.
			return { decision: "deny", reason: "plan mode is read-only" };
		case "acceptEdits": {
			if (snapshot.capability === "mutate" && unit.kind === "paths") {
				const targets = unit.paths.filter((p) => p.length > 0);
				const allInRoot =
					targets.length > 0 &&
					targets.every((p) => isWithinRoot(resolveTarget(p, snapshot), anchors.workspaceRoot));
				if (allInRoot) return { decision: "allow" };
			}
			return {
				decision: "ask",
				reason: "acceptEdits asks outside the workspace root",
				suggestedRules: suggestForUnit(unit, snapshot),
			};
		}
		default:
			// `default` mode (and any unexpected mode → step 7 fallback): mutate/exec ask.
			return {
				decision: "ask",
				reason: "approval required by default mode",
				suggestedRules: suggestForUnit(unit, snapshot),
			};
	}
}

/** The full §10 pipeline for a single unit. */
function checkUnit(unit: Unit, snapshot: PolicySnapshot, anchors: Anchors): UnitResult {
	const { rules } = snapshot;

	// 1. deny rule.
	const denyRule = rules.find((r) => r.list === "deny" && ruleApplies(r, unit, snapshot, anchors));
	if (denyRule) return { decision: "deny", reason: `denied by rule "${denyRule.raw}"` };

	// 2. circuit breaker (above allow; §24.3).
	if (unit.kind === "command" && unit.access.circuitBreakerReason) {
		return {
			decision: "ask",
			reason: unit.access.circuitBreakerReason,
			suggestedRules: suggestForUnit(unit, snapshot),
		};
	}

	// 3. ask rule.
	const askRule = rules.find((r) => r.list === "ask" && ruleApplies(r, unit, snapshot, anchors));
	if (askRule) {
		return {
			decision: "ask",
			reason: `matched ask rule "${askRule.raw}"`,
			suggestedRules: suggestForUnit(unit, snapshot),
		};
	}

	// 4. allow rule. A high-risk command only passes on an exact (non-wildcard) allow.
	const highRisk = unit.kind === "command" ? unit.access.highRiskReason : undefined;
	if (highRisk) {
		const exactAllow = rules.find(
			(r) =>
				r.list === "allow" &&
				r.specifier !== undefined &&
				!specifierHasWildcard(r.specifier) &&
				ruleApplies(r, unit, snapshot, anchors),
		);
		if (exactAllow) return { decision: "allow" };
	} else {
		const allowRule = rules.find((r) => r.list === "allow" && ruleApplies(r, unit, snapshot, anchors));
		if (allowRule) return { decision: "allow" };
	}

	// 5a. read-capable built-in tool (read / ls / grep / find): no read deny/ask matched above.
	if (snapshot.capability === "read") return { decision: "allow" };

	// 5b. built-in read-only bash command (any mode), unless it is high-risk.
	if (unit.kind === "command" && unit.access.readonly && !unit.access.highRiskReason) {
		return { decision: "allow" };
	}

	// 6. mode default (+ 7. fallback → ask, folded into modeDefault's default branch).
	return modeDefault(unit, snapshot, anchors);
}

/** Deduplicates suggested rules by their (tool, specifier, list) identity. */
function dedupeSuggested(
	suggested: NonNullable<CheckResult["suggestedRules"]>,
): NonNullable<CheckResult["suggestedRules"]> {
	const seen = new Set<string>();
	const out: NonNullable<CheckResult["suggestedRules"]> = [];
	for (const s of suggested) {
		const key = `${s.tool} ${s.specifier ?? ""} ${s.list}`;
		if (seen.has(key)) continue;
		seen.add(key);
		out.push(s);
	}
	return out;
}

/**
 * Decides one tool call against the merged rule set + mode default (spec §10).
 * Total: any unexpected internal failure fails safe to `ask`.
 */
export function check(snapshot: PolicySnapshot): CheckResult {
	try {
		const anchors: Anchors = {
			cwd: snapshot.cwd,
			home: snapshot.home,
			workspaceRoot: snapshot.workspaceRoot,
		};
		const resource: Resource = snapshot.resource;

		if (resource.kind === "command") {
			const results = resource.accesses.map((access) => checkUnit({ kind: "command", access }, snapshot, anchors));
			return combine(results);
		}
		if (resource.kind === "paths") {
			return finalize(checkUnit({ kind: "paths", paths: resource.paths }, snapshot, anchors));
		}
		return finalize(checkUnit({ kind: "none" }, snapshot, anchors));
	} catch {
		// Fail safe (spec §18): never let the guardrail crash the tool call path.
		return { decision: "ask", reason: "permission check failed; asking to be safe" };
	}
}

/** Combines per-subcommand unit results: any deny → deny; any ask → ask; all allow → allow. */
function combine(results: UnitResult[]): CheckResult {
	if (results.length === 0) return { decision: "allow" };
	const deny = results.find((r) => r.decision === "deny");
	if (deny) return { decision: "deny", reason: deny.reason };
	const asks = results.filter((r) => r.decision === "ask");
	if (asks.length > 0) {
		const suggested = dedupeSuggested(asks.flatMap((r) => r.suggestedRules ?? []));
		return {
			decision: "ask",
			reason: asks[0].reason,
			...(suggested.length > 0 ? { suggestedRules: suggested } : {}),
		};
	}
	return { decision: "allow" };
}

/** Shapes a single-unit result into a `CheckResult`, dropping empty suggestion lists. */
function finalize(result: UnitResult): CheckResult {
	const decision: Decision = result.decision;
	if (decision === "ask" && result.suggestedRules && result.suggestedRules.length > 0) {
		return { decision, reason: result.reason, suggestedRules: result.suggestedRules };
	}
	return { decision, reason: result.reason };
}
