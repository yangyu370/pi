import { resolvePath } from "../../utils/paths.ts";
import { matchBashCommand, matchPath, matchToolName, specifierHasWildcard } from "./rule-matcher.ts";
import type { CheckResult, CommandAccess, Decision, PolicySnapshot, Resource, Rule } from "./types.ts";

type Anchors = { cwd: string; home: string; workspaceRoot: string };

type Unit = { kind: "command"; access: CommandAccess } | { kind: "paths"; paths: string[] } | { kind: "none" };

type UnitResult = Required<Pick<CheckResult, "decision">> & {
	reason?: string;
	suggestedRules?: NonNullable<CheckResult["suggestedRules"]>;
};

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

function isWithinRoot(target: string, root: string): boolean {
	const t = toPosix(target);
	const r = toPosix(root).replace(/\/+$/, "");
	if (r === "") return true; // root is the filesystem root: contains everything.
	return t === r || t.startsWith(`${r}/`);
}

export function suggestBashSpecifier(access: CommandAccess): string | undefined {
	if (access.highRiskReason) return access.normalizedCommand || undefined;
	const prefix = access.normalizedCommand.split(" ").filter(Boolean).slice(0, 2).join(" ");
	// An empty/degenerate command has no meaningful prefix; never suggest `bash(*)` (allow-all).
	return prefix.length > 0 ? `${prefix} *` : undefined;
}

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
		if (
			(matchToolName(rule.tool, "edit") || matchToolName(rule.tool, "write")) &&
			unit.access.mutatePaths.length > 0
		) {
			// Deleting a file is not editing it: an edit/write allow rule must not
			// silently authorize a bash delete (rm/rmdir). Deny rules still apply so
			// a protective deny(edit ...) keeps catching deletions.
			if (rule.list === "allow" && unit.access.deletesPaths) return false;
			if (rule.specifier === undefined) return true;
			const matches = (p: string): boolean =>
				matchPath(rule.specifier as string, resolveTarget(p, snapshot), anchors);
			return rule.list === "allow" ? unit.access.mutatePaths.every(matches) : unit.access.mutatePaths.some(matches);
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

function suggestForUnit(unit: Unit, snapshot: PolicySnapshot): UnitResult["suggestedRules"] {
	if (unit.kind === "command") {
		const specifier = suggestBashSpecifier(unit.access);
		return specifier !== undefined ? [{ tool: "bash", specifier, list: "allow" }] : undefined;
	}
	if (unit.kind === "paths") {
		return unit.paths
			.filter((p) => p.length > 0)
			.map((p) => ({ tool: snapshot.tool, specifier: resolveTarget(p, snapshot), list: "allow" as const }));
	}
	return undefined;
}

function modeDefault(unit: Unit, snapshot: PolicySnapshot, anchors: Anchors): UnitResult {
	switch (snapshot.mode) {
		case "bypass":
			return { decision: "allow" };
		case "dontAsk":
			return { decision: "deny", reason: "dontAsk mode denies anything not explicitly allowed" };
		case "plan":
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
			return {
				decision: "ask",
				reason: "approval required by default mode",
				suggestedRules: suggestForUnit(unit, snapshot),
			};
	}
}

function checkUnit(unit: Unit, snapshot: PolicySnapshot, anchors: Anchors): UnitResult {
	const { rules } = snapshot;

	const denyRule = rules.find((r) => r.list === "deny" && ruleApplies(r, unit, snapshot, anchors));
	if (denyRule) return { decision: "deny", reason: `denied by rule "${denyRule.raw}"` };

	// Circuit breakers stay above allow rules and never offer "always allow".
	if (unit.kind === "command" && unit.access.circuitBreakerReason) {
		return { decision: "ask", reason: unit.access.circuitBreakerReason };
	}

	const askRule = rules.find((r) => r.list === "ask" && ruleApplies(r, unit, snapshot, anchors));
	if (askRule) {
		return {
			decision: "ask",
			reason: `matched ask rule "${askRule.raw}"`,
			suggestedRules: suggestForUnit(unit, snapshot),
		};
	}

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

	if (snapshot.capability === "read") return { decision: "allow" };

	if (unit.kind === "command" && unit.access.readonly && !unit.access.highRiskReason) {
		return { decision: "allow" };
	}

	return modeDefault(unit, snapshot, anchors);
}

function dedupeSuggested(
	suggested: NonNullable<CheckResult["suggestedRules"]>,
): NonNullable<CheckResult["suggestedRules"]> {
	const seen = new Set<string>();
	const out: NonNullable<CheckResult["suggestedRules"]> = [];
	for (const s of suggested) {
		const key = `${s.tool}\0${s.specifier ?? ""}\0${s.list}`;
		if (seen.has(key)) continue;
		seen.add(key);
		out.push(s);
	}
	return out;
}

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
		return { decision: "ask", reason: "permission check failed; asking to be safe" };
	}
}

function combine(results: UnitResult[]): CheckResult {
	if (results.length === 0) return { decision: "ask", reason: "no analyzable command; asking to be safe" };
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

function finalize(result: UnitResult): CheckResult {
	const decision: Decision = result.decision;
	if (decision === "ask" && result.suggestedRules && result.suggestedRules.length > 0) {
		return { decision, reason: result.reason, suggestedRules: result.suggestedRules };
	}
	return { decision, reason: result.reason };
}
