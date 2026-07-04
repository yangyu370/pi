const METACHARS = new Set([".", "+", "?", "^", "$", "{", "}", "(", ")", "|", "[", "]", "\\"]);

function wildcardSource(pattern: string): string {
	return pattern.replace(/[.*+?^${}()|[\]\\]/g, (ch) => (ch === "*" ? ".*" : `\\${ch}`));
}

function buildWildcardRegex(pattern: string): RegExp {
	return new RegExp(`^${wildcardSource(pattern)}$`);
}

export function matchBashCommand(specifier: string, command: string): boolean {
	const normalized = specifier.endsWith(":*") ? `${specifier.slice(0, -2)} *` : specifier;
	// A trailing " *" means "this command with any (or no) arguments", so it must also match the
	// bare base command — otherwise an "always allow npm install" rule never re-matches `npm install`.
	// The separating space stays required for the arg case, keeping the `git push` vs `git pushx` boundary.
	if (normalized.endsWith(" *")) {
		return new RegExp(`^${wildcardSource(normalized.slice(0, -2))}(?: .*)?$`).test(command);
	}
	return buildWildcardRegex(normalized).test(command);
}

export function matchToolName(pattern: string, toolName: string): boolean {
	return buildWildcardRegex(pattern).test(toolName);
}

function toPosix(path: string): string {
	return path.replace(/\\/g, "/");
}

function joinPosix(root: string, body: string): string {
	if (!body) return root || "/";
	const base = root.endsWith("/") ? root.slice(0, -1) : root;
	return `${base}/${body}`;
}

interface ResolvedAnchor {
	root: string;
	body: string;
	anyDepth: boolean;
}

function resolveAnchor(
	specifier: string,
	anchors: { cwd: string; home: string; workspaceRoot: string },
): ResolvedAnchor {
	const spec = toPosix(specifier);
	if (spec.startsWith("//")) {
		return { root: "/", body: spec.slice(2), anyDepth: false };
	}
	if (spec === "~" || spec.startsWith("~/")) {
		return { root: toPosix(anchors.home), body: spec === "~" ? "" : spec.slice(2), anyDepth: false };
	}
	if (spec.startsWith("/")) {
		return { root: toPosix(anchors.workspaceRoot), body: spec.slice(1), anyDepth: false };
	}
	const body = spec.startsWith("./") ? spec.slice(2) : spec;
	return { root: toPosix(anchors.cwd), body, anyDepth: body.length > 0 && !body.includes("/") };
}

function globToRegExpSource(pattern: string): string {
	let out = "";
	let i = 0;
	while (i < pattern.length) {
		const ch = pattern[i];
		if (ch === "*" && pattern[i + 1] === "*") {
			const precededByBoundary = i === 0 || pattern[i - 1] === "/";
			const afterIdx = i + 2;
			const followedByBoundary = afterIdx === pattern.length || pattern[afterIdx] === "/";
			if (precededByBoundary && followedByBoundary) {
				if (afterIdx < pattern.length) {
					out += "(?:.*/)?";
					i = afterIdx + 1;
				} else if (out.endsWith("/")) {
					out = `${out.slice(0, -1)}(?:/.*)?`;
					i = afterIdx;
				} else {
					out += ".*";
					i = afterIdx;
				}
				continue;
			}
		}
		if (ch === "*") {
			out += "[^/]*";
			i += 1;
			continue;
		}
		out += METACHARS.has(ch) ? `\\${ch}` : ch;
		i += 1;
	}
	return out;
}

export function matchPath(
	specifier: string,
	targetPath: string,
	anchors: { cwd: string; home: string; workspaceRoot: string },
): boolean {
	const { root, body, anyDepth } = resolveAnchor(specifier, anchors);
	const fullPattern = anyDepth ? joinPosix(joinPosix(root, "**"), body) : joinPosix(root, body);
	const regex = new RegExp(`^${globToRegExpSource(fullPattern)}$`);
	return regex.test(toPosix(targetPath));
}

export function parseRule(raw: string): { tool: string; specifier?: string } {
	const trimmed = raw.trim();
	const openIdx = trimmed.indexOf("(");
	if (openIdx === -1) {
		return { tool: trimmed, specifier: undefined };
	}
	const tool = trimmed.slice(0, openIdx).trim();
	const closeIdx = trimmed.lastIndexOf(")");
	const specifier = closeIdx > openIdx ? trimmed.slice(openIdx + 1, closeIdx) : trimmed.slice(openIdx + 1);
	return { tool, specifier };
}

export function specifierHasWildcard(specifier: string): boolean {
	return specifier.includes("*");
}
