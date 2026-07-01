/**
 * Pure specifier-matching primitives for the permission rule engine.
 *
 * These functions have no knowledge of rules, modes, or decisions — they only
 * answer "does this specifier match that command/path/tool name". The engine
 * (later PRs) combines them with rule lists and mode defaults.
 *
 * Semantics implemented here (docs/superpowers/specs/2026-07-01-permission-check-design.md §11):
 * - Bash specifiers: `*` matches anything, including spaces. A `*` immediately
 *   preceded by a literal space enforces a word boundary there (because the
 *   space itself must appear literally in the command). A trailing `:*` is
 *   equivalent to a trailing ` *`; a `:` anywhere else is literal.
 * - Path specifiers: gitignore-style 4 anchors — `//x` filesystem-absolute,
 *   `~/x` home-relative, `/x` project-root-relative, `x` / `./x` cwd-relative
 *   (a bare name with no further `/` matches at any depth under cwd). `*`
 *   matches a single path segment, `**` crosses directories.
 */

/** Characters that are regex metacharacters and must be escaped when matched literally. */
const METACHARS = new Set([".", "+", "?", "^", "$", "{", "}", "(", ")", "|", "[", "]", "\\"]);

/**
 * Builds an anchored (`^...$`) RegExp from a pattern where `*` means "match
 * anything, including nothing" and every other character is literal. Used for
 * bash command specifiers and tool-name globs, which have no segment/boundary
 * structure to respect beyond literal characters (including literal spaces).
 */
function buildWildcardRegex(pattern: string): RegExp {
	const source = pattern.replace(/[.*+?^${}()|[\]\\]/g, (ch) => (ch === "*" ? ".*" : `\\${ch}`));
	return new RegExp(`^${source}$`);
}

/**
 * Matches a bash command against a `bash(...)` rule specifier.
 *
 * `*` matches anything (including spaces). A `*` immediately after a literal
 * space enforces a word boundary there: `ls *` matches `ls -la` but not
 * `lsof` (no space follows "ls" in "lsof"), while `ls*` matches both. A
 * trailing `:*` is normalized to a trailing ` *` before matching; a `:`
 * anywhere else in the specifier is literal.
 */
export function matchBashCommand(specifier: string, command: string): boolean {
	const normalized = specifier.endsWith(":*") ? `${specifier.slice(0, -2)} *` : specifier;
	return buildWildcardRegex(normalized).test(command);
}

/**
 * Matches a tool name against a rule's `tool` pattern (e.g. `"*"`, `"db_*"`).
 * Same "`*` matches anything" semantics as {@link matchBashCommand}, without
 * the space/word-boundary nuance since tool names have no internal structure.
 */
export function matchToolName(pattern: string, toolName: string): boolean {
	return buildWildcardRegex(pattern).test(toolName);
}

function toPosix(path: string): string {
	return path.replace(/\\/g, "/");
}

/** Joins an absolute POSIX root with a (possibly empty) relative body, avoiding double slashes. */
function joinPosix(root: string, body: string): string {
	if (!body) return root || "/";
	const base = root.endsWith("/") ? root.slice(0, -1) : root;
	return `${base}/${body}`;
}

interface ResolvedAnchor {
	root: string;
	body: string;
	/** Whether a bare (no further `/`) body should match at any depth under root. */
	anyDepth: boolean;
}

/**
 * Resolves a path specifier's gitignore-style 4-anchor prefix into an
 * absolute root plus the remaining pattern body:
 * - `//x`  -> filesystem-absolute (root = "/")
 * - `~/x`  -> home-relative (root = anchors.home)
 * - `/x`   -> project-root-relative (root = anchors.workspaceRoot)
 * - `x` / `./x` -> cwd-relative (root = anchors.cwd); a bare body with no
 *   further `/` matches at any depth under cwd (a bare ".env" behaves like
 *   a double-star segment followed by "/.env").
 */
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

/**
 * Translates a resolved absolute glob pattern (POSIX, `*` = one path segment,
 * `**` = zero or more segments) into an anchored RegExp source fragment.
 * Every other character is matched literally.
 */
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
					// "**/" mid-pattern: zero or more full segments, including the trailing slash.
					out += "(?:.*/)?";
					i = afterIdx + 1;
				} else if (out.endsWith("/")) {
					// trailing "/**": optionally the slash plus anything beneath it.
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

/**
 * Matches an absolute target path against a gitignore-style path specifier.
 * See the module doc for the 4-anchor prefix rules and `*` / `**` semantics.
 */
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

/**
 * Splits a rule's raw text into its tool name and optional specifier, e.g.
 * `"bash(git push *)"` -> `{ tool: "bash", specifier: "git push *" }`,
 * `"bash"` -> `{ tool: "bash", specifier: undefined }`.
 */
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

/**
 * True if the specifier contains a `*`; used by the engine to distinguish an
 * exact allow from a prefix allow when gating high-risk commands.
 */
export function specifierHasWildcard(specifier: string): boolean {
	return specifier.includes("*");
}
