import type { CommandAccess } from "./types.ts";

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

const READONLY_GIT_SUBCOMMANDS: ReadonlySet<string> = new Set(["status", "diff", "log", "show"]);

const HIGH_RISK_LEADING_PROGRAMS: ReadonlySet<string> = new Set([
	"watch",
	"setsid",
	"ionice",
	"flock",
	// Wrapper programs run another command indirectly; the analyzer only inspects
	// the leading token, so the real program stays hidden. Treat them as high-risk
	// so they can never be auto-approved as "readonly" or matched by a wildcard rule.
	"sudo",
	"doas",
	"env",
	"xargs",
	"timeout",
	"nice",
	"nohup",
]);

const READ_PATH_COMMANDS: ReadonlySet<string> = new Set(["cat", "head", "tail", "grep", "ls"]);

const MUTATE_PATH_COMMANDS: ReadonlySet<string> = new Set(["rm", "mv", "cp"]);

const CIRCUIT_BREAKER_PROGRAMS: ReadonlySet<string> = new Set(["rm", "rmdir"]);

const CRITICAL_SYSTEM_PATH_PREFIXES: readonly string[] = [
	"/etc",
	"/usr",
	"/bin",
	"/System",
	"/Library",
	"/var",
	"/boot",
	"/dev",
	"/root",
];
const BRACED_HOME = "$" + "{HOME}";

const GLOB_CHARS_RE = /[*?[]/;

export function isReadonlyGitSubcommand(args: string[]): boolean {
	return args.length > 0 && READONLY_GIT_SUBCOMMANDS.has(args[0]);
}

interface Token {
	value: string;
	quoted: boolean;
}

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
			if (quote === '"' && ch === "\\") {
				const next = text[i + 1];
				if (next !== undefined) {
					value += next;
					active = true;
					i += 2;
					continue;
				}
			}
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
		if (ch === "\\") {
			const next = text[i + 1];
			if (next !== undefined) {
				value += next;
				active = true;
				i += 2;
				continue;
			}
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

function normalizeWhitespace(text: string): string {
	return text.trim().replace(/\s+/g, " ");
}

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
			if (quote === '"' && ch === "\\") {
				current += ch;
				const next = command[i + 1];
				if (next !== undefined) {
					current += next;
					i += 2;
					continue;
				}
				i++;
				continue;
			}
			current += ch;
			if (ch === quote) {
				quote = undefined;
			} else if (quote === '"') {
				if (ch === "`") {
					highRiskReason ??= "command substitution (`...`) inside double quotes";
				} else if (ch === "$" && command[i + 1] === "(") {
					highRiskReason ??= "command substitution $(...) inside double quotes";
				}
			}
			i++;
			continue;
		}
		if (ch === '"' || ch === "'") {
			quote = ch;
			current += ch;
			i++;
			continue;
		}
		if (ch === "\\") {
			current += ch;
			const next = command[i + 1];
			if (next !== undefined) {
				current += next;
				i += 2;
				continue;
			}
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
		if (ch === ">" || ch === "<") {
			highRiskReason ??= `shell redirection (${ch})`;
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

function hasWriteCapableFlag(_program: string, _args: readonly Token[]): boolean {
	return false;
}

function criticalPathReason(target: string): string | undefined {
	const stripped = target.replace(/\/+$/, "") || "/";
	const normalized = stripped.startsWith("/") ? stripped.replace(/^\/+/, "/") : stripped;
	if (normalized === "/") {
		return `rm/rmdir target is the filesystem root ("${target}")`;
	}
	if (
		normalized === "~" ||
		normalized.startsWith("~/") ||
		normalized === "$HOME" ||
		normalized.startsWith("$HOME/") ||
		normalized === BRACED_HOME ||
		normalized.startsWith(`${BRACED_HOME}/`)
	) {
		return `rm/rmdir target is the home directory ("${target}")`;
	}
	for (const prefix of CRITICAL_SYSTEM_PATH_PREFIXES) {
		if (normalized === prefix || normalized.startsWith(`${prefix}/`)) {
			return `rm/rmdir target is under the system path ${prefix} ("${target}")`;
		}
	}
	return undefined;
}

const VALUE_CONSUMING_FLAGS: Record<string, ReadonlySet<string>> = {
	head: new Set(["-n", "-c"]),
	tail: new Set(["-n", "-c"]),
	grep: new Set(["-A", "-B", "-C", "-m", "-e"]),
};

function extractPathArgs(program: string, args: readonly Token[]): string[] {
	const valueFlags = VALUE_CONSUMING_FLAGS[program];
	const paths: string[] = [];
	let patternFromFlag = false;
	for (let i = 0; i < args.length; i++) {
		const token = args[i];
		if (token.value.startsWith("-")) {
			if (valueFlags?.has(token.value)) {
				if (program === "grep" && token.value === "-e") patternFromFlag = true;
				i++; // consume this flag's value token
			}
			continue;
		}
		paths.push(token.value);
	}
	if (program === "grep" && !patternFromFlag && paths.length > 0) {
		paths.shift(); // leading positional is the search pattern, not a file
	}
	return paths;
}

function analyzeSingleCommand(segment: string): CommandAccess {
	const command = segment.trim();
	const normalizedCommand = normalizeWhitespace(command);
	const tokens = tokenizeWords(command);

	if (tokens.length === 0) {
		return { command, normalizedCommand, readPaths: [], mutatePaths: [], readonly: false };
	}

	const program = tokens[0].value;
	const args = tokens.slice(1);
	const pathArgs = extractPathArgs(program, args);
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
		for (const value of pathArgs) {
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
		readPaths: READ_PATH_COMMANDS.has(program) ? pathArgs : [],
		mutatePaths: MUTATE_PATH_COMMANDS.has(program) ? pathArgs : [],
		readonly,
		deletesPaths: CIRCUIT_BREAKER_PROGRAMS.has(program),
		circuitBreakerReason,
		highRiskReason,
	};
}

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
