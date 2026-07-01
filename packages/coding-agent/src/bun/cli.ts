#!/usr/bin/env node
import { APP_NAME } from "../config.ts";

process.title = APP_NAME;
// Bun emits warnings to stderr even when they should be suppressed — this
// prevents them from corrupting the TUI display in interactive mode.
process.emitWarning = (() => {}) as typeof process.emitWarning;

import { restoreSandboxEnv } from "./restore-sandbox-env.ts";

restoreSandboxEnv();

await import("./register-bedrock.ts");
await import("../cli.ts");
