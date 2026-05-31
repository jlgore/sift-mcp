/**
 * Pi / oh-my-pi policy gate hook.
 *
 * TypeScript extension that intercepts tool_call events for bash commands
 * and evaluates them against the sift-mcp OPA policy engine via subprocess.
 *
 * Install: add this file's directory to Pi's hook/extension paths, or
 * run `python3 -m sift_mcp.hooks.install --harness pi` to configure.
 *
 * Requires: python3 and sift_mcp on PYTHONPATH in the Pi process env.
 */

import type { HookAPI } from "@oh-my-pi/pi-coding-agent/extensibility/hooks";
import { execSync } from "child_process";

export default function siftPolicyGate(pi: HookAPI): void {
  pi.on("tool_call", async (event, _ctx) => {
    // Only intercept bash/shell tool calls.
    if (event.toolName !== "bash") return;

    const cmd = String(event.input.command ?? "").trim();
    if (!cmd) return;

    try {
      // Call the Python gate with the command as argv.
      // gate.py exits 0 (allow) or 2 (deny, reason on stderr).
      execSync(
        `python3 -m sift_mcp.hooks.gate ${JSON.stringify(cmd)}`,
        {
          stdio: ["pipe", "pipe", "pipe"],
          timeout: 5000,
          env: process.env,
        }
      );
      // Exit 0 -- allowed, proceed normally.
    } catch (err: any) {
      // execSync throws on nonzero exit.
      if (err.status === 2) {
        const reason = (err.stderr?.toString() ?? "").trim()
          || "command denied by sift-mcp policy";
        return { block: true, reason };
      }
      // Any other error (timeout, crash) -- fail open, log warning.
      const msg = err.stderr?.toString().trim() || err.message;
      console.warn(`[sift-policy] gate error (fail-open): ${msg}`);
    }
  });
}
