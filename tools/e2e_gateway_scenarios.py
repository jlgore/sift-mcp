#!/usr/bin/env python3
"""Drive the three PRD §10 e2e scenarios through the running gateway.

Unlike e2e_defense_matrix.py (which calls run_command in-process to prove
each layer blocks), this goes through the gateway's MCP endpoint so the
server-layer audit trail fires — producing the audit JSONL deliverable:

  S1  allow         fls -r <case>/evidence/…E01   → rc=0, sandboxed
  S2  policy deny   find <case>/evidence -exec …  → structured policy_denial
  S3  kernel block  touch <case>/evidence/…       → EROFS from bwrap

Usage (on the SIFT box, gateway already running):
  VHIR_CASE_DIR=/cases/e2e-test python tools/e2e_gateway_scenarios.py
"""

import asyncio
import json
import os

URL = os.environ.get("GATEWAY_URL", "http://127.0.0.1:4508/mcp")
CASE = os.environ.get("VHIR_CASE_DIR", "/cases/e2e-test")

SCENARIOS = [
    ("S1 allow",
     ["fls", "-r", f"{CASE}/evidence/win7-64-nfury-c-drive.E01"],
     "e2e S1: enumerate evidence filesystem (expect allow, sandboxed)"),
    ("S2 policy deny",
     ["find", f"{CASE}/evidence", "-exec", "rm", "{}", ";"],
     "e2e S2: destructive find (expect structured policy denial)"),
    ("S3 kernel block",
     ["touch", f"{CASE}/evidence/e2e-proof"],
     "e2e S3: write to evidence (expect EROFS from bwrap)"),
]


async def main() -> int:
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    async with streamablehttp_client(URL) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = [t.name for t in (await session.list_tools()).tools]
            name = next(t for t in tools if t.endswith("run_command"))
            print(f"gateway exposes {len(tools)} tools; using {name!r}\n")

            failures = 0
            for label, cmd, purpose in SCENARIOS:
                res = await session.call_tool(
                    name, {"command": cmd, "purpose": purpose}
                )
                text = "".join(
                    c.text for c in res.content if getattr(c, "text", None)
                )
                try:
                    doc = json.loads(text)
                except ValueError:
                    doc = {"raw": text}

                data = doc.get("data") or {}
                if label.startswith("S1"):
                    # sandboxed=True is asserted from the audit JSONL after
                    # the run (it lives in the audit result_summary).
                    ok = doc.get("success") is True
                elif label.startswith("S2"):
                    ok = doc.get("success") is False and (
                        "denied by policy" in doc.get("error", "")
                    )
                else:  # S3
                    ok = data.get("exit_code") not in (0, None) and (
                        "Read-only file system" in data.get("stderr", "")
                    )

                failures += 0 if ok else 1
                summary = json.dumps(doc)[:300]
                print(f"[{'PASS' if ok else 'FAIL'}] {label:16s} {summary}\n")

            print(f"{len(SCENARIOS) - failures}/{len(SCENARIOS)} scenarios passed")
            return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
