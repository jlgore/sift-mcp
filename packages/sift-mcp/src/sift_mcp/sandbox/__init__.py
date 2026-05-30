"""Layer 2: bubblewrap (bwrap) sandbox for forensic tool execution.

Wraps every tool invocation in a Linux-namespace sandbox at the execution layer
(``executor.execute``): evidence read-only, network unshared, host processes
hidden. No daemon, no image — each invocation gets its own namespace that exits
with the tool.

The mount layout is driven by the same parsed paths the policy engine uses
(``policy.parser.build_input_doc``): input/device paths become read-only binds,
output paths become read-write binds.
"""

from sift_mcp.sandbox.bwrap import build_sandbox_prefix, load_profile, verify_bwrap

__all__ = ["build_sandbox_prefix", "load_profile", "verify_bwrap"]
