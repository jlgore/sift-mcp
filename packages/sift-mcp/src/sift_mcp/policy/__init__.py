"""Policy engine: YAML -> Rego compilation + OPA evaluation for run_command.

This package replaces the imperative checks in ``sift_mcp.security`` with a
declarative policy pipeline:

    security.yaml  -> compiler -> data.json + generated .rego
    run_command    -> parser   -> OPA input document
    OPA(input, policies)        -> structured allow/deny with ALL reasons

The parser is the shared front end: the input document it produces feeds both
OPA policy evaluation and the bubblewrap sandbox mount builder.
"""

from sift_mcp.policy.parser import DEV_PATH_TOOLS, build_input_doc

__all__ = ["build_input_doc", "DEV_PATH_TOOLS"]
