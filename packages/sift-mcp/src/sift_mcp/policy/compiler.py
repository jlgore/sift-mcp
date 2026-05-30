"""Compile security.yaml into OPA-evaluable Rego policies + data.json.

Flow:
    security.yaml
      -> yaml.safe_load
      -> SecurityPolicy (Pydantic validation)
      -> data.json            (the policy lists, resolved + absolute)
      -> templates/*.rego.j2  (Jinja2)  -> compiled/*.rego

Run once at MCP startup (compile-many, evaluate-many) or via CLI:

    python -m sift_mcp.policy.compiler compile <security.yaml> --output <dir>
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined

from sift_mcp.policy.schema import SecurityPolicy

_TEMPLATES_DIR = Path(__file__).parent / "templates"

_HEADER = "# Generated from security.yaml by sift_mcp.policy.compiler — do not edit directly."

# Category packages rendered from <name>.rego.j2, in evaluation order. The
# decision aggregator is rendered separately and references these by name.
POLICY_PACKAGES = [
    "denied_binaries",
    "tool_blocked_flags",
    "shell_metacharacters",
    "awk_scanning",
    "rm_protection",
    "path_policy",
    "output_path_policy",
]


class CompilerError(Exception):
    """Raised when security.yaml cannot be loaded, validated, or rendered."""


def load_policy(yaml_path: str | Path) -> SecurityPolicy:
    """Load and validate security.yaml into a SecurityPolicy."""
    path = Path(yaml_path)
    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise CompilerError(f"Cannot read security.yaml at {path}: {exc}") from exc
    try:
        return SecurityPolicy.model_validate(raw)
    except Exception as exc:  # pydantic.ValidationError and friends
        raise CompilerError(f"Invalid security.yaml at {path}: {exc}") from exc


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        undefined=StrictUndefined,  # fail loudly on a missing template var
        keep_trailing_newline=True,
        autoescape=False,  # generating Rego, not HTML
    )


def compile_policy(yaml_path: str | Path, output_dir: str | Path) -> dict:
    """Compile security.yaml to <output_dir>/{*.rego, data.json}.

    Returns the data dict that was written (handy for tests/inspection).
    """
    policy = load_policy(yaml_path)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # 1. data.json — the policy lists.
    data = policy.to_data()
    (out / "data.json").write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")

    # 2. Category policies from templates.
    env = _env()
    for pkg in POLICY_PACKAGES:
        template = env.get_template(f"{pkg}.rego.j2")
        rendered = template.render(
            header=_HEADER,
            awk_danger_regex=policy.awk_danger_regex,
        )
        (out / f"{pkg}.rego").write_text(rendered)

    # 3. Decision aggregator referencing every category package.
    decision = env.get_template("decision.rego.j2")
    (out / "decision.rego").write_text(
        decision.render(header=_HEADER, policy_packages=POLICY_PACKAGES)
    )

    return data


def _main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="sift_mcp.policy.compiler")
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("compile", help="Compile security.yaml to Rego + data.json")
    c.add_argument("security_yaml", help="Path to security.yaml")
    c.add_argument(
        "--output",
        "-o",
        default="compiled",
        help="Output directory for .rego + data.json (default: compiled/)",
    )
    args = parser.parse_args(argv)

    if args.command == "compile":
        data = compile_policy(args.security_yaml, args.output)
        print(
            f"Compiled {args.security_yaml} -> {args.output}/ "
            f"({len(POLICY_PACKAGES) + 1} .rego files, "
            f"{len(data)} data keys)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
