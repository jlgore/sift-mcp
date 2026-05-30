"""Parse a run_command invocation into an OPA policy input document.

This mirrors two pieces of the existing enforcement so the compiled Rego
policies can reproduce ``security.py`` decisions exactly:

* the path classification in ``sift_mcp.tools.generic.run_command``
  (input path vs. output path vs. /dev device specifier), and
* the flag normalization in ``sift_mcp.security.sanitize_extra_args``
  (``arg.split("=")[0]`` so ``--output=/x`` is matched as ``--output``).

The document it returns is the single source of truth consumed by BOTH the
OPA evaluator (Layer 1) and the bubblewrap mount builder (Layer 2): ``paths``
become read-only binds, ``output_paths`` become read-write binds.

Paths are resolved with ``Path.resolve()`` (following symlinks), matching what
``validate_input_path`` / ``validate_output_path`` / ``validate_rm_targets`` do
today, so the naive ``startswith`` checks in the generated Rego land on the
same absolute paths the Python checks would.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sift_mcp.security import get_output_flags

# Tools whose positional args may legitimately be /dev/ device specifiers
# (disk forensics), where a /dev path must NOT be treated as a blocked input.
# Mirrors ``_DEV_PATH_TOOLS`` in ``sift_mcp.tools.generic``.
DEV_PATH_TOOLS = frozenset(
    {
        "mount",
        "umount",
        "mmls",
        "fls",
        "icat",
        "img_stat",
        "blkid",
        "fdisk",
        "losetup",
        "fsstat",
        "ifind",
        "istat",
        "mmcat",
        "sigfind",
        "tsk_recover",
        "sorter",
        "dd",
    }
)


def _looks_like_path(arg: str) -> bool:
    """Match generic.py's heuristic for "this argument is a filesystem path"."""
    return arg.startswith("/") or arg.startswith("..") or "/" in arg


def _resolve(path: str) -> str:
    """Resolve a path the way the security validators do (symlinks included).

    Falls back to the original string if resolution fails (e.g. invalid path),
    so the policy layer still sees *something* to evaluate rather than crashing.
    """
    try:
        return str(Path(path).resolve())
    except (OSError, ValueError, RuntimeError):
        return path


def build_input_doc(
    command: list[str],
    *,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Serialize a run_command call into the OPA policy input document.

    Args:
        command: The command as a list, ``[binary, *args]`` (as received by
            ``run_command``). ``binary`` may carry a path prefix; only its
            basename is used as ``tool``, matching ``run_command``.
        context: Optional runtime context (case_id, case_dir, examiner,
            sandbox_enabled, ...) merged into the document. Command-derived
            keys always win over context keys of the same name.

    Returns:
        A JSON-serializable dict with keys: tool, raw_command, args, flags,
        paths, output_paths, device_paths (plus any context fields).

    Raises:
        ValueError: If the command is empty.
    """
    if not command:
        raise ValueError("Empty command")

    binary = command[0].split("/")[-1]  # strip path prefix, as run_command does
    args = list(command[1:])
    output_flags = get_output_flags()

    # Normalized flag tokens: "--output=/x" -> "--output". Positional args are
    # excluded because every blocked/dangerous flag starts with "-", so this is
    # equivalent to security.py's per-arg ``split("=")[0]`` check for matching.
    flags = [a.split("=", 1)[0] for a in args if a.startswith("-")]

    paths: list[str] = []
    output_paths: list[str] = []
    device_paths: list[str] = []

    if binary == "rm":
        # rm: every non-flag arg is a deletion target. In the live pipeline
        # these pass through both validate_rm_targets AND validate_input_path,
        # so they belong in ``paths`` (which feeds rm_protection + path_policy).
        # Unlike the generic case below, no-slash relative targets count too.
        for arg in args:
            if not arg.startswith("-"):
                paths.append(_resolve(arg))
    else:
        prev_was_output_flag = False
        for arg in args:
            # flag=value: validate the value portion as a path
            if "=" in arg and arg.startswith("-"):
                flag_part, value = arg.split("=", 1)
                if value and _looks_like_path(value):
                    if value.startswith("/dev/") and binary in DEV_PATH_TOOLS:
                        device_paths.append(value)
                    elif flag_part in output_flags:
                        output_paths.append(_resolve(value))
                    else:
                        paths.append(_resolve(value))
                prev_was_output_flag = False
                continue
            # bare flag: remember whether it expects an output path next
            if arg.startswith("-"):
                prev_was_output_flag = arg in output_flags
                continue
            # positional: classify as device / output / input path
            if _looks_like_path(arg):
                if arg.startswith("/dev/") and binary in DEV_PATH_TOOLS:
                    device_paths.append(arg)
                elif prev_was_output_flag:
                    output_paths.append(_resolve(arg))
                else:
                    paths.append(_resolve(arg))
            prev_was_output_flag = False

    doc: dict[str, Any] = {
        "tool": binary,
        "raw_command": " ".join(command),
        "args": args,
        "flags": flags,
        "paths": paths,
        "output_paths": output_paths,
        "device_paths": device_paths,
    }
    if context:
        # Command-derived keys take precedence over caller-supplied context.
        doc = {**context, **doc}
    return doc
