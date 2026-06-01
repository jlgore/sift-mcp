"""Decompose a shell command line into its constituent simple commands.

The harness policy gate receives a *full shell command line* (e.g.
``cat /evidence/f | grep x && rm -rf /evidence``).  Evaluated as one flat
``shlex.split`` the policy only sees the first token (``cat``) as the tool, so a
dangerous command hidden after an operator — or inside ``$(...)`` — is invisible
to Layer 1.  This module splits the line into every simple command it contains
so each is policy-checked on its own.

Primary path: **bashlex**, a real bash-grammar parser.  We walk the AST and
collect every ``CommandNode`` — including those inside pipelines, ``&&``/``||``/
``;`` lists, subshells, and command substitutions — returning each as an
``[tool, *args]`` argv with redirects and leading env-assignments stripped.

Fallback path: a **shlex** operator-split, used when bashlex is unavailable or
cannot parse the line (exotic syntax).  It handles the common ``&&``/``||``/
``|``/``;`` chains while respecting quotes, but does not descend into command
substitutions.  Either way, Layer 2 (the bwrap sandbox, evidence read-only) is
the backstop for anything the parser misses — so this is defense in depth, not a
single point of failure.
"""

from __future__ import annotations

import logging
import shlex

logger = logging.getLogger(__name__)

# Shell control operators that separate one simple command from the next.
_SEPARATORS = {";", "&&", "||", "|", "&", "|&", "\n"}

# Redirect operators (shlex fallback): the operator AND its following target
# token are dropped from the command's argv.
_REDIRECTS = {">", ">>", "<", "<<", "<<<", "2>", "2>>", "&>", ">&", "&>>"}


def decompose_command_line(raw: str) -> list[list[str]]:
    """Return every simple command in *raw* as an ``[tool, *args]`` argv.

    Never raises: on any parse failure it degrades (bashlex → shlex → bare
    split), and an unparseable line falls back to the whole line as a single
    command so the caller still evaluates *something*.
    """
    if not raw or not raw.strip():
        return []
    cmds = _bashlex_commands(raw)
    if cmds is not None:
        return cmds
    return _shlex_commands(raw)


# ── bashlex (primary) ──────────────────────────────────────────────────────────


def _bashlex_commands(raw: str) -> list[list[str]] | None:
    """Collect commands via the bashlex AST, or None to signal fallback."""
    try:
        import bashlex
    except ImportError:
        return None
    try:
        trees = bashlex.parse(raw)
    except Exception as exc:  # noqa: BLE001 — bashlex raises various parse errors
        logger.debug("bashlex could not parse %r (%s); using shlex fallback", raw, exc)
        return None

    cmds: list[list[str]] = []
    for tree in trees:
        _collect(tree, cmds)
    # An empty result (e.g. a line that is only a comment or assignment) is a
    # valid "nothing to check" — but return None so the caller's fallback can
    # still try, matching the "never silently drop" intent only when bashlex
    # produced no command at all from non-empty input.
    return cmds if cmds else None


def _collect(node, cmds: list[list[str]]) -> None:
    """Recursively gather CommandNodes (incl. nested substitutions) into *cmds*."""
    kind = getattr(node, "kind", None)

    if kind == "command":
        argv: list[str] = []
        for part in getattr(node, "parts", []) or []:
            pkind = getattr(part, "kind", None)
            if pkind == "word":
                argv.append(part.word)
                # A word may embed command substitutions ($(...) / `...`).
                for sub in getattr(part, "parts", []) or []:
                    _collect(sub, cmds)
            elif pkind == "assignment":
                # Never the tool; only recurse for a substitution in its value.
                for sub in getattr(part, "parts", []) or []:
                    _collect(sub, cmds)
            elif pkind == "redirect":
                # Redirect target is not part of argv, but may hide a sub.
                out = getattr(part, "output", None)
                for sub in getattr(out, "parts", []) or []:
                    _collect(sub, cmds)
        if argv:
            cmds.append(argv)
        return

    if kind == "commandsubstitution":
        _collect(node.command, cmds)
        return

    # Container nodes (list / pipeline / compound / function …): recurse.
    for child in getattr(node, "parts", []) or []:
        _collect(child, cmds)
    for child in getattr(node, "list", []) or []:
        _collect(child, cmds)
    inner = getattr(node, "command", None)
    if inner is not None and kind not in ("command", "commandsubstitution"):
        _collect(inner, cmds)


# ── shlex (fallback) ───────────────────────────────────────────────────────────


def _shlex_commands(raw: str) -> list[list[str]]:
    """Operator-split fallback that respects quotes but ignores substitutions."""
    try:
        lex = shlex.shlex(raw, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        tokens = list(lex)
    except ValueError:
        # Unbalanced quotes etc. — last resort: best-effort whole-line split.
        try:
            return [shlex.split(raw)]
        except ValueError:
            return [raw.split()]

    cmds: list[list[str]] = []
    cur: list[str] = []
    skip_next = False
    for tok in tokens:
        if skip_next:
            skip_next = False
            continue
        if tok in _REDIRECTS:
            skip_next = True  # also drop the redirect target
            continue
        if tok in _SEPARATORS:
            cur = _strip_assignments(cur)
            if cur:
                cmds.append(cur)
            cur = []
            continue
        cur.append(tok)
    cur = _strip_assignments(cur)
    if cur:
        cmds.append(cur)
    return cmds


def _is_assignment(tok: str) -> bool:
    """True for a ``NAME=value`` env-assignment token."""
    if "=" not in tok or tok.startswith("="):
        return False
    return tok.split("=", 1)[0].isidentifier()


def _strip_assignments(argv: list[str]) -> list[str]:
    """Drop leading ``FOO=bar`` tokens so the tool is the actual binary."""
    i = 0
    while i < len(argv) and _is_assignment(argv[i]):
        i += 1
    return argv[i:]
