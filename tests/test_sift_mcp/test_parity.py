"""CI gate: OPA decisions must match security.py decisions.

Runs the curated parity corpus (both no-case and active-case contexts) plus a
small seeded fuzz batch through both oracles and asserts 100% boolean parity.
The large fuzz run lives in `python -m sift_mcp.policy.parity` for the report.
"""

import shutil
from pathlib import Path

import pytest
from sift_mcp.catalog import clear_catalog_cache
from sift_mcp.policy import parity
from sift_mcp.policy.evaluator import reset_evaluator

_REPO_OPA = Path(__file__).resolve().parents[2] / "tools" / "opa"
_HAS_OPA = shutil.which("opa") is not None or _REPO_OPA.exists()
needs_opa = pytest.mark.skipif(not _HAS_OPA, reason="opa binary not available")


def _fmt(divergences) -> str:
    return "\n".join(
        f"{' '.join(r.command)} — secpy={'DENY' if r.secpy_denied else 'ALLOW'} "
        f"opa={'DENY' if r.opa_denied else 'ALLOW'}"
        for r in divergences
    )


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    clear_catalog_cache()
    reset_evaluator()
    monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
    yield
    clear_catalog_cache()
    reset_evaluator()


@needs_opa
class TestParity:
    def test_curated_no_case(self):
        cases = [c for c in parity.CURATED if not c.requires_case]
        div = [r for r in parity.run_cases(cases) if not r.parity]
        assert not div, "OPA/security.py divergence:\n" + _fmt(div)

    def test_fuzz_smoke(self):
        cases = parity.build_fuzz_cases(250, seed=99)
        div = [r for r in parity.run_cases(cases) if not r.parity]
        assert not div, "OPA/security.py divergence:\n" + _fmt(div)

    def test_curated_active_case(self, tmp_path):
        case_dir = tmp_path / "CASE-001"
        case_dir.mkdir()
        (case_dir / "CASE.yaml").write_text("case_id: parity\n")
        (case_dir / "out").mkdir()
        cases = [c for c in parity.CURATED if c.requires_case]
        div = [
            r
            for r in parity.run_cases(cases, active_case_dir=str(case_dir))
            if not r.parity
        ]
        assert not div, "OPA/security.py divergence:\n" + _fmt(div)
