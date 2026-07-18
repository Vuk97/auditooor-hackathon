"""Guard test - R76 excerpt verification is MULTILINE-AWARE (2026-07-10).

Root cause: a genuine multiline code_excerpt is verbatim source but the file
wraps statements differently than the agent's excerpt (the agent reflows a
wrapped statement onto one line). The prior check picked only the single LONGEST
line as the needle, which (a) credited a whole block whenever its longest line
was verbatim EVEN IF other lines were fabricated (an R76 anti-hallucination hole)
and (b) could drop a genuine finding whose longest line was an annotation.

Fix: split on newlines, keep substantive lines, and for a multiline excerpt
credit ONLY IF every substantive line is a whitespace-normalized verbatim
substring of the cited source. Mutation-verified BOTH directions below.
"""
from __future__ import annotations
import importlib.util, json, tempfile, unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


HSB = _load("hsb_ml", _ROOT / "hunt-sidecar-bridge.py")
GUARD = _load("r76g_ml", _ROOT / "r76-hallucination-guard.py")

# Source with a statement WRAPPED across two physical lines (result = ... / total;)
# to prove reflow-tolerance: the excerpt puts it on one line and must still match.
_SRC = (
    "function getShares(uint balance) view internal returns (uint) {\n"
    "\t\tif (exponent == 1)\n"
    "\t\t\treturn balance;\n"
    "\t\tuint result = balance * shares\n"
    "\t\t\t/ total;\n"
    "\t\treturn result;\n"
    "\t}\n"
)

# Genuine multiline excerpt: every substantive line is verbatim source (the
# ``uint result = balance * shares / total;`` line is reflowed onto one line).
_GENUINE = (
    "function getShares(uint balance) view internal returns (uint) {\n"
    "\t\tif (exponent == 1)\n"
    "\t\t\treturn balance;\n"
    "\t\tuint result = balance * shares / total;\n"
)

# Same excerpt, ONE substantive line replaced by a fabricated line.
_FABRICATED = (
    "function getShares(uint balance) view internal returns (uint) {\n"
    "\t\tselfdestruct(payable(attacker)); // injected line not in source\n"
    "\t\t\treturn balance;\n"
    "\t\tuint result = balance * shares / total;\n"
)


def _ws() -> Path:
    d = Path(tempfile.mkdtemp())
    (d / "src").mkdir()
    (d / "src" / "Shares.sol").write_text(_SRC)
    return d


def _inner(excerpt: str) -> dict:
    return {"applies_to_target": "yes", "confidence": "high",
            "file_line": "src/Shares.sol:1-6", "code_excerpt": excerpt}


class TestMultilineGrepExcerpt(unittest.TestCase):
    def test_grep_genuine_multiline_credited(self):
        ws = _ws()
        cf = ws / "src" / "Shares.sol"
        self.assertTrue(HSB._grep_excerpt(ws, _GENUINE, cited_file=cf))

    def test_grep_fabricated_line_downgraded(self):
        ws = _ws()
        cf = ws / "src" / "Shares.sol"
        # The LONGEST line (the function signature) is still verbatim - the old
        # longest-line-only check would WRONGLY pass this. Multiline-aware fails.
        self.assertFalse(HSB._grep_excerpt(ws, _FABRICATED, cited_file=cf))

    def test_single_line_behavior_preserved(self):
        ws = _ws()
        cf = ws / "src" / "Shares.sol"
        # single verbatim line -> credited
        self.assertTrue(HSB._grep_excerpt(
            ws, "uint result = balance * shares / total;", cited_file=cf))
        # single abridged line -> downgraded
        self.assertFalse(HSB._grep_excerpt(
            ws, "uint result = balance * shares ... total;", cited_file=cf))


class TestMultilineSourceExistenceCheck(unittest.TestCase):
    def test_genuine_multiline_passes_gate(self):
        ws = _ws()
        chk = HSB.r76_source_existence_check(_inner(_GENUINE), ws)
        self.assertTrue(chk["pass_gate"], chk.get("reason"))

    def test_fabricated_multiline_soft_downgraded(self):
        ws = _ws()
        chk = HSB.r76_source_existence_check(_inner(_FABRICATED), ws)
        self.assertFalse(chk["pass_gate"])
        # real file+line, only the excerpt fails -> SOFT (coverage preserved)
        self.assertTrue(chk.get("soft_excerpt_fail"))
        out = json.loads(HSB._apply_r76_downgrade(
            {"result": json.dumps(_inner(_FABRICATED))}, chk)["result"])
        self.assertTrue(out.get("r76_excerpt_unverified"))
        self.assertNotIn("r76_source_existence_fail", out)


class TestStandaloneGuardMultiline(unittest.TestCase):
    def test_guard_genuine_multiline_grep_hits(self):
        ws = _ws()
        # tree grep is line-oriented, so the reflowed line is not asserted here;
        # use the non-reflowed genuine subset (all lines exist verbatim per-line).
        genuine = (
            "function getShares(uint balance) view internal returns (uint) {\n"
            "\t\tif (exponent == 1)\n"
            "\t\t\treturn balance;\n"
        )
        self.assertTrue(GUARD.grep_excerpt(ws, genuine))

    def test_guard_fabricated_line_downgraded(self):
        ws = _ws()
        fab = (
            "function getShares(uint balance) view internal returns (uint) {\n"
            "\t\tselfdestruct(payable(attacker)); // injected not in source\n"
            "\t\t\treturn balance;\n"
        )
        self.assertFalse(GUARD.grep_excerpt(ws, fab))


if __name__ == "__main__":
    unittest.main()
