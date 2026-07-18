"""Guard test - bridge R76: abridged-excerpt-with-REAL-file is a SOFT downgrade
(coverage preserved), only a hallucinated FILE is a HARD fail (hollow).
Root cause: 783/910 near-intents verdicts wrongly buried hollow because agents
wrote abridged ("...") excerpts that cannot grep-match verbatim source, while the
file+line were real."""
from __future__ import annotations
import importlib.util, json, tempfile, types
from pathlib import Path

_MOD = Path(__file__).resolve().parents[1] / "hunt-sidecar-bridge.py"
_spec = importlib.util.spec_from_file_location("hsb", _MOD)
m = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(m)


def _ws():
    d = Path(tempfile.mkdtemp())
    (d / "src").mkdir()
    (d / "src" / "lib.rs").write_text(
        "pub fn burn(\n    &mut self,\n    amount: u128,\n) {\n    self.token.internal_withdraw(amount);\n}\n")
    return d


def _inner(**kw):
    base = {"applies_to_target": "yes", "confidence": "high",
            "file_line": "src/lib.rs:1"}
    base.update(kw)
    return base


class Test(__import__("unittest").TestCase):
    def test_abridged_excerpt_real_file_is_soft(self):
        ws = _ws()
        chk = m.r76_source_existence_check(
            _inner(code_excerpt="self.token.internal_withdraw(amount); ... FtBurn{...}"), ws)
        self.assertFalse(chk["pass_gate"])
        self.assertTrue(chk.get("soft_excerpt_fail"))
        # downgrade applies the SOFT flag, not the hard one
        sc = {"result": json.dumps(_inner(code_excerpt="x ... y"))}
        out = json.loads(m._apply_r76_downgrade(sc, chk)["result"])
        self.assertTrue(out.get("r76_excerpt_unverified"))
        self.assertNotIn("r76_source_existence_fail", out)
        self.assertEqual(out.get("applies_to_target"), "no")

    def test_missing_file_is_hard(self):
        ws = _ws()
        chk = m.r76_source_existence_check(
            _inner(file_line="src/ghost.rs:9", code_excerpt="whatever long enough excerpt here xxxxx"), ws)
        self.assertFalse(chk["pass_gate"])
        self.assertFalse(chk.get("soft_excerpt_fail"))
        out = json.loads(m._apply_r76_downgrade({"result": json.dumps(_inner())}, chk)["result"])
        self.assertTrue(out.get("r76_source_existence_fail"))

    def test_real_excerpt_passes(self):
        ws = _ws()
        chk = m.r76_source_existence_check(
            _inner(code_excerpt="self.token.internal_withdraw(amount);"), ws)
        self.assertTrue(chk["pass_gate"])


if __name__ == "__main__":
    __import__("unittest").main()
