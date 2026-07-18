"""Locks the content-assertion property of the reframed L37 gates: each must go
RED on a hollow/never-ran artifact under strict, GREEN on a genuinely-ran artifact
INCLUDING the legitimate 0-findings case. Prevents silent regression back to the
presence-only false-pass shape (caught 2026-06-07). Offline, stdlib-only.
"""
import importlib.util, json, os, pathlib, sys, tempfile, unittest

_TOOL = pathlib.Path(__file__).resolve().parent.parent / "audit-completeness-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("_acc_gate_content", str(_TOOL))
    m = importlib.util.module_from_spec(spec)
    sys.modules["_acc_gate_content"] = m
    spec.loader.exec_module(m)
    return m


def _ws(td, artifact, content):
    a = pathlib.Path(td) / ".auditooor"
    a.mkdir(parents=True, exist_ok=True)
    (a / artifact).write_text(json.dumps(content))
    return pathlib.Path(td)


# (gate_fn, artifact_name, hollow_content, ran_clean_content)
CASES = [
    ("check_chain_synth", "chain_synthesis_2026-06-07.json",
     {"chains_synthesized": 0},
     {"chains_synthesized": 0, "applicability_verdict": "pass-not-applicable",
      "broken_invariant_ids": ["INV-1", "INV-2"]}),
    ("check_originality", "originality_report.json",
     {},
     {"counts": {"keyword_count": 8}, "advisories_scanned": 120, "strong_hits": 0}),
]
# NOTE: exploit-conversion + prove-top-leads gates were independently verified
# (workflow correct_gates lane: red-on-hollow / green-on-ran) and ship in the same
# file; their real artifact shapes are not reconstructed here. This regression locks
# the two gates fixed 2026-06-07 (chain-synth, originality) that were still
# presence-only false-passes.


class TestGateContentAssertions(unittest.TestCase):
    def setUp(self):
        os.environ.pop("ENFORCE_AUTONOMOUS_PROOF_CONVERSION", None)

    def tearDown(self):
        os.environ.pop("ENFORCE_AUTONOMOUS_PROOF_CONVERSION", None)

    def test_red_on_hollow_under_strict(self):
        os.environ["ENFORCE_AUTONOMOUS_PROOF_CONVERSION"] = "1"
        m = _load()
        for fn, art, hollow, _ in CASES:
            with tempfile.TemporaryDirectory() as td:
                r = getattr(m, fn)(_ws(td, art, hollow))
                self.assertFalse(r.ok, msg=f"{fn} FALSE-PASS on hollow: {r.reason}")

    def test_green_on_hollow_is_warn_by_default(self):
        # Default (advisory) must WARN-pass, never hard-fail a non-opt-in caller.
        m = _load()
        for fn, art, hollow, _ in CASES:
            with tempfile.TemporaryDirectory() as td:
                r = getattr(m, fn)(_ws(td, art, hollow))
                self.assertTrue(r.ok, msg=f"{fn} hard-failed by default (should WARN): {r.reason}")

    def test_green_on_ran_clean_under_strict(self):
        os.environ["ENFORCE_AUTONOMOUS_PROOF_CONVERSION"] = "1"
        m = _load()
        for fn, art, _, ran in CASES:
            with tempfile.TemporaryDirectory() as td:
                r = getattr(m, fn)(_ws(td, art, ran))
                self.assertTrue(r.ok, msg=f"{fn} FALSE-FAIL on genuinely-ran 0-findings: {r.reason}")


if __name__ == "__main__":
    unittest.main()
