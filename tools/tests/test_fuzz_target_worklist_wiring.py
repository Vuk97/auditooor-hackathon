"""Regression: the fuzz-target WORKLIST (--from-inscope) must be invoked by the
audit-deep driver. Before this, the only Makefile call to fuzz-target-corpus.py was
`fuzz-quick` in campaign-TAGGING mode (needs a finished fuzz_results.json), so on any
workspace the needs-fuzz worklist was never generated and fuzz-target-completeness-check
was a permanent no-op - the whole fuzz-target capability was dead-on-arrival."""
import re
import subprocess
import unittest
from pathlib import Path

MK = Path(__file__).resolve().parents[2] / "Makefile"


class FuzzTargetWorklistWiring(unittest.TestCase):
    def setUp(self):
        self.text = MK.read_text(encoding="utf-8")

    def test_from_inscope_invoked_in_makefile(self):
        self.assertRegex(self.text, r"fuzz-target-corpus\.py --from-inscope",
                         "audit-deep must materialize the worklist via --from-inscope")

    def test_invocation_is_non_fatal(self):
        # the --from-inscope line must be advisory (|| echo ... continuing), never a hard fail
        m = re.search(r"fuzz-target-corpus\.py --from-inscope[^\n]*\n[^\n]*", self.text)
        self.assertIsNotNone(m)
        self.assertIn("||", m.group(0), "worklist generation must be non-fatal")

    def test_make_n_audit_deep_shows_worklist(self):
        out = subprocess.run(
            ["make", "-n", "audit-deep", "WS=/tmp/x", "AUDIT_DEEP_SKIP_AUDIT_PREREQ=1"],
            cwd=MK.parent, capture_output=True, text=True)
        self.assertIn("fuzz-target-corpus.py --from-inscope", out.stdout)


if __name__ == "__main__":
    unittest.main()
