"""Guard: A3-r39-gate - the R39 attack-class-orphan gate is revived (live, not skipped).

Check #74 used to pass-out-of-scope for EVERY draft because its input file
(attack_class_distribution.json) was never produced. A3 makes the gate live two ways:
 (1) make audit refreshes the distribution index each pin (advisory);
 (2) pre-submit-check.sh generates the index ON-DEMAND if absent before running R39,
     so a standalone pre-submit run also has a real index (with --allow-missing-index
     kept only as the producer-failed graceful fallback, not the normal path).

Asserts both wirings are present in the shipped scripts.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = ROOT / "Makefile"
PRESUBMIT = ROOT / "tools" / "pre-submit-check.sh"


class TestR39GateRevived(unittest.TestCase):
    def test_make_audit_refreshes_distribution_index(self):
        text = MAKEFILE.read_text(encoding="utf-8")
        # audit recipe block
        m = re.search(r"^audit:.*?(?=^\S)", text, re.S | re.M)
        self.assertTrue(m, "audit target not found")
        block = m.group(0)
        self.assertIn("hackerman-attack-class-distribution.py", block,
                      "A3: make audit must refresh attack_class_distribution index")
        self.assertIn("attack_class_distribution.json", block)

    def test_presubmit_generates_index_on_demand(self):
        text = PRESUBMIT.read_text(encoding="utf-8")
        self.assertIn("hackerman-attack-class-distribution.py", text,
                      "A3: pre-submit must generate the R39 distribution index on-demand")
        # the on-demand generation must be guarded by the missing-file check
        self.assertRegex(
            text,
            r'if \[ ! -f "\$_R39_DIST" \].*hackerman-attack-class-distribution\.py',
            )


if __name__ == "__main__":
    unittest.main()
