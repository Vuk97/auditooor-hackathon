import unittest
from pathlib import Path
import subprocess
import tempfile


class AuditPipelineOrderingTest(unittest.TestCase):
    MAKEFILE = Path(__file__).resolve().parents[2] / "Makefile"

    def test_direct_later_phase_execution_is_rejected(self):
        targets = (
            "audit-depth",
            "chain-synth",
            "prove-top-leads",
            "exploit-conversion-loop",
        )
        with tempfile.TemporaryDirectory() as workspace:
            for target in targets:
                result = subprocess.run(
                    ["make", "--no-print-directory", target, f"WS={workspace}"],
                    cwd=self.MAKEFILE.parent,
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(result.returncode, 2, target)
                self.assertIn("direct invocation is blocked", result.stderr, target)

    def test_full_driver_supplies_ordered_phase_tokens(self):
        makefile = self.MAKEFILE.read_text()
        calls = (
            ("audit-depth", "AUDITOOOR_PIPELINE_PHASE_TOKEN=audit-depth"),
            ("chain-synth", "AUDITOOOR_PIPELINE_PHASE_TOKEN=chain-synth"),
            ("prove-top-leads", "AUDITOOOR_PIPELINE_PHASE_TOKEN=prove-top-leads"),
            (
                "exploit-conversion-loop",
                "AUDITOOOR_PIPELINE_PHASE_TOKEN=exploit-conversion-loop",
            ),
        )
        positions = []
        for target, token in calls:
            call = f"{token} $(MAKE) --no-print-directory {target}"
            self.assertIn(call, makefile)
            positions.append(makefile.index(call))
        self.assertEqual(positions, sorted(positions))

    def test_full_driver_defers_g15_until_post_hunt_closeout(self):
        makefile = self.MAKEFILE.read_text()
        self.assertIn(
            "AUDITOOOR_DEFER_HUNT_COVERAGE=1 AUDITOOOR_DEFER_DRIVE=1 AUDITOOOR_DEFER_DATAFLOW_SLICE=1 $(MAKE) --no-print-directory audit",
            makefile,
        )
        self.assertIn(
            "canonical pipeline enforces G15 after pre-hunt, deep, and hunt stages",
            makefile,
        )
        self.assertIn('"strict_gate":"audit-complete"', makefile)

    def test_direct_audit_still_has_strict_branch(self):
        makefile = self.MAKEFILE.read_text()
        self.assertIn(
            'if [ "$(STRICT)" = "1" ]; then exit $$rc; fi;',
            makefile,
        )


if __name__ == "__main__":
    unittest.main()
