from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "escalation-chain-precheck.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("escalation_chain_precheck", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load escalation-chain-precheck.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EscalationChainPrecheckTests(unittest.TestCase):
    def _write_markdown(self, body: str) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "finding.md"
        path.write_text(textwrap.dedent(body).strip() + "\n", encoding="utf-8")
        return path

    def test_reports_missing_evidence_advisory_only(self) -> None:
        module = _load_module()
        path = self._write_markdown(
            """
            ## Chain/escalation attempt
            Attempted to escalate this primitive into a stronger listed impact.
            """
        )

        payload = module.inspect_file(path)

        self.assertEqual(payload["status"], "blocked_missing_evidence")
        self.assertFalse(payload["passes_precheck"])
        self.assertTrue(payload["advisory_only"])
        self.assertTrue(payload["does_not_claim_exploitability"])
        self.assertEqual(
            payload["missing_checks"],
            [
                "named primitive(s)",
                "attempted stronger impact",
                "material distinction from base issue",
                "why escalation holds or fails",
            ],
        )

    def test_accepts_structured_escalation_evidence(self) -> None:
        module = _load_module()
        path = self._write_markdown(
            """
            ## Chain/escalation attempt
            - primitives: unchecked settlement replay + stale accounting snapshot
            - attempted stronger impact: escalate from queue delay to temporary freezing of all pending withdrawals
            - material distinction: unlike the base issue, the chain couples replay with stale accounting so every pending withdrawal inherits the same stale cap
            - escalation result: fails because the replay dies at the epoch boundary and the broader freeze never survives the listed-impact contract
            """
        )

        payload = module.inspect_file(path)

        self.assertEqual(payload["status"], "ok")
        self.assertTrue(payload["passes_precheck"])
        self.assertEqual(payload["missing_checks"], [])
        for check in payload["checks"]:
            self.assertTrue(check["present"], check)
            self.assertGreaterEqual(len(check["evidence"]), 1, check)
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")

    def test_cli_strict_mode_fails_when_evidence_is_incomplete(self) -> None:
        path = self._write_markdown(
            """
            ## Chain/escalation attempt
            - primitives: unchecked settlement replay
            - attempted stronger impact: temporary freezing of all pending withdrawals
            """
        )

        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--strict", str(path)],
            capture_output=True,
            text=True,
        )

        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "blocked_missing_evidence")
        self.assertIn("material distinction from base issue", payload["missing_checks"])
        self.assertIn("why escalation holds or fails", payload["missing_checks"])

    def test_cli_default_mode_stays_zero_for_advisory_blockers(self) -> None:
        path = self._write_markdown(
            """
            ## Chain/escalation attempt
            - primitives: unchecked settlement replay
            """
        )

        proc = subprocess.run(
            [sys.executable, str(SCRIPT), str(path)],
            capture_output=True,
            text=True,
        )

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "blocked_missing_evidence")
        self.assertTrue(payload["advisory_only"])


if __name__ == "__main__":
    unittest.main()
