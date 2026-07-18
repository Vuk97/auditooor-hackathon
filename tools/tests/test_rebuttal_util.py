"""Tests for the shared rebuttal-marker gate (Rank 3 friction fix).

Covers:
  * the shared util `apply_rebuttal_gate` directly (accept / loud-reject / absent);
  * end-to-end wiring in `no-fault-injection-check.py` proving:
      - the false-positive (silent over-length drop) is now LOUD; and
      - the CONTROL true-positive (genuine fault-injection) STILL FAILs, both
        with a short-but-valid rebuttal (deferred) and with an over-length one
        (rejected -> gate still fires).
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

from lib.rebuttal_util import REBUTTAL_MAX_LEN, apply_rebuttal_gate  # noqa: E402

NO_FAULT = TOOLS / "no-fault-injection-check.py"

# A line containing this token is a genuine, actionable fault-injection signal
# per FAULT_RE in no-fault-injection-check.py.
GENUINE_FAULT_LINE = "The PoC wraps the KV store with injectFault(err) to force the panic."


class ApplyRebuttalGateUnit(unittest.TestCase):
    def test_accept_short_rebuttal(self) -> None:
        payload: dict = {"gate": "X"}
        handled = apply_rebuttal_gate(payload, "short reason", stderr=False)
        self.assertTrue(handled)
        self.assertEqual(payload["verdict"], "ok-rebuttal")
        self.assertEqual(payload["rebuttal"], "short reason")
        self.assertNotIn("rebuttal_rejected", payload)

    def test_accept_boundary_exactly_cap(self) -> None:
        payload: dict = {"gate": "X"}
        reason = "a" * REBUTTAL_MAX_LEN  # exactly 200 -> still accepted (<=)
        self.assertTrue(apply_rebuttal_gate(payload, reason, stderr=False))
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_reject_over_length_is_loud_not_silent(self) -> None:
        payload: dict = {"gate": "X"}
        reason = "b" * (REBUTTAL_MAX_LEN + 1)  # 201 -> rejected
        handled = apply_rebuttal_gate(payload, reason, stderr=False)
        # Not "handled": caller must continue to its FAIL path (no return 0).
        self.assertFalse(handled)
        # ...but the rejection is recorded LOUDLY on the payload.
        self.assertTrue(payload["rebuttal_rejected"])
        self.assertEqual(payload["rebuttal_length"], REBUTTAL_MAX_LEN + 1)
        self.assertIn(str(REBUTTAL_MAX_LEN), payload["rebuttal_reason"])
        # Crucially it did NOT pass the gate via ok-rebuttal.
        self.assertNotIn("verdict", payload)

    def test_no_rebuttal_is_unhandled_and_quiet(self) -> None:
        payload: dict = {"gate": "X"}
        self.assertFalse(apply_rebuttal_gate(payload, None, stderr=False))
        self.assertFalse(apply_rebuttal_gate(payload, "", stderr=False))
        self.assertNotIn("rebuttal_rejected", payload)
        self.assertNotIn("verdict", payload)

    def test_custom_accept_verdict(self) -> None:
        payload: dict = {}
        apply_rebuttal_gate(payload, "ok", accept_verdict="pass-cooperative", stderr=False)
        self.assertEqual(payload["verdict"], "pass-cooperative")


def _run(draft: Path):
    proc = subprocess.run(
        [sys.executable, str(NO_FAULT), str(draft), "--severity", "High", "--json"],
        capture_output=True,
        text=True,
    )
    return proc.returncode, json.loads(proc.stdout), proc.stderr


class NoFaultInjectionWiring(unittest.TestCase):
    """End-to-end: the fix is wired and the true-positive still fires."""

    def setUp(self) -> None:
        self.tmp = Path(self.enterContext(_tmpdir()))

    def _draft(self, name: str, body: str) -> Path:
        p = self.tmp / name
        p.write_text(body)
        return p

    def test_short_rebuttal_defers(self) -> None:
        draft = self._draft(
            "short.md",
            f"# Finding\nSeverity: High\n{GENUINE_FAULT_LINE}\n"
            "<!-- r20-rebuttal: bounded source-backed exception src/x.go:10 -->\n",
        )
        rc, payload, _ = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_over_length_rebuttal_is_loud_AND_gate_still_fails(self) -> None:
        # CONTROL: a genuine fault-injection PoC (true-positive). The rebuttal is
        # present but over-length, so historically it was SILENTLY dropped. Now:
        #  (a) rejection is recorded loudly (payload + stderr), AND
        #  (b) the gate STILL FAILs on the genuine fault (no return-0 escape).
        reason = "z" * (REBUTTAL_MAX_LEN + 50)
        draft = self._draft(
            "long.md",
            f"# Finding\nSeverity: High\n{GENUINE_FAULT_LINE}\n"
            f"<!-- r20-rebuttal: {reason} -->\n",
        )
        rc, payload, stderr = _run(draft)
        # Loud on the payload
        self.assertTrue(payload.get("rebuttal_rejected"))
        self.assertEqual(payload.get("rebuttal_length"), len(reason))
        # Loud on stderr
        self.assertIn("REJECTED", stderr)
        self.assertIn(str(REBUTTAL_MAX_LEN), stderr)
        # The over-length rebuttal did NOT green the gate: true-positive still FAILs.
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-fault-injection")

    def test_no_rebuttal_genuine_fault_fails(self) -> None:
        # Baseline true-positive with no marker at all.
        draft = self._draft(
            "none.md",
            f"# Finding\nSeverity: High\n{GENUINE_FAULT_LINE}\n",
        )
        rc, payload, _ = _run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-fault-injection")
        self.assertNotIn("rebuttal_rejected", payload)


# --- tiny stdlib-only tempdir contextmanager (enterContext needs 3.11) ---
import contextlib
import tempfile


@contextlib.contextmanager
def _tmpdir():
    d = tempfile.mkdtemp(prefix="rebuttal_util_test_")
    try:
        yield d
    finally:
        import shutil

        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
