#!/usr/bin/env python3
"""Tests for Rule 82 - impact-recovery-falsification-check.py.

Anchors (honest, per the design's section 0): R82 is NOT anchored on Spark LEAD-1
(its recovery is partly defender-side / R57). The canonical FAIL anchor is a generic
EVM vault whose victim can forceWithdraw() post-impact (the permanent claim is false).
The canonical PASS anchors are (a) burned shares with no in-protocol restore, and
(b) every recovery entrypoint falsified.
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parent.parent / "impact-recovery-falsification-check.py"
_spec = importlib.util.spec_from_file_location("r82", TOOL)
r82 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(r82)


def run(text, *, severity="auto", strict=False, workspace=None, poc_dir=None):
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
        f.write(text)
        p = Path(f.name)
    try:
        return r82.check(p, workspace, poc_dir, severity, strict)
    finally:
        p.unlink(missing_ok=True)


FAIL_SURVIVES = """# Permanent direct loss of victim funds
- Severity: HIGH
This is permanent direct loss of victim funds.
## Victim Recovery Enumeration
- Impact-lands citation: Vault.sol:300
- Victim role + asset: depositor V; shares
- Recovery surface scope mode: source-only
- In-protocol recovery entrypoints enumerated:
  | entrypoint | mechanism | driven | outcome | reason |
  | Vault.sol:412 forceWithdraw() | emergency exit | source-traced | returns shares to V | callable any time |
- Verdict: all-recovery-paths-falsified
"""

PASS_NORECOVERY = """# Permanent loss: shares burned
- Severity: HIGH
permanent loss of funds; shares are burned irrecoverably.
## Victim Recovery Enumeration
- Impact-lands citation: Vault.sol:412
- Victim role + asset: depositor V; burned shares
- Recovery surface scope mode: source-only
- In-protocol recovery entrypoints enumerated:
  | entrypoint | mechanism | driven | outcome | reason |
  | excluded: re-deposit | mints new shares | n/a | does not restore burned position | excluded: cannot restore burned shares (Vault.sol:412) |
- Verdict: no-in-protocol-recovery-exists
"""

PASS_FALSIFIED = """# Permanent freezing of funds
- Severity: CRITICAL
funds are permanently frozen for the user.
## Victim Recovery Enumeration
- Impact-lands citation: Bridge.sol:88
- Victim role + asset: user V; bridged funds
- Recovery surface scope mode: source-only
- In-protocol recovery entrypoints enumerated:
  | entrypoint | mechanism | driven | outcome | reason |
  | Bridge.sol:120 claimTimeout() | timeout refund | source-traced | reverts: window already closed | timeout disabled in this config (Bridge.sol:120) |
  | Bridge.sol:150 challenge() | fraud challenge | source-traced | unreachable: V is not a bonded challenger | only bonded actors (Bridge.sol:150) |
- Verdict: all-recovery-paths-falsified
"""


class TestR82(unittest.TestCase):
    def test_fail_recovery_survives(self):
        self.assertEqual(run(FAIL_SURVIVES)["verdict"], "fail-recovery-path-survives-claim-false")

    def test_pass_no_in_protocol_recovery(self):
        self.assertEqual(run(PASS_NORECOVERY)["verdict"], "pass-recovery-enumeration-complete")

    def test_pass_all_falsified(self):
        self.assertEqual(run(PASS_FALSIFIED)["verdict"], "pass-recovery-enumeration-complete")

    def test_out_of_scope_low(self):
        self.assertEqual(run("# x\n- Severity: LOW\npermanent loss of funds.")["verdict"], "pass-out-of-scope")

    def test_not_permanent_claim(self):
        self.assertEqual(run("# x\n- Severity: HIGH\nTemporary latency degradation, self-clears.")["verdict"],
                         "pass-not-permanent-impact-claim")

    def test_fail_no_section(self):
        self.assertEqual(run("# x\n- Severity: CRITICAL\nFunds are permanently frozen and unrecoverable.")["verdict"],
                         "fail-no-recovery-enumeration-section")

    def test_fail_no_impact_lands(self):
        txt = "# x\n- Severity: HIGH\npermanent loss of funds.\n## Victim Recovery Enumeration\n- Victim role: V\n- some text no citation\n"
        self.assertEqual(run(txt)["verdict"], "fail-no-impact-lands-citation")

    def test_rebuttal_overrides_missing_section(self):
        txt = "# x\n- Severity: HIGH\npermanent loss of funds.\n<!-- r82-rebuttal: out-of-protocol recovery only; documented disabled -->\n"
        self.assertEqual(run(txt)["verdict"], "ok-rebuttal")

    def test_oversized_rebuttal_ignored(self):
        txt = ("# x\n- Severity: HIGH\npermanent loss of funds.\n<!-- r82-rebuttal: " + "z" * 250 + " -->\n")
        self.assertEqual(run(txt)["verdict"], "fail-no-recovery-enumeration-section")

    def test_cli_json_and_exit(self):
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
            f.write(FAIL_SURVIVES); p = f.name
        try:
            r = subprocess.run([sys.executable, str(TOOL), p, "--strict", "--json"],
                               capture_output=True, text=True)
            self.assertEqual(json.loads(r.stdout)["verdict"], "fail-recovery-path-survives-claim-false")
            self.assertEqual(r.returncode, 1)  # strict + fail
        finally:
            Path(p).unlink(missing_ok=True)

    def test_emit_worklist_shape(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d); (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text("function withdraw() public {}\nfunction emergencyWithdraw() external {}\n")
            out = r82.emit_worklist(ws)
            self.assertEqual(out["schema"], "auditooor.vault_recovery_surface_worklist.v1")
            self.assertTrue(any("Vault.sol" in h for h in out["recovery_surfaces"]))

    def test_schema_present(self):
        self.assertEqual(run(FAIL_SURVIVES)["schema"], "auditooor.r82_impact_recovery_falsification.v1")


if __name__ == "__main__":
    unittest.main()
