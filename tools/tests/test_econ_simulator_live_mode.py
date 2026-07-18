#!/usr/bin/env python3
"""PR 207-b (iter10 T4) — econ-simulator live-mode offline tests.

Five offline tests covering the halmos-output classification cascade
(design §3.5) and the advisory-only invariant (design §5 / §6). Every
test mocks `subprocess.run` / `subprocess.Popen` / `shutil.which` so no
real halmos or anvil binary is ever invoked. No network, no RPC, fully
offline.

Tests (each maps to design §7.2):

  1. `test_live_mode_counterexample_parsed_correctly`
     Mocked halmos stdout contains `Counterexample:` → manifest
     `status: counterexample`, ce.txt file emitted, advisory flags
     preserved.

  2. `test_live_mode_no_counterexample_parsed_correctly`
     Mocked halmos exits 0 with UNSAT/clean stdout → manifest
     `status: no-counterexample`, no ce.txt, advisory flags preserved.

  3. `test_live_mode_timeout_parsed_correctly`
     Mocked halmos exits 124 (timeout(1) sentinel) → manifest
     `status: timeout`, advisory flags preserved.

  4. `test_live_mode_halmos_crash_parsed_as_error`
     Mocked halmos exits non-zero with no counterexample markers +
     garbage stderr → manifest `status: error`, stderr_log sibling
     cited, advisory flags preserved.

  5. `test_live_mode_output_still_advisory_only`
     HARD-NEGATIVE regression lock (design §6): iterate every status
     path (counterexample / no-counterexample / timeout / error) and
     assert every manifest carries:
        advisory: true
        severity_upgrade_allowed: false
        evidence_matrix_contributes: false
     A future refactor that accidentally flips a flag on the
     counterexample path dies here. FM-001 + FM-002 + FM-016 guard.

Plus: `test_parse_halmos_output_unit` exercises the pure classification
helper directly (no mocks); this is not one of the 5 required tests but
aids debuggability and is kept deliberately cheap.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "tools" / "econ-simulator.py"


def _load_tool_module():
    """Import tools/econ-simulator.py as a module (hyphenated filename)."""
    spec = importlib.util.spec_from_file_location(
        "econ_simulator_tool", TOOL_PATH,
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _make_bundle(
    tmp: Path,
    with_harness: bool = True,
    harness_manifest: Optional[Dict[str, Any]] = None,
    harness_files: Optional[Dict[str, str]] = None,
) -> Path:
    """Build a packaged-bundle skeleton for live-mode testing.

    Includes a fake `<bundle>/econ-simulator/harness.t.sol` so
    `_select_harness` has a file to pick. The file contents are
    irrelevant — the mocked halmos never reads them.
    """
    bundle = tmp / "packaged" / "r77-06"
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "source-draft.md").write_text(
        "## Test finding\n"
        "**Severity**: Medium\n\n"
        "Target: `CtfCollateralAdapter` — balance-delta defect.\n"
    )
    (bundle / "evidence-matrix.json").write_text(json.dumps({
        "schema_version": 1,
        "severity": "MEDIUM",
        "rows": [],
        "summary": {"ready_verdict": "UNKNOWN"},
    }, indent=2))
    (bundle / "manifest.json").write_text(json.dumps({
        "workspace": "polymarket",
    }, indent=2))
    if with_harness:
        (bundle / "econ-simulator").mkdir(parents=True, exist_ok=True)
        (bundle / "econ-simulator" / "harness.t.sol").write_text(
            "// offline-test harness — halmos is mocked; content unused\n"
            "contract harness {}\n"
        )
    if harness_manifest is not None:
        (bundle / "harness-binding-manifest.json").write_text(
            json.dumps(harness_manifest, indent=2)
        )
    if harness_files:
        for rel_path, content in harness_files.items():
            path = bundle / rel_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
    return bundle


class _FakePopen:
    """Drop-in replacement for subprocess.Popen used by anvil spawn.

    Supports the .pid / .terminate() / .kill() / .wait() shape
    live_mode_run's finally block calls. The test suite never actually
    spawns an anvil process; we only verify the live_mode_run logic
    and confirm terminate() is attempted.
    """
    terminate_count = 0
    kill_count = 0

    def __init__(self, *args, **kwargs) -> None:
        self.pid = 99999
        self._terminated = False

    def terminate(self) -> None:
        _FakePopen.terminate_count += 1
        self._terminated = True

    def kill(self) -> None:
        _FakePopen.kill_count += 1
        self._terminated = True

    def wait(self, timeout: Optional[float] = None) -> int:
        return 0

    def poll(self) -> Optional[int]:
        return 0 if self._terminated else None

    @property
    def stdout(self) -> Any:
        return None

    @property
    def stderr(self) -> Any:
        return None


def _run_live_mode(
    mod,
    bundle: Path,
    halmos_exit_code: int,
    halmos_stdout: str,
    halmos_stderr: str = "",
) -> Dict[str, Any]:
    """Invoke live_mode_run with halmos/anvil/readiness mocked.

    Returns the manifest dict produced by live_mode_run.
    """
    _FakePopen.terminate_count = 0
    _FakePopen.kill_count = 0

    out_path = bundle / "econ-simulator" / "A-DONATION-CAPTURE.json"

    with mock.patch.object(mod.shutil, "which", side_effect=lambda name: f"/usr/local/bin/{name}") as _which_mock, \
         mock.patch.object(mod.subprocess, "Popen", _FakePopen), \
         mock.patch.object(mod, "_probe_anvil_ready", return_value=True), \
         mock.patch.object(mod, "_pick_free_port", return_value=8545), \
         mock.patch.object(
             mod, "_run_halmos",
             return_value=(halmos_exit_code, halmos_stdout, halmos_stderr),
         ):
        payload = mod.live_mode_run(
            angle="A-DONATION-CAPTURE",
            bundle=bundle,
            out_path=out_path,
            targets=["CtfCollateralAdapter"],
            replay_manifest_path=None,
            replay_manifest=None,
            replay_summary=None,
            cli_rpc_url="https://offline-test.invalid/rpc",
            halmos_timeout_seconds=300,
        )
    return payload


class EconSimulatorLiveModeTest(unittest.TestCase):

    # ------------------------------------------------------------------
    # 1. Counterexample path — SAT markers in stdout.
    # ------------------------------------------------------------------
    def test_live_mode_counterexample_parsed_correctly(self) -> None:
        mod = _load_tool_module()
        with tempfile.TemporaryDirectory() as tmp:
            bundle = _make_bundle(Path(tmp))
            stdout = (
                "Running 1 test for harness:invariant_share_price_non_decreasing\n"
                "Counterexample:\n"
                "    caller:       0xdeadbeef\n"
                "    arg0:         0x00...10\n"
                "Ran 1 test suite in 187s: 0 passed, 1 failed.\n"
            )
            payload = _run_live_mode(
                mod, bundle,
                halmos_exit_code=0,
                halmos_stdout=stdout,
            )

            self.assertEqual(payload["status"], "counterexample")
            self.assertEqual(payload["mode"], "live")
            self.assertEqual(payload["angle"], "A-DONATION-CAPTURE")
            self.assertIn("counterexample_path", payload)
            self.assertEqual(payload["counterexample_path"], "A-DONATION-CAPTURE.ce.txt")

            ce_file = bundle / "econ-simulator" / "A-DONATION-CAPTURE.ce.txt"
            self.assertTrue(ce_file.is_file())
            self.assertIn("Counterexample:", ce_file.read_text())

            # Advisory-only invariants — locked.
            self.assertTrue(payload["advisory"])
            self.assertFalse(payload["severity_upgrade_allowed"])
            self.assertFalse(payload["evidence_matrix_contributes"])

            # anvil was terminated in the finally block.
            self.assertGreaterEqual(_FakePopen.terminate_count, 1)

    # ------------------------------------------------------------------
    # 2. No-counterexample path — UNSAT / exit 0 / clean stdout.
    # ------------------------------------------------------------------
    def test_live_mode_no_counterexample_parsed_correctly(self) -> None:
        mod = _load_tool_module()
        with tempfile.TemporaryDirectory() as tmp:
            bundle = _make_bundle(Path(tmp))
            stdout = (
                "Running 1 test for harness:invariant_share_price_non_decreasing\n"
                "[PASS] invariant_share_price_non_decreasing\n"
                "Ran 1 test suite in 42s: 1 passed, 0 failed.\n"
            )
            payload = _run_live_mode(
                mod, bundle,
                halmos_exit_code=0,
                halmos_stdout=stdout,
            )

            self.assertEqual(payload["status"], "no-counterexample")
            self.assertNotIn("counterexample_path", payload)
            ce_file = bundle / "econ-simulator" / "A-DONATION-CAPTURE.ce.txt"
            self.assertFalse(ce_file.is_file())

            # Advisory-only invariants.
            self.assertTrue(payload["advisory"])
            self.assertFalse(payload["severity_upgrade_allowed"])
            self.assertFalse(payload["evidence_matrix_contributes"])

    # ------------------------------------------------------------------
    # 3. Timeout path — exit 124 sentinel.
    # ------------------------------------------------------------------
    def test_live_mode_timeout_parsed_correctly(self) -> None:
        mod = _load_tool_module()
        with tempfile.TemporaryDirectory() as tmp:
            bundle = _make_bundle(Path(tmp))
            payload = _run_live_mode(
                mod, bundle,
                halmos_exit_code=124,
                halmos_stdout="(truncated by timeout)\n",
                halmos_stderr="timeout: sending signal TERM to command 'halmos'\n",
            )

            self.assertEqual(payload["status"], "timeout")
            self.assertIn("exit 124", payload["reason"])
            # duration_seconds should be an int (not necessarily positive in mocked time).
            self.assertIn("duration_seconds", payload)
            self.assertIsInstance(payload["duration_seconds"], int)

            # Advisory-only invariants.
            self.assertTrue(payload["advisory"])
            self.assertFalse(payload["severity_upgrade_allowed"])
            self.assertFalse(payload["evidence_matrix_contributes"])

    def test_live_mode_uses_binding_manifest_contract_name(self) -> None:
        """Angle-keyed harnesses must execute with the manifest's contract selector."""
        mod = _load_tool_module()
        harness_manifest = {
            "schema_version": 1,
            "generator": "tools/submission-packager.py",
            "draft_angle_ids": ["A-DONATION-CAPTURE"],
            "entries": [
                {
                    "angle_id": "A-DONATION-CAPTURE",
                    "family": "vault",
                    "source_harness": "tools/invariants/families/vault/RedemptionBounds.t.sol",
                    "bundle_harness": "harnesses/A-DONATION-CAPTURE.t.sol",
                    "contract_name": "RedemptionBounds",
                    "origin": "copied",
                    "execution_contract": {
                        "tool": "econ-simulator",
                        "argv": [
                            "python3",
                            "${AUDITOOOR_DIR}/tools/econ-simulator.py",
                            "--bundle",
                            "${BUNDLE_ROOT}",
                            "--angle",
                            "A-DONATION-CAPTURE",
                        ],
                        "requires": ["AUDITOOOR_DIR", "BUNDLE_ROOT"],
                    },
                }
            ],
            "unresolved_angles": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            bundle = _make_bundle(
                Path(tmp),
                with_harness=False,
                harness_manifest=harness_manifest,
                harness_files={
                    "harnesses/A-DONATION-CAPTURE.t.sol": "contract RedemptionBounds {}\n",
                },
            )
            captured: Dict[str, Any] = {}

            def _fake_run_halmos(**kwargs):
                captured.update(kwargs)
                return (0, "[PASS] invariant_share_price_non_decreasing\n", "")

            with mock.patch.object(mod.shutil, "which", side_effect=lambda name: f"/usr/local/bin/{name}"), \
                 mock.patch.object(mod.subprocess, "Popen", _FakePopen), \
                 mock.patch.object(mod, "_probe_anvil_ready", return_value=True), \
                 mock.patch.object(mod, "_pick_free_port", return_value=8545), \
                 mock.patch.object(mod, "_run_halmos", side_effect=_fake_run_halmos):
                payload = mod.live_mode_run(
                    angle="A-DONATION-CAPTURE",
                    bundle=bundle,
                    out_path=bundle / "econ-simulator" / "A-DONATION-CAPTURE.json",
                    targets=["CtfCollateralAdapter"],
                    replay_manifest_path=None,
                    replay_manifest=None,
                    replay_summary=None,
                    cli_rpc_url="https://offline-test.invalid/rpc",
                    halmos_timeout_seconds=300,
                )

            self.assertEqual(payload["status"], "no-counterexample")
            self.assertEqual(captured["contract_name"], "RedemptionBounds")
            self.assertEqual(
                captured["harness_path"],
                bundle / "harnesses" / "A-DONATION-CAPTURE.t.sol",
            )

    def test_live_mode_blocks_ambiguous_legacy_harness_selection(self) -> None:
        """Multiple legacy harnesses without a binding manifest must fail closed."""
        mod = _load_tool_module()
        with tempfile.TemporaryDirectory() as tmp:
            bundle = _make_bundle(
                Path(tmp),
                with_harness=False,
                harness_files={
                    "harnesses/A-ONE.t.sol": "contract OneHarness {}\n",
                    "harnesses/A-TWO.t.sol": "contract TwoHarness {}\n",
                },
            )
            payload = mod.live_mode_run(
                angle="A-DONATION-CAPTURE",
                bundle=bundle,
                out_path=bundle / "econ-simulator" / "A-DONATION-CAPTURE.json",
                targets=["CtfCollateralAdapter"],
                replay_manifest_path=None,
                replay_manifest=None,
                replay_summary=None,
                cli_rpc_url="https://offline-test.invalid/rpc",
                halmos_timeout_seconds=300,
            )
            self.assertEqual(payload["status"], "error")
            self.assertIn(
                "multiple harnesses present but harness-binding-manifest.json is missing",
                payload["reason"],
            )

    # ------------------------------------------------------------------
    # 4. halmos crash path — non-zero exit, no counterexample markers.
    # ------------------------------------------------------------------
    def test_live_mode_halmos_crash_parsed_as_error(self) -> None:
        mod = _load_tool_module()
        with tempfile.TemporaryDirectory() as tmp:
            bundle = _make_bundle(Path(tmp))
            payload = _run_live_mode(
                mod, bundle,
                halmos_exit_code=2,
                halmos_stdout="",
                halmos_stderr=(
                    "halmos: internal error: RuntimeError: failed to load "
                    "symbol table from bytecode\n"
                ),
            )

            self.assertEqual(payload["status"], "error")
            self.assertIn("exit", payload["reason"])
            self.assertIn("2", payload["reason"])
            # stderr_log sibling is cited on error.
            self.assertEqual(payload.get("stderr_log"), "A-DONATION-CAPTURE.stderr.log")
            stderr_file = bundle / "econ-simulator" / "A-DONATION-CAPTURE.stderr.log"
            self.assertTrue(stderr_file.is_file())

            # Advisory-only invariants.
            self.assertTrue(payload["advisory"])
            self.assertFalse(payload["severity_upgrade_allowed"])
            self.assertFalse(payload["evidence_matrix_contributes"])

    # ------------------------------------------------------------------
    # 5. Advisory-only hard-negative regression lock (design §6).
    # ------------------------------------------------------------------
    def test_live_mode_output_still_advisory_only(self) -> None:
        """Every live-mode status path produces an advisory-only manifest.

        This is the FM-002 guard: a future refactor that accidentally
        flips `evidence_matrix_contributes` or `severity_upgrade_allowed`
        on a counterexample run dies here before it reaches review. Gate
        promotion is PR 207-e's exclusive domain.
        """
        mod = _load_tool_module()

        status_cases: List[Tuple[str, int, str, str]] = [
            # (expected_status, exit_code, stdout, stderr)
            ("counterexample", 0,
             "Counterexample:\n    caller: 0xdead\n", ""),
            ("no-counterexample", 0,
             "[PASS] invariant_x\n", ""),
            ("timeout", 124, "(truncated)\n", "timeout sent TERM\n"),
            ("error", 2, "",
             "halmos: error: could not parse bytecode\n"),
        ]

        for expected_status, exit_code, stdout, stderr in status_cases:
            with tempfile.TemporaryDirectory() as tmp:
                bundle = _make_bundle(Path(tmp))
                payload = _run_live_mode(
                    mod, bundle,
                    halmos_exit_code=exit_code,
                    halmos_stdout=stdout,
                    halmos_stderr=stderr,
                )

                self.assertEqual(
                    payload["status"], expected_status,
                    f"expected status {expected_status!r} for exit_code="
                    f"{exit_code}; got {payload['status']!r}",
                )

                # HARD-NEGATIVE LOCK — these three flags MUST be present
                # and MUST have these exact values in EVERY live-mode
                # manifest, regardless of status. A refactor that flips
                # any of them fails this assertion loudly.
                self.assertIs(
                    payload["advisory"], True,
                    f"advisory flag flipped off on status={expected_status}",
                )
                self.assertIs(
                    payload["severity_upgrade_allowed"], False,
                    f"severity_upgrade_allowed flipped on on status="
                    f"{expected_status}",
                )
                self.assertIs(
                    payload["evidence_matrix_contributes"], False,
                    f"evidence_matrix_contributes flipped on on status="
                    f"{expected_status} — this would be a FM-002 "
                    f"violation blocking gate promotion scope",
                )
                # Status must stay in the locked vocabulary.
                self.assertIn(payload["status"], mod.ALLOWED_STATUSES)

    # ------------------------------------------------------------------
    # Bonus (not one of the 5 required): pure-parser unit test.
    # ------------------------------------------------------------------
    def test_parse_halmos_output_unit(self) -> None:
        mod = _load_tool_module()

        # SAT / Counterexample marker
        status, reason, ce = mod.parse_halmos_output(
            "Running tests\nCounterexample:\n  x = 1\n", "", 0,
        )
        self.assertEqual(status, "counterexample")
        self.assertIsNotNone(ce)
        self.assertIn("Counterexample:", ce or "")

        # UNSAT / clean exit 0
        status, reason, ce = mod.parse_halmos_output(
            "[PASS] invariant_a\n", "", 0,
        )
        self.assertEqual(status, "no-counterexample")
        self.assertIsNone(ce)

        # Timeout sentinel
        status, reason, ce = mod.parse_halmos_output("", "", 124)
        self.assertEqual(status, "timeout")

        # Crash / non-zero
        status, reason, ce = mod.parse_halmos_output(
            "", "halmos exploded\n", 2,
        )
        self.assertEqual(status, "error")
        self.assertIn("exit", reason)
        self.assertIn("2", reason)


if __name__ == "__main__":
    unittest.main(verbosity=2)
