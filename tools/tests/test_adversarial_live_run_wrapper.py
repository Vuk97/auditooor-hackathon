#!/usr/bin/env python3
"""capv3-iter6-T1 — hermetic tests for tools/adversarial-live-run.sh.

The wrapper is the operator-gating shim around iter-v3-5 T1's live adversarial
dispatcher (`scripts/_capv3_iter5_T1_driver.py`). Semantics:

  * ANTHROPIC_API_KEY missing       → JSON {status: cannot-run, reason: no-api-key}
  * ADVERSARIAL_LIVE_CONSENT != "1" → JSON {status: cannot-run, reason: operator-not-consented}
  * both present                    → SWARM_REAL_DISPATCH=1 python3 <driver>;
                                      JSON {status: ran, driver_exit_code: <N>}

Wrapper ALWAYS exits 0 — driver exit code surfaces in JSON only.

Hermetic strategy:
  * We invoke the real wrapper via `subprocess.run` with a pinned `env` dict
    (no inheritance of ambient `ANTHROPIC_API_KEY`).
  * We point `AUDITOOOR_ROOT` at a `tempfile.TemporaryDirectory` that contains
    just the `agent_outputs/` dir (wrapper creates it too, but we check the
    target path is writable).
  * For the `ran` paths we override `ADVERSARIAL_LIVE_RUN_DRIVER` to a stub
    python script we write to the tmp dir. The stub does NOT import
    `tools/llm-dispatch.py` and does NOT call Anthropic — it simply `exit(N)`.
  * `ANTHROPIC_API_KEY` is set to a test sentinel string (never a real key).

This means: no real Anthropic call ever happens in the test suite.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "tools" / "adversarial-live-run.sh"


def _base_env() -> dict:
    """Minimal env with PATH but no leaked Anthropic creds."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        # LANG/LC_* keep `date` / shell happy on Linux & macOS.
        "LANG": os.environ.get("LANG", "C"),
        "LC_ALL": os.environ.get("LC_ALL", "C"),
    }
    return env


def _run(tmp_root: Path, env: dict) -> subprocess.CompletedProcess:
    full_env = _base_env()
    full_env.update(env)
    full_env["AUDITOOOR_ROOT"] = str(tmp_root)
    return subprocess.run(
        ["bash", str(WRAPPER)],
        capture_output=True,
        text=True,
        env=full_env,
    )


def _write_stub_driver(tmp_root: Path, exit_code: int) -> Path:
    """Create a stand-alone python stub that neither imports llm-dispatch nor
    touches the network. The wrapper invokes it via `python3 <path>`."""
    stub = tmp_root / "stub_driver.py"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "# hermetic stub driver — exits with the code baked in at write time\n"
        "import sys\n"
        f"sys.exit({int(exit_code)})\n",
        encoding="utf-8",
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    return stub


def _out_json(tmp_root: Path) -> Path:
    return tmp_root / "agent_outputs" / "capv3_iter6_T1_live_wrapper.json"


class AdversarialLiveRunWrapperTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp_obj = tempfile.TemporaryDirectory(prefix="capv3-iter6-T1-")
        self.tmp_root = Path(self._tmp_obj.name)
        (self.tmp_root / "agent_outputs").mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self._tmp_obj.cleanup()

    # ------------------------------------------------------------------
    # Gate 1 — no ANTHROPIC_API_KEY
    # ------------------------------------------------------------------
    def test_no_api_key_records_cannot_run_reason(self) -> None:
        """Empty env (no key, no consent) → cannot-run: no-api-key, exit 0."""
        proc = _run(self.tmp_root, env={})
        self.assertEqual(
            proc.returncode, 0,
            f"wrapper must exit 0; got {proc.returncode}\nstderr: {proc.stderr}",
        )
        out = _out_json(self.tmp_root)
        self.assertTrue(out.exists(), f"JSON not written: {out}")
        payload = json.loads(out.read_text())
        self.assertEqual(payload["status"], "cannot-run")
        self.assertEqual(payload["reason"], "no-api-key")
        self.assertEqual(payload["wrapper_version"], "v1")
        self.assertIn("ts", payload)
        # No driver_exit_code on cannot-run records.
        self.assertNotIn("driver_exit_code", payload)

    # ------------------------------------------------------------------
    # Gate 2 — key present, no consent
    # ------------------------------------------------------------------
    def test_no_consent_records_cannot_run_reason(self) -> None:
        """Key set but ADVERSARIAL_LIVE_CONSENT absent → cannot-run: operator-not-consented."""
        proc = _run(
            self.tmp_root,
            env={"ANTHROPIC_API_KEY": "testkey-hermetic-not-real"},
        )
        self.assertEqual(
            proc.returncode, 0,
            f"wrapper must exit 0; got {proc.returncode}\nstderr: {proc.stderr}",
        )
        out = _out_json(self.tmp_root)
        self.assertTrue(out.exists())
        payload = json.loads(out.read_text())
        self.assertEqual(payload["status"], "cannot-run")
        self.assertEqual(payload["reason"], "operator-not-consented")
        self.assertEqual(payload["wrapper_version"], "v1")

    # ------------------------------------------------------------------
    # Both gates open, driver errors → driver_exit_code captured
    # ------------------------------------------------------------------
    def test_both_present_but_driver_errors_captures_exit_code(self) -> None:
        """Stub driver exits 42 → JSON {status: ran, driver_exit_code: 42}; wrapper exit 0."""
        stub = _write_stub_driver(self.tmp_root, exit_code=42)
        proc = _run(
            self.tmp_root,
            env={
                "ANTHROPIC_API_KEY": "testkey-hermetic-not-real",
                "ADVERSARIAL_LIVE_CONSENT": "1",
                "ADVERSARIAL_LIVE_RUN_DRIVER": str(stub),
            },
        )
        self.assertEqual(
            proc.returncode, 0,
            f"wrapper must exit 0 even when driver errors; "
            f"got {proc.returncode}\nstderr: {proc.stderr}",
        )
        out = _out_json(self.tmp_root)
        self.assertTrue(out.exists())
        payload = json.loads(out.read_text())
        self.assertEqual(payload["status"], "ran")
        self.assertEqual(payload["driver_exit_code"], 42)
        self.assertEqual(payload["wrapper_version"], "v1")
        self.assertNotIn("reason", payload)

    # ------------------------------------------------------------------
    # Both gates open, driver success → driver_exit_code = 0
    # ------------------------------------------------------------------
    def test_both_present_driver_success_records_ran(self) -> None:
        """Stub driver exits 0 → JSON {status: ran, driver_exit_code: 0}; wrapper exit 0."""
        stub = _write_stub_driver(self.tmp_root, exit_code=0)
        proc = _run(
            self.tmp_root,
            env={
                "ANTHROPIC_API_KEY": "testkey-hermetic-not-real",
                "ADVERSARIAL_LIVE_CONSENT": "1",
                "ADVERSARIAL_LIVE_RUN_DRIVER": str(stub),
            },
        )
        self.assertEqual(
            proc.returncode, 0,
            f"wrapper must exit 0 on driver success; "
            f"got {proc.returncode}\nstderr: {proc.stderr}",
        )
        out = _out_json(self.tmp_root)
        self.assertTrue(out.exists())
        payload = json.loads(out.read_text())
        self.assertEqual(payload["status"], "ran")
        self.assertEqual(payload["driver_exit_code"], 0)
        self.assertEqual(payload["wrapper_version"], "v1")


if __name__ == "__main__":
    unittest.main()
