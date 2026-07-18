#!/usr/bin/env python3
# r36: lane L37-RUST-CREDIT registered in .auditooor/agent_pathspec.json
"""test_rust_proptest_engine_env_skip.py - FIX 3 regression lock.

The rust proptest engine runner previously classified ANY failed `cargo test`
that lacked a network signature as a proptest COUNTEREXAMPLE (the false-pass
the live-engines / audit-honesty gate then surfaced as fail-engine-false-pass).
FIX 3 adds a generic env-failure / missing-build-artifact branch: when the
failure output matches an env-failure signature (wasms.rs / compile-contract /
lazy_lock init / "No such file" on a .wasm / missing build artifact) AND NO
proptest "minimal failing input" marker is present, the runner emits
STATUS=env_skip (a recognized SKIPPED state), NOT pass and NOT counterexample.

These tests are hermetic: they put a FAKE `cargo` stub on PATH that emits the
chosen failure output, then run the REAL runner and assert the manifest status.
Generic across any Rust suite that needs a build step - the signature list is
also env-overridable via AUDITOOOR_RUST_ENGINE_ENV_SKIP_PATTERNS.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
RUNNER = TOOLS / "rust-proptest-engine-runner.sh"


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


class RustEngineEnvSkipTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        # minimal cargo workspace with a proptest-impl feature so the runner
        # selects the crate and proceeds to run_cargo.
        self.ws = self.tmp / "ws"
        crate = self.ws / "crate-a"
        _write(self.ws / "Cargo.toml",
               "[workspace]\nmembers = [\"crate-a\"]\n")
        _write(crate / "Cargo.toml",
               "[package]\nname = \"crate-a\"\nversion = \"0.1.0\"\n"
               "[features]\nproptest-impl = [\"proptest\"]\n")
        _write(crate / "src" / "lib.rs", "fn main(){}\n")
        # fake-bin dir we prepend to PATH; holds the cargo stub.
        self.fakebin = self.tmp / "fakebin"
        self.fakebin.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _install_cargo_stub(self, *, stdout: str, stderr: str = "", rc: int = 101) -> None:
        # cargo --version must succeed (the runner calls it for CARGO_VER);
        # everything else prints the fixture output and exits rc.
        stub = self.fakebin / "cargo"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "if [ \"$1\" = \"--version\" ]; then echo 'cargo 1.99.0 (fake)'; exit 0; fi\n"
            f"cat <<'__SO__'\n{stdout}\n__SO__\n"
            f"cat <<'__SE__' 1>&2\n{stderr}\n__SE__\n"
            f"exit {rc}\n",
            encoding="utf-8",
        )
        stub.chmod(0o755)

    def _run(self, env_extra: dict | None = None) -> dict:
        env = dict(os.environ)
        env["PATH"] = f"{self.fakebin}:{env['PATH']}"
        if env_extra:
            env.update(env_extra)
        subprocess.run(
            ["bash", str(RUNNER), str(self.ws)],
            env=env, capture_output=True, text=True, timeout=120,
        )
        manifests = sorted((self.ws / "fuzz_runs").glob("*/manifest.json"))
        self.assertTrue(manifests, "runner produced no manifest")
        return json.loads(manifests[-1].read_text(encoding="utf-8"))

    # -- env-skip cases: failure + env signature + NO proptest marker --------
    def test_missing_wasm_artifact_is_env_skip(self) -> None:
        out = (
            "running 3 tests\n"
            "test contract::integration ... FAILED\n"
            "failures:\n"
            "thread 'contract::integration' panicked at 'No such file or "
            "directory (os error 2): target/wasm32/release/contract.wasm'\n"
            "test result: FAILED. 0 passed; 1 failed\n"
        )
        self._install_cargo_stub(stdout=out)
        man = self._run()
        self.assertEqual(man["status"], "env_skip", man.get("notes"))

    def test_wasms_rs_generated_artifact_is_env_skip(self) -> None:
        out = (
            "test result: FAILED. 5 passed; 1 failed\n"
            "thread 'main' panicked at src/wasms.rs:12: compile-contract step "
            "did not produce the expected artifact\n"
        )
        self._install_cargo_stub(stdout=out)
        man = self._run()
        self.assertEqual(man["status"], "env_skip", man.get("notes"))

    def test_lazy_lock_init_panic_is_env_skip(self) -> None:
        out = (
            "test result: FAILED. 10 passed; 1 failed\n"
            "thread 'test_x' panicked: LazyLock init failed: missing build "
            "artifact\n"
        )
        self._install_cargo_stub(stdout=out)
        man = self._run()
        self.assertEqual(man["status"], "env_skip", man.get("notes"))

    # -- genuine counterexample: proptest marker present -> NOT env-skip -----
    def test_real_counterexample_still_counterexample(self) -> None:
        out = (
            "test result: FAILED. 2 passed; 1 failed\n"
            "thread 'prop_roundtrip' panicked\n"
            "minimal failing input: input = 42\n"
        )
        self._install_cargo_stub(stdout=out)
        man = self._run()
        self.assertEqual(man["status"], "counterexample", man.get("notes"))

    def test_wasm_signature_but_proptest_marker_wins(self) -> None:
        # If a real proptest counterexample AND an env phrase both appear, the
        # proptest marker MUST win (a genuine CE is never swallowed).
        out = (
            "test result: FAILED. 1 passed; 2 failed\n"
            "could not find build artifact contract.wasm\n"
            "minimal failing input: x = -1\n"
        )
        self._install_cargo_stub(stdout=out)
        man = self._run()
        self.assertEqual(man["status"], "counterexample", man.get("notes"))

    # -- network case unchanged (regression) --------------------------------
    def test_network_failure_still_pass(self) -> None:
        out = (
            "test result: FAILED. 7 passed; 1 failed\n"
            "thread 'daemon_test' panicked: Connection refused (os error 61)\n"
        )
        self._install_cargo_stub(stdout=out)
        man = self._run()
        self.assertEqual(man["status"], "pass", man.get("notes"))

    # -- env-overridable signature list -------------------------------------
    def test_env_overridable_signature(self) -> None:
        out = (
            "test result: FAILED. 3 passed; 1 failed\n"
            "thread 'x' panicked: MY_CUSTOM_BUILD_TOKEN absent\n"
        )
        self._install_cargo_stub(stdout=out)
        # Without override: this is NOT an env phrase -> counterexample.
        man = self._run()
        self.assertEqual(man["status"], "counterexample", man.get("notes"))
        # With override: classified as env_skip.
        man2 = self._run(env_extra={
            "AUDITOOOR_RUST_ENGINE_ENV_SKIP_PATTERNS": "MY_CUSTOM_BUILD_TOKEN",
        })
        self.assertEqual(man2["status"], "env_skip", man2.get("notes"))


if __name__ == "__main__":
    unittest.main()
