"""Regression: the step-2d pre-hunt language reasoners emit their obligation ledger
BY DEFAULT (2026-07-14).

rust-unchecked-arith-value-overflow / goroutine-shared-state-race / slice-oob-bounds-
taint gated the ledger write behind --emit, but the runbook documents the plain
`--workspace <ws>` command and the step-2d verifiers check file_exists as proof-of-run
("empty = ran, 0 survivors"). So a genuine 0-survivor run never emitted its ledger and
the step could never pass. Each now emits by default (cited-empty marker on 0 survivors),
--no-emit to opt out.
"""
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

_TOOLS = pathlib.Path(__file__).resolve().parent.parent / "tools"


def _mk_ws():
    ws = tempfile.mkdtemp()
    src = pathlib.Path(ws) / "src"
    src.mkdir(parents=True, exist_ok=True)
    # a trivial, guard-clean Go file -> reasoners run, 0 survivors
    (src / "main.go").write_text("package main\nfunc main() {}\n")
    return ws


class Step2dReasonersEmitByDefault(unittest.TestCase):
    def _run(self, tool, ledger):
        ws = _mk_ws()
        env = dict(os.environ, GOTOOLCHAIN="go1.25.8")
        r = subprocess.run([sys.executable, str(_TOOLS / tool), "--workspace", ws],
                           capture_output=True, text=True, timeout=120, env=env)
        led = pathlib.Path(ws) / ".auditooor" / ledger
        self.assertTrue(led.is_file(),
                        f"{tool} must emit {ledger} by default (rc={r.returncode}); "
                        f"stderr={r.stderr[-300:]}")
        self.assertTrue(led.stat().st_size > 0,
                        f"{tool} ledger must carry a cited-empty proof-of-run marker, "
                        f"not a 0-byte file")

    def test_goroutine_race_emits_by_default(self):
        self._run("goroutine-shared-state-race.py",
                  "goroutine_shared_state_race_hypotheses.jsonl")

    def test_slice_oob_emits_by_default(self):
        self._run("slice-oob-bounds-taint.py", "slice_oob_bounds_taint.jsonl")

    def test_rust_arith_emits_by_default(self):
        # no cargo.toml -> degraded (0 survivors) but must still emit the cited-empty ledger
        self._run("rust-unchecked-arith-value-overflow.py",
                  "rust_unchecked_arith_obligations.jsonl")


if __name__ == "__main__":
    unittest.main()
