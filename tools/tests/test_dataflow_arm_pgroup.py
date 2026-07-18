"""Regression: dataflow._run_arm must NOT deadlock when an arm backend spawns a
GRANDCHILD (e.g. a multiprocessing worker) that inherits - and holds open - the
captured stdout/stderr pipe.

Before the fix _run_arm used subprocess.run(capture_output=True, timeout=...).
On timeout that SIGKILLs only the DIRECT child, then its internal communicate()
blocks forever in poll() waiting for a pipe-EOF the still-alive grandchild never
sends (observed NUVA 2026-07-06: the go arm parent + a multiprocessing worker
both wedged in poll(), 0% CPU, long past the per-arm timeout - stalling advisory
step-1c up to the make-level 1800s cap). The fix isolates each arm in its own
process group (start_new_session=True) and group-kills on timeout, so the pipe
write-ends close and the drain returns promptly.
"""
import importlib.util
import os
import sys
import time
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_DF = os.path.join(_HERE, "..", "dataflow.py")


def _load_dataflow():
    # dataflow.py puts tools/ on sys.path and imports dataflow_schema at module load;
    # ensure tools/ is importable, then exec the module in isolation.
    tools_dir = os.path.abspath(os.path.join(_HERE, ".."))
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location("dataflow_under_test", _DF)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# An "arm" that spawns a grandchild inheriting the captured pipe, with BOTH the
# parent and the grandchild outliving the per-arm timeout. This is the exact
# shape that wedged NUVA.
_HANG_ARM = (
    "import subprocess,time;"
    "subprocess.Popen(['sleep','30']);"  # grandchild inherits stdout/stderr PIPE
    "time.sleep(30)"                       # parent also lives past the timeout
)

_OK_ARM = "import json;print(json.dumps({'records':[],'ok':True}))"
_FAIL_ARM = "import sys;sys.stderr.write('boom');sys.exit(3)"


class TestRunArmProcessGroup(unittest.TestCase):
    def test_timeout_does_not_deadlock_on_grandchild_pipe(self):
        mod = _load_dataflow()
        t0 = time.monotonic()
        rep = mod._run_arm("test", [sys.executable, "-c", _HANG_ARM], timeout=2)
        elapsed = time.monotonic() - t0
        self.assertEqual(rep.get("status"), "timeout")
        # Old code blocked ~30s on the grandchild holding the pipe open; the
        # group-kill fix returns in ~timeout + reap (< 20s, generous for CI).
        self.assertLess(
            elapsed, 20.0,
            f"_run_arm hung {elapsed:.1f}s - pipe-inherited grandchild deadlock not fixed",
        )

    def test_normal_arm_still_parses_summary(self):
        mod = _load_dataflow()
        rep = mod._run_arm("test", [sys.executable, "-c", _OK_ARM], timeout=15)
        self.assertEqual(rep.get("status"), "ok")
        self.assertEqual(rep.get("returncode"), 0)
        self.assertEqual(rep.get("summary"), {"records": [], "ok": True})

    def test_nonzero_arm_reports_stderr_tail(self):
        mod = _load_dataflow()
        rep = mod._run_arm("test", [sys.executable, "-c", _FAIL_ARM], timeout=15)
        self.assertEqual(rep.get("status"), "arm-nonzero")
        self.assertEqual(rep.get("returncode"), 3)
        self.assertIn("boom", rep.get("stderr_tail", ""))


if __name__ == "__main__":
    unittest.main()
