from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from io import StringIO
from pathlib import Path
from contextlib import redirect_stdout


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "detectors" / "go_ast_failure_status_branch_asymmetry.py"
FIX_DIR = REPO_ROOT / "tools" / "detectors" / "fixtures" / "d2_failure_status_branch"


def _load():
    spec = importlib.util.spec_from_file_location("go_ast_failure_status_branch_asymmetry", TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load detector")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["go_ast_failure_status_branch_asymmetry"] = mod
    spec.loader.exec_module(mod)
    return mod


detector = _load()


def _run(root: Path) -> dict:
    buf = StringIO()
    with redirect_stdout(buf):
        rc = detector.main([str(root)])
    payload = json.loads(buf.getvalue())
    payload["_rc"] = rc
    return payload


class TestD2FailureStatusBranchAsymmetry(unittest.TestCase):
    def test_positive_fixtures_fire(self):
        payload = _run(FIX_DIR / "positive")
        self.assertEqual(payload["_rc"], 0)
        self.assertEqual(payload["count"], 2)
        funcs = {c["function"] for c in payload["candidates"]}
        self.assertIn("DistributeFee", funcs)
        self.assertIn("Settle", funcs)

    def test_negative_fixtures_do_not_fire(self):
        payload = _run(FIX_DIR / "negative")
        self.assertEqual(payload["_rc"], 0)
        self.assertEqual(payload["count"], 0)

    def test_severity_hint_high_for_success_only_branch(self):
        payload = _run(FIX_DIR / "positive")
        for c in payload["candidates"]:
            self.assertEqual(c["severity_hint"], "HIGH")

    def test_schema_field(self):
        payload = _run(FIX_DIR / "positive")
        self.assertEqual(payload["schema"], "auditooor.go_ast_failure_status_branch_asymmetry.v1")
        self.assertGreaterEqual(payload["count"], 2)


if __name__ == "__main__":
    unittest.main()
