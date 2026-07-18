from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from io import StringIO
from pathlib import Path
from contextlib import redirect_stdout


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "detectors" / "go_ast_decode_pre_fee.py"
FIX_DIR = REPO_ROOT / "tools" / "detectors" / "fixtures" / "d1_decode_pre_fee"


def _load():
    spec = importlib.util.spec_from_file_location("go_ast_decode_pre_fee", TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load detector")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["go_ast_decode_pre_fee"] = mod
    spec.loader.exec_module(mod)
    return mod


detector = _load()


def _run(root: Path) -> dict:
    buf = StringIO()
    with redirect_stdout(buf):
        rc = detector.main([str(root)])
    self_payload = json.loads(buf.getvalue())
    self_payload["_rc"] = rc
    return self_payload


class TestD1DecodePreFee(unittest.TestCase):
    def test_positive_fixtures_fire(self):
        payload = _run(FIX_DIR / "positive")
        self.assertEqual(payload["_rc"], 0)
        self.assertEqual(payload["count"], 2)
        names = {c["function"] for c in payload["candidates"]}
        self.assertIn("HandleDecode", names)
        self.assertIn("ExtractAny", names)

    def test_negative_fixtures_do_not_fire(self):
        payload = _run(FIX_DIR / "negative")
        self.assertEqual(payload["_rc"], 0)
        self.assertEqual(payload["count"], 0)
        self.assertEqual(payload["candidates"], [])

    def test_severity_hint_high_for_handler_names(self):
        payload = _run(FIX_DIR / "positive")
        for cand in payload["candidates"]:
            self.assertEqual(cand["severity_hint"], "HIGH")
            self.assertIn("Unmarshal", cand["snippet"])

    def test_schema_field_present(self):
        payload = _run(FIX_DIR / "positive")
        self.assertEqual(payload["schema"], "auditooor.go_ast_decode_pre_fee.v1")
        self.assertGreater(len(payload["candidates"]), 0)


if __name__ == "__main__":
    unittest.main()
