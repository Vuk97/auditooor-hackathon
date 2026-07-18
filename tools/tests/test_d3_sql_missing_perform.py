from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from io import StringIO
from pathlib import Path
from contextlib import redirect_stdout


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "detectors" / "sql_handler_missing_perform.py"
FIX_DIR = REPO_ROOT / "tools" / "detectors" / "fixtures" / "d3_sql_missing_perform"


def _load():
    spec = importlib.util.spec_from_file_location(
        "sql_handler_missing_perform", TOOL_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load detector")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["sql_handler_missing_perform"] = mod
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


class TestD3SqlMissingPerform(unittest.TestCase):
    def test_positive_fixtures_fire(self):
        payload = _run(FIX_DIR / "positive")
        self.assertEqual(payload["_rc"], 0)
        # one candidate per positive fixture
        self.assertEqual(payload["count"], 2)
        callees = {c["function_called"] for c in payload["candidates"]}
        self.assertIn("update_subaccount_balance", callees)
        self.assertIn("record_pnl_row", callees)

    def test_negative_fixtures_do_not_fire(self):
        payload = _run(FIX_DIR / "negative")
        self.assertEqual(payload["_rc"], 0)
        self.assertEqual(payload["count"], 0)
        self.assertEqual(payload["candidates"], [])

    def test_severity_hint_medium_for_side_effect_prefix(self):
        payload = _run(FIX_DIR / "positive")
        # both positive callees start with `update_` or `record_` (side-effect)
        for cand in payload["candidates"]:
            self.assertEqual(cand["severity_hint"], "MEDIUM")
            self.assertIn("SELECT", cand["snippet"].upper())

    def test_schema_and_caller_metadata_present(self):
        payload = _run(FIX_DIR / "positive")
        self.assertEqual(payload["schema"], "auditooor.sql_handler_missing_perform.v1")
        callers = {c["function_caller"] for c in payload["candidates"]}
        self.assertIn("dydx_liquidation_handler", callers)
        self.assertIn("dydx_deleveraging_handler", callers)
        for cand in payload["candidates"]:
            self.assertGreater(cand["line"], 0)
            self.assertTrue(cand["file"].endswith(".sql"))

    def test_low_severity_when_no_side_effect_prefix(self):
        # Build an in-memory fixture-like file: a SELECT-call with a callee
        # whose name does NOT start with a side-effect prefix.
        import tempfile
        sql = (
            "CREATE OR REPLACE FUNCTION caller_fn() RETURNS trigger AS $$\n"
            "BEGIN\n"
            "    SELECT compute_something(NEW.id);\n"
            "    RETURN NEW;\n"
            "END;\n"
            "$$ LANGUAGE plpgsql;\n"
        )
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "t.sql"
            p.write_text(sql, encoding="utf-8")
            payload = _run(p)
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["candidates"][0]["severity_hint"], "LOW")
        self.assertEqual(
            payload["candidates"][0]["function_called"], "compute_something"
        )


if __name__ == "__main__":
    unittest.main()
