from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "detectors" / "go_insurance_fund_ordering_sentinel.py"
FIX_DIR = REPO_ROOT / "tools" / "detectors" / "fixtures" / "d4_if_ordering"


def _load():
    spec = importlib.util.spec_from_file_location(
        "go_insurance_fund_ordering_sentinel", TOOL_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load detector")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["go_insurance_fund_ordering_sentinel"] = mod
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


class TestD4IFOrdering(unittest.TestCase):
    def test_positive_fires_on_inverted_order(self):
        payload = _run(FIX_DIR / "positive")
        self.assertEqual(payload["_rc"], 0)
        self.assertEqual(payload["schema"], "auditooor.go_insurance_fund_ordering_sentinel.v1")
        self.assertGreater(payload["count"], 0)
        funcs = {s["func"] for s in payload["sentinels"]}
        self.assertIn("persistLiquidationMatchInverted", funcs)
        self.assertIn("liquidateInvertedSendCoins", funcs)
        for s in payload["sentinels"]:
            self.assertEqual(s["pattern"], "ORDER_INVERTED")
            self.assertEqual(s["severity_hint"], "HIGH")
            self.assertLess(s["update_subaccounts_line"], s["if_transfer_line"])

    def test_negative_does_not_fire_on_correct_ordering(self):
        payload = _run(FIX_DIR / "negative")
        self.assertEqual(payload["_rc"], 0)
        self.assertEqual(payload["count"], 0)
        self.assertEqual(payload["sentinels"], [])

    def test_schema_and_evidence_strings_present(self):
        payload = _run(FIX_DIR / "positive")
        for s in payload["sentinels"]:
            self.assertIn("UpdateSubaccounts at line", s["evidence"])
            self.assertIn("precedes", s["evidence"])
            self.assertTrue(s["if_transfer_snippet"])
            self.assertTrue(s["update_subaccounts_snippet"])
            self.assertGreater(s["func_line"], 0)

    def test_root_does_not_exist_returns_2(self):
        buf = StringIO()
        with redirect_stdout(buf):
            rc = detector.main([str(FIX_DIR / "no_such_dir_xyzzy")])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
