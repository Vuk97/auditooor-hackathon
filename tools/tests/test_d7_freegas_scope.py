from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "detectors" / "go_free_infinite_gas_scope_analyzer.py"
FIX_DIR = REPO_ROOT / "tools" / "detectors" / "fixtures" / "d7_freegas_scope"


def _load():
    spec = importlib.util.spec_from_file_location(
        "go_free_infinite_gas_scope_analyzer", TOOL_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load detector")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["go_free_infinite_gas_scope_analyzer"] = mod
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


class TestD7FreeGasScope(unittest.TestCase):
    def test_positive_fires_on_both_decorators(self):
        payload = _run(FIX_DIR / "positive")
        self.assertEqual(payload["_rc"], 0)
        self.assertEqual(
            payload["schema"], "auditooor.go_free_infinite_gas_scope_analyzer.v1"
        )
        decorators = payload["decorators"]
        names = {d["decorator"] for d in decorators}
        self.assertIn("AnteHandle", names)
        # Should be at least 2 hits (FreeInfiniteGasDecorator + SecondDecorator both
        # use AnteHandle as the receiver method).
        self.assertGreaterEqual(len(decorators), 2)
        for d in decorators:
            # Each hit must record a gas-switch line + non-empty snippet.
            self.assertGreater(d["gas_switch_line"], 0)
            self.assertIn("WithGasMeter", d["gas_switch_snippet"])
            # Predicate detected → HIGH severity for the broad-scope hit.
            self.assertIsNotNone(d["gating_predicate"])
            self.assertEqual(d["severity_hint"], "HIGH")

    def test_decision_matrix_contains_gate_tokens(self):
        payload = _run(FIX_DIR / "positive")
        all_tokens: set[str] = set()
        for d in payload["decorators"]:
            all_tokens.update(d["msg_type_tokens"])
        self.assertIn("IsSingleAppInjectedMsg", all_tokens)
        for d in payload["decorators"]:
            for token, classification in d["decision_matrix"].items():
                self.assertEqual(classification, "free-gas")
                self.assertIn(token, d["msg_type_tokens"])

    def test_negative_does_not_fire(self):
        payload = _run(FIX_DIR / "negative")
        self.assertEqual(payload["_rc"], 0)
        self.assertEqual(payload["count"], 0)
        self.assertEqual(payload["decorators"], [])

    def test_root_does_not_exist_returns_2(self):
        buf = StringIO()
        with redirect_stdout(buf):
            rc = detector.main([str(FIX_DIR / "no_such_dir_xyzzy")])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
