from __future__ import annotations

import importlib.util
import json
import py_compile
import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "detectors" / "go_ast_fee_redirect_user_controlled_sink.py"
FIXTURE_DIR = ROOT / "fixtures" / "go-detector-runner"
POSITIVE = FIXTURE_DIR / "positive" / "fee_redirect_user_controlled_sink_fire6.go"
NEGATIVE = FIXTURE_DIR / "negative" / "fee_redirect_user_controlled_sink_fire6_guarded.go"


def _load_detector():
    spec = importlib.util.spec_from_file_location(
        "go_ast_fee_redirect_user_controlled_sink",
        TOOL_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load detector")
    module = importlib.util.module_from_spec(spec)
    sys.modules["go_ast_fee_redirect_user_controlled_sink"] = module
    spec.loader.exec_module(module)
    return module


detector = _load_detector()


def _run(root: Path) -> dict:
    buf = StringIO()
    with redirect_stdout(buf):
        rc = detector.main([str(root)])
    payload = json.loads(buf.getvalue())
    payload["_rc"] = rc
    return payload


class GoFeeRedirectUserControlledSinkFire6Test(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(TOOL_PATH), doraise=True)

    def test_positive_fixture_fires_on_signer_controlled_collector(self) -> None:
        payload = _run(POSITIVE)
        self.assertEqual(payload["_rc"], 0)
        self.assertEqual(payload["schema"], "auditooor.go_ast_fee_redirect_user_controlled_sink.v1")
        self.assertEqual(payload["count"], 1, payload)
        candidate = payload["candidates"][0]
        self.assertEqual(candidate["function"], "SettleProtocolFee")
        self.assertEqual(candidate["severity_hint"], "HIGH")
        self.assertIn("collector", candidate["reason"])
        self.assertIn("protocolFee", candidate["snippet"])

    def test_negative_fixture_is_silent_for_configured_or_guarded_sinks(self) -> None:
        payload = _run(NEGATIVE)
        self.assertEqual(payload["_rc"], 0)
        self.assertEqual(payload["count"], 0, payload)
        self.assertEqual(payload["candidates"], [])

    def test_fixtures_lock_confirmed_go_shape_and_guard_controls(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")
        self.assertIn("msg.GetSigners()", positive)
        self.assertIn("collector := signers[0]", positive)
        self.assertIn("protocolFee", positive)
        self.assertIn("params.FeeCollector", negative)
        self.assertIn("collector != params.FeeCollector", negative)
        self.assertIn("params.Treasury", negative)


if __name__ == "__main__":
    unittest.main()
