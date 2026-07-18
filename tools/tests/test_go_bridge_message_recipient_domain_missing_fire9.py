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
TOOL_PATH = REPO_ROOT / "tools" / "detectors" / "go_ast_bridge_message_recipient_domain_missing_fire9.py"
FIXTURE_DIR = ROOT / "fixtures" / "go-detector-runner"
POSITIVE = FIXTURE_DIR / "positive" / "bridge_message_recipient_domain_missing_fire9.go"
NEGATIVE = FIXTURE_DIR / "negative" / "bridge_message_recipient_domain_missing_fire9.go"


def _load_detector():
    spec = importlib.util.spec_from_file_location(
        "go_ast_bridge_message_recipient_domain_missing_fire9",
        TOOL_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load detector")
    module = importlib.util.module_from_spec(spec)
    sys.modules["go_ast_bridge_message_recipient_domain_missing_fire9"] = module
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


class GoBridgeMessageRecipientDomainMissingFire9Test(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(TOOL_PATH), doraise=True)

    def test_positive_fixture_fires_on_verified_message_without_domain_binding(self) -> None:
        payload = _run(POSITIVE)
        self.assertEqual(payload["_rc"], 0)
        self.assertEqual(
            payload["schema"],
            "auditooor.go_ast_bridge_message_recipient_domain_missing_fire9.v1",
        )
        self.assertEqual(payload["count"], 1, payload)
        candidate = payload["candidates"][0]
        self.assertEqual(candidate["function"], "CompleteBridgeMessage")
        self.assertEqual(candidate["severity_hint"], "HIGH")
        self.assertEqual(candidate["attack_class"], "bridge-proof-domain-bypass")
        self.assertIn("go-bridge-message-recipient-validation-missing-positive", candidate["source_miss_id"])
        self.assertIn("receiver-domain", candidate["reason"])
        self.assertIn("SendCoinsFromModuleToAccount", candidate["snippet"])

    def test_negative_fixture_is_silent_when_recipient_and_domain_are_bound(self) -> None:
        payload = _run(NEGATIVE)
        self.assertEqual(payload["_rc"], 0)
        self.assertEqual(payload["count"], 0, payload)
        self.assertEqual(payload["candidates"], [])

    def test_fixtures_lock_source_lift_shape_and_guard_control(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")
        self.assertIn("VerifyProof", positive)
        self.assertIn("msg.ReceiverDomain", positive)
        self.assertNotIn("recipient != proof.Recipient", positive)
        self.assertIn("recipient != proof.Recipient", negative)
        self.assertIn("receiverDomain != k.localDomain", negative)


if __name__ == "__main__":
    unittest.main()
