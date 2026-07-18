from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "tools" / "cosmos-detector-runner.py"
PATTERN = "evmos-bank-send-to-blocklisted-module-account"
DETECTOR = ROOT / "detectors" / "wave17" / "evmos_bank_send_to_blocklisted_module_account.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "evmos_bank_send_to_blocklisted_module_account"
POSITIVE = FIXTURE_DIR / "positive"
CLEAN = FIXTURE_DIR / "clean"
POSITIVE_KEEPER = POSITIVE / "x" / "bank" / "keeper.go"
CLEAN_KEEPER = CLEAN / "x" / "bank" / "keeper.go"
SMOKE = FIXTURE_DIR / "smoke.json"


def _load_runner():
    spec = importlib.util.spec_from_file_location("cosmos_detector_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class EvmosBankSendToBlocklistedModuleAccountTest(unittest.TestCase):
    def _findings_payload(self, fixture: Path) -> dict:
        mod = _load_runner()
        with tempfile.TemporaryDirectory() as t:
            out = Path(t) / "findings.json"
            rc = mod.run(fixture, only=PATTERN, patterns_dir=REFERENCE.parent, out_path=out, quiet=True)
            self.assertEqual(rc, 0)
            return json.loads(out.read_text(encoding="utf-8"))

    def test_reference_yaml_points_at_owned_fixture_pair(self) -> None:
        reference = REFERENCE.read_text(encoding="utf-8")
        detector = DETECTOR.read_text(encoding="utf-8")

        self.assertIn(
            "vuln: detectors/fixtures/evmos_bank_send_to_blocklisted_module_account/positive",
            reference,
        )
        self.assertIn(
            "clean: detectors/fixtures/evmos_bank_send_to_blocklisted_module_account/clean",
            reference,
        )
        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector)
        self.assertIn("BlockedAddr", reference)

    def test_fixture_pair_models_guarded_and_unguarded_msgsend(self) -> None:
        positive = POSITIVE_KEEPER.read_text(encoding="utf-8")
        clean = CLEAN_KEEPER.read_text(encoding="utf-8")

        self.assertIn("func (k Keeper) MsgSend", positive)
        self.assertIn("return k.SendCoins(ctx, fromAddr, toAddr, amt)", positive)
        self.assertNotIn("BlockedAddr(toAddr)", positive)
        self.assertIn("if k.BlockedAddr(toAddr) {", clean)
        self.assertIn("return k.SendCoins(ctx, fromAddr, toAddr, amt)", clean)

    def test_smoke_record_captures_positive_and_clean_counts(self) -> None:
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertGreaterEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        positive_payload = self._findings_payload(POSITIVE)
        self.assertEqual(positive_payload["summary"]["findings_count"], 1)
        self.assertEqual(positive_payload["findings"][0]["pattern"], PATTERN)

        clean_payload = self._findings_payload(CLEAN)
        self.assertEqual(clean_payload["summary"]["findings_count"], 0)
        self.assertEqual(clean_payload["findings"], [])


if __name__ == "__main__":
    unittest.main()
