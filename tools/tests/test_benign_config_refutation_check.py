"""Tests for benign-config-refutation-check.py (R-ADVERSARIAL-CONFIG)."""
import importlib.util, json, os, sys, tempfile, unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "benign-config-refutation-check.py"
_spec = importlib.util.spec_from_file_location("bcrc", TOOL)
bcrc = importlib.util.module_from_spec(_spec); sys.modules["bcrc"] = bcrc
_spec.loader.exec_module(bcrc)


def _ws(tmp, rows):
    a = Path(tmp) / ".auditooor"; a.mkdir(parents=True, exist_ok=True)
    with (a / "lead_verdicts.jsonl").open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return Path(tmp)


class TestBenignConfigRefutation(unittest.TestCase):
    def setUp(self):
        os.environ.pop("AUDITOOOR_ADVERSARIAL_CONFIG_STRICT", None)

    def test_flags_narrative_only_refutation(self):
        # The NUVA donation shape: refuted on the KYC/RWA program description +
        # "not evidenced as the deployed config" with NO adversarial-reachability.
        with tempfile.TemporaryDirectory() as tmp:
            ws = _ws(tmp, [{"lead": "donation", "verdict": "NOT-FILEABLE",
                            "reason": "the underlying marker is restricted per the KYC/RWA "
                                      "program description; every realistic test fixture points "
                                      "to a restricted denom, and this is not evidenced as the "
                                      "deployed config, so the donation vector is blocked."}])
            res = bcrc.scan(ws)
            self.assertEqual(len(res["flagged"]), 1, "narrative-only refutation must be flagged")

    def test_exempts_adversarial_reachability_refutation(self):
        # A CODE-grounded refutation that reasons about the attacker-chosen config.
        with tempfile.TemporaryDirectory() as tmp:
            ws = _ws(tmp, [{"lead": "donation", "verdict": "REFUTED",
                            "reason": "CreateVault is permissionless but the donation is "
                                      "self-diluting: the attacker share-fraction x rate x "
                                      "duration < 1 for all reachable params (interest.go:95), "
                                      "so no net gain even for an adversarially-created "
                                      "unrestricted-marker vault - break-even at best."}])
            res = bcrc.scan(ws)
            self.assertEqual(len(res["flagged"]), 0, "adversarial-reachability math must exempt")

    def test_exempts_real_config_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _ws(tmp, [{"lead": "x", "verdict": "KILL",
                            "reason": "the deployed config assumption is moot: CreateVault "
                                      "require(markerType == Restricted) at vault.go:212 "
                                      "structurally forbids an unrestricted underlying, so an "
                                      "attacker cannot create the adversarial config."}])
            res = bcrc.scan(ws)
            self.assertEqual(len(res["flagged"]), 0, "a real structural config guard must exempt")

    def test_positive_verdict_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _ws(tmp, [{"lead": "x", "verdict": "CONFIRMED",
                            "reason": "realistic deployment uses a restricted marker but the "
                                      "attack still works via ..."}])
            res = bcrc.scan(ws)
            self.assertEqual(len(res["flagged"]), 0, "only terminal-NEGATIVE verdicts refute")

    def test_strict_env_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _ws(tmp, [{"lead": "d", "verdict": "NOT-FILEABLE",
                            "reason": "restricted per the program description; not the real config."}])
            os.environ["AUDITOOOR_ADVERSARIAL_CONFIG_STRICT"] = "1"
            try:
                rc = bcrc.main(["--workspace", str(ws)])
            finally:
                os.environ.pop("AUDITOOOR_ADVERSARIAL_CONFIG_STRICT", None)
            self.assertEqual(rc, 1, "strict + flagged -> rc 1")


if __name__ == "__main__":
    unittest.main()
