from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
import sys
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

from lib import triager_precheck_schema as schema


class TriagerPrecheckSchemaProviderStatusTest(unittest.TestCase):
    def test_blank_silent_kill_votes_has_expected_classes(self) -> None:
        self.assertEqual(
            schema.blank_silent_kill_votes(),
            {
                "duplicate": 0,
                "no_fund_impact": 0,
                "dos": 0,
                "design_intended": 0,
                "event_only": 0,
                "user_error": 0,
                "reachability": 0,
            },
        )

    def test_detect_provider_status_uses_concrete_report_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "reports" / "v3_iter_2026-05-24" / "lane_V3_REMAINING_P4_TRIAGER_MODEL" / "provider_prereq_resolution.json"
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(
                """{
  "p4_can_run_now": false,
  "provider_auth": {
    "kimi": {
      "usable_dry_run": true,
      "usable_live_smoke": false,
      "live_smoke_error_class": "http-4xx"
    },
    "minimax": {
      "usable_dry_run": false,
      "usable_live_smoke": false,
      "live_smoke_error_class": "not-attempted-no-dry-run-auth"
    }
  },
  "network_consent": {
    "AUDITOOOR_LLM_NETWORK_CONSENT": false,
    "ADVERSARIAL_LIVE_CONSENT": false
  },
  "local_dependency_blockers": [{"blocker": "missing scikit-learn"}]
}""",
                encoding="utf-8",
            )
            status = schema.detect_provider_status(root)

        self.assertEqual(status["state"], "blocked")
        self.assertIn("blocked", status["reason"])
        self.assertTrue(status.get("blockers"))
        self.assertIn("kimi_live_smoke_http-4xx", status["blockers"])
        self.assertIn("minimax_auth_unusable_dry_run", status["blockers"])
        self.assertNotIn("minimax_live_smoke_not-attempted-no-dry-run-auth", status["blockers"])
        self.assertIn("live_network_consent_missing", status["blockers"])
        self.assertIn("evidence_report", status)

    def test_detect_provider_status_honors_explicit_no_live_call_requirement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "reports" / "v3_iter_2026-05-24" / "lane_V3_REMAINING_P4_TRIAGER_MODEL" / "provider_prereq_resolution.json"
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(
                """{
  "p4_can_run_now": false,
  "provider_auth": {},
  "network_consent": {
    "required_for_live_calls": false,
    "AUDITOOOR_LLM_NETWORK_CONSENT": false,
    "ADVERSARIAL_LIVE_CONSENT": false
  },
  "local_dependency_blockers": [{"blocker": "missing scikit-learn"}]
}""",
                encoding="utf-8",
            )
            status = schema.detect_provider_status(root)

        self.assertEqual(status["state"], "blocked")
        self.assertIn("missing scikit-learn", status["blockers"])
        self.assertNotIn("live_network_consent_missing", status["blockers"])

    def test_detect_provider_status_ignores_blank_settings_env_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "fake-home"
            settings = home / ".claude" / "settings.json"
            settings.parent.mkdir(parents=True, exist_ok=True)
            settings.write_text(
                """{
  "env": {
    "KIMI_API_KEY": "",
    "MINIMAX_API_KEY": "   ",
    "ANTHROPIC_API_KEY": "",
    "ANTHROPIC_AUTH_TOKEN": " "
  }
}""",
                encoding="utf-8",
            )
            with mock.patch.dict(
                os.environ,
                {
                    key: value
                    for key, value in os.environ.items()
                    if key
                    not in {
                        "KIMI_API_KEY",
                        "MINIMAX_API_KEY",
                        "ANTHROPIC_API_KEY",
                        "ANTHROPIC_AUTH_TOKEN",
                    }
                },
                clear=True,
            ):
                with mock.patch.object(Path, "home", return_value=home):
                    status = schema.detect_provider_status(root)

        self.assertEqual(status["state"], "not_configured")
        self.assertEqual(status["provider"], "none")
        self.assertNotIn("blockers", status)

    def test_recommended_action_low_confidence_does_not_claim_provider_readiness(self) -> None:
        action = schema.recommended_action(
            [
                {
                    "outcome_class_key": "F_no_fund_impact_or_actor_model",
                    "score": 1,
                }
            ],
            {
                "source": "local_disposition_classifier",
                "provider_backed": False,
                "confidence": 0.4,
            },
        )

        self.assertEqual(
            action,
            "manual_review_local_classifier_low_confidence_no_provider_readiness_claim",
        )


if __name__ == "__main__":
    unittest.main()
