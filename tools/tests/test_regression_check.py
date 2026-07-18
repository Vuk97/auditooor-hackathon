"""Schema validation tests for tools/regression-check.py + tools/baselines/.

These tests are slither-free on purpose: they only exercise the schema
validator and walk every JSON file under tools/baselines/ to confirm it
round-trips. Detector execution is covered by the regression check itself
when run as `tools/regression-check.py` (see commit message rationale).
"""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "regression-check.py"
BASELINES_DIR = REPO / "tools" / "baselines"


def _load_tool():
    spec = importlib.util.spec_from_file_location("regression_check", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RegressionCheckSchemaTests(unittest.TestCase):
    """Verify the validator accepts well-formed payloads and rejects every
    individual schema violation.
    """

    def setUp(self):
        self.tool = _load_tool()
        self.good = {
            "detector_name": "role-grant-divergence",
            "fixture_path": "detectors/test_fixtures/role_grant_divergence_vulnerable.sol",
            "expected_hits": 1,
            "expected_severity": "HIGH",
            "baseline_date": "2026-04-25",
            "baseline_sha": "5110095ac70fc5e34d5f75341a9e491efdaa08e0",
        }

    def test_well_formed_payload_validates(self):
        self.assertEqual(self.tool.validate_baseline(self.good), [])

    def test_missing_required_key_is_flagged(self):
        for k in self.tool.REQUIRED_KEYS:
            with self.subTest(key=k):
                payload = dict(self.good)
                del payload[k]
                errs = self.tool.validate_baseline(payload)
                self.assertTrue(any(k in e for e in errs),
                                f"expected error mentioning {k!r}, got {errs}")

    def test_negative_expected_hits_rejected(self):
        payload = dict(self.good, expected_hits=-1)
        errs = self.tool.validate_baseline(payload)
        self.assertTrue(any("expected_hits" in e for e in errs))

    def test_non_int_expected_hits_rejected(self):
        payload = dict(self.good, expected_hits="1")
        errs = self.tool.validate_baseline(payload)
        self.assertTrue(any("expected_hits" in e for e in errs))

    def test_invalid_severity_rejected(self):
        payload = dict(self.good, expected_severity="CRITICAL")
        errs = self.tool.validate_baseline(payload)
        self.assertTrue(any("expected_severity" in e for e in errs))

    def test_severity_case_insensitive(self):
        for sev in ("high", "High", "HIGH", "medium", "Low"):
            with self.subTest(severity=sev):
                payload = dict(self.good, expected_severity=sev)
                self.assertEqual(self.tool.validate_baseline(payload), [])

    def test_short_baseline_sha_rejected(self):
        payload = dict(self.good, baseline_sha="abc")
        errs = self.tool.validate_baseline(payload)
        self.assertTrue(any("baseline_sha" in e for e in errs))

    def test_bad_date_rejected(self):
        payload = dict(self.good, baseline_date="2026-04")
        errs = self.tool.validate_baseline(payload)
        self.assertTrue(any("baseline_date" in e for e in errs))

    def test_empty_detector_name_rejected(self):
        payload = dict(self.good, detector_name="")
        errs = self.tool.validate_baseline(payload)
        self.assertTrue(any("detector_name" in e for e in errs))

    def test_load_baselines_roundtrip(self):
        """Every JSON file under tools/baselines/ MUST validate. This is the
        canary that catches a bad commit landing a malformed baseline."""
        baselines = self.tool.load_baselines(BASELINES_DIR)
        # We expect the seeded baselines from this PR (>= 4); the test does not
        # hardcode the exact set, just that they all parse and validate.
        for path, payload in baselines:
            with self.subTest(path=str(path.relative_to(REPO))):
                errs = self.tool.validate_baseline(payload, path)
                self.assertEqual(errs, [], f"schema errors in {path}: {errs}")
        self.assertGreaterEqual(
            len(baselines), 4,
            "expected at least 4 seeded baselines (PR-#177 seed set)",
        )

    def test_load_baselines_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self.tool.load_baselines(Path(tmp)), [])

    def test_load_baselines_skips_dotfiles(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / ".keep").write_text("")
            (d / ".hidden.json").write_text("{}")
            (d / "good.json").write_text(json.dumps(self.good))
            loaded = self.tool.load_baselines(d)
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0][0].name, "good.json")

    def test_load_baselines_raises_on_malformed_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "broken.json").write_text("{not json")
            with self.assertRaises(SystemExit) as ctx:
                self.tool.load_baselines(d)
            self.assertIn("broken.json", str(ctx.exception))


class RegressionCheckCliTests(unittest.TestCase):
    """Smoke tests: --help works without slither, and an empty baselines dir
    is a no-op (exit 0)."""

    def setUp(self):
        self.tool = _load_tool()

    def test_main_help_does_not_require_slither(self):
        # argparse exits 0 on --help via SystemExit
        with self.assertRaises(SystemExit) as ctx:
            self.tool.main(["--help"])
        self.assertEqual(ctx.exception.code, 0)

    def test_check_with_empty_baselines_dir_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = self.tool.main(["--baselines-dir", tmp])
            self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
