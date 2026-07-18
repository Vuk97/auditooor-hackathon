"""Tests for tools/antipattern-attribution-check.py."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "antipattern_attribution_check",
    ROOT / "tools" / "antipattern-attribution-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


class AntipatternAttributionCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="r59_antipattern_")
        self.root = Path(self.tmp.name)
        self.catalog = self.root / "catalog"
        (self.catalog / "solidity").mkdir(parents=True)
        (self.catalog / "solidity" / "solidity.oracle-price-used-without-freshness-check.yaml").write_text(
            "\n".join(
                [
                    "schema_version: auditooor.antipattern_catalog.v1",
                    "pattern_id: solidity.oracle-price-used-without-freshness-check",
                    "category: freshness-and-staleness",
                    "language: solidity",
                    "severity_floor: medium",
                    "severity_ceiling: critical",
                    "query_type: grep",
                    "query_source: |",
                    "  grep -nE '(oracle|price|stale|fresh)' --include='*.sol' -r .",
                    "description: |",
                    "  Oracle price is consumed without freshness validation.",
                    "false_positive_rate_estimate: 0.35",
                    "source_finding_ids:",
                    "  - \"fixture:oracle-stale-price\"",
                    "  - \"fixture:oracle-freshness-check-missing\"",
                    "target_invariants:",
                    "  - INV-FRESH-001",
                    "known_bug_class_from_corpus:",
                    "  - oracle.stale-price",
                    "empirical_anchors:",
                    "  - stale oracle price",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        (self.catalog / "solidity" / "solidity.reentrancy-external-call-before-state-write.yaml").write_text(
            "\n".join(
                [
                    "schema_version: auditooor.antipattern_catalog.v1",
                    "pattern_id: solidity.reentrancy-external-call-before-state-write",
                    "category: reentrancy",
                    "language: solidity",
                    "severity_floor: medium",
                    "severity_ceiling: critical",
                    "query_type: grep",
                    "query_source: |",
                    "  grep -nE '(call|transfer|send)' --include='*.sol' -r .",
                    "description: |",
                    "  External call occurs before state update.",
                    "false_positive_rate_estimate: 0.35",
                    "source_finding_ids:",
                    "  - \"fixture:reentrancy-one\"",
                    "  - \"fixture:reentrancy-two\"",
                    "target_invariants:",
                    "  - INV-ATM-EX-0001",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        self.draft = self.root / "draft.md"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write(self, body: str) -> Path:
        self.draft.write_text(body, encoding="utf-8")
        return self.draft

    def _run(self, *, severity: str | None = None) -> tuple[int, dict]:
        return mod.run(
            self.draft,
            severity_override=severity,
            catalog_root=self.catalog,
            strict=True,
        )

    def test_passes_when_bound_category_cites_recognized_pattern_id(self) -> None:
        self._write(
            "Severity: High\n"
            "category: freshness-and-staleness\n\n"
            "Anti-pattern attribution: solidity.oracle-price-used-without-freshness-check\n"
        )
        rc, payload = self._run()
        self.assertEqual(rc, 0)
        self.assertEqual(payload["schema"], "auditooor.r59_antipattern_attribution.v1")
        self.assertEqual(payload["verdict"], "pass-antipattern-cited-and-recognized")
        self.assertEqual(
            payload["cited_antipattern_ids"],
            ["solidity.oracle-price-used-without-freshness-check"],
        )

    def test_fails_high_when_category_maps_to_catalog_without_pattern_id(self) -> None:
        self._write(
            "Severity: Critical\n"
            "category: freshness-and-staleness\n\n"
            "The liquidation path consumes stale oracle prices.\n"
        )
        rc, payload = self._run()
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-antipattern-id-cited-for-bound-category")
        self.assertEqual(
            payload["evidence"]["matched_catalog_pattern_ids"],
            ["solidity.oracle-price-used-without-freshness-check"],
        )

    def test_fails_when_cited_pattern_id_does_not_match_bound_category(self) -> None:
        self._write(
            "Severity: High\n"
            "category: freshness-and-staleness\n\n"
            "Anti-pattern attribution: solidity.reentrancy-external-call-before-state-write\n"
        )
        rc, payload = self._run()
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-antipattern-id-does-not-match-bound-category")
        self.assertEqual(payload["cited_matched_antipattern_ids"], [])

    def test_accepts_r59_no_binding_rebuttal(self) -> None:
        self._write(
            "Severity: High\n"
            "category: freshness-and-staleness\n"
            "<!-- r59-no-binding: target-specific doc/config issue, no P3 row binds -->\n"
        )
        rc, payload = self._run()
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_medium_is_out_of_scope(self) -> None:
        self._write(
            "Severity: Medium\n"
            "category: freshness-and-staleness\n"
        )
        rc, payload = self._run()
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_unmapped_high_category_passes_no_binding(self) -> None:
        self._write(
            "Severity: High\n"
            "category: target-specific-edge\n"
        )
        rc, payload = self._run()
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-catalog-binding")


class PreSubmitR59WiringTests(unittest.TestCase):
    def test_pre_submit_wires_check_106_as_high_plus_gate(self) -> None:
        pre_submit = (ROOT / "tools" / "pre-submit-check.sh").read_text(encoding="utf-8")
        self.assertIn("Check #106: R59-ANTIPATTERN-ATTRIBUTION", pre_submit)
        self.assertIn("tools/antipattern-attribution-check.py", pre_submit)
        self.assertIn("HIGH|CRITICAL", pre_submit)
        self.assertIn("fail-no-antipattern-id-cited-for-bound-category", pre_submit)


if __name__ == "__main__":
    unittest.main()
