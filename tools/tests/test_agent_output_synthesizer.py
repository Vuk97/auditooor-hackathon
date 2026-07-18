#!/usr/bin/env python3
"""Tests for scanner promotion advisory surfacing in agent-output-synthesizer."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "agent-output-synthesizer.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("agent_output_synthesizer", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["agent_output_synthesizer"] = module
    spec.loader.exec_module(module)
    return module


class AgentOutputSynthesizerScannerAdvisoryTest(unittest.TestCase):
    def test_scanner_advisory_becomes_capability_gap_candidate(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "scanner_promotion_advisories.json").write_text(
                json.dumps(
                    {
                        "schema_version": "auditooor.scanner_promotion_advisories.v1",
                        "workspace": str(ws),
                        "advisory_count": 1,
                        "advisories": [
                            {
                                "id": "scanner-promo-test",
                                "kind": "capability_gap",
                                "promotion_status": "needs_poc",
                                "severity_floor": "LOW",
                                "severity_promotion_allowed": False,
                                "shape": "factory_constructor_pool_liveness_config",
                                "contract": "RevertLikeFactory",
                                "file": "src/RevertLikeFactory.sol",
                                "line": 9,
                                "matched_low_detectors": ["fee-cap-check"],
                                "signals": ["later_swap_or_liquidity_action"],
                                "reason": "LOW scanner hit overlaps factory pool liveness config.",
                                "recommended_next_step": "Build a swap/liquidity PoC.",
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = tool.synthesize_brief_candidates(ws)

            self.assertEqual(payload["summary"]["candidate_count"], 1)
            self.assertEqual(payload["summary"]["capability_gaps"], 1)
            self.assertEqual(payload["summary"]["scanner_promotion_advisories"], 1)
            candidate = payload["candidates"][0]
            self.assertEqual(candidate["kind"], "capability_gap")
            self.assertEqual(candidate["promotion_status"], "needs_poc")
            self.assertTrue(candidate["capability_gap"])
            self.assertEqual(candidate["scanner_advisory_id"], "scanner-promo-test")
            self.assertFalse(candidate["severity_promotion_allowed"])

    def test_scanner_advisory_appears_in_needs_verify(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "scanner_promotion_advisories.json").write_text(
                json.dumps(
                    {
                        "schema_version": "auditooor.scanner_promotion_advisories.v1",
                        "workspace": str(ws),
                        "advisory_count": 1,
                        "advisories": [
                            {
                                "id": "scanner-promo-test",
                                "contract": "RevertLikeFactory",
                                "file": "src/RevertLikeFactory.sol",
                                "line": 9,
                                "reason": "LOW scanner hit needs pool liveness PoC.",
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = tool.synthesize_findings([], ws)

            # scanner_promotion_advisories is no longer in summary to prevent double-counting;
            # check the top-level list instead
            self.assertEqual(len(payload["scanner_promotion_advisories"]), 1)
            self.assertNotIn("scanner_promotion_advisories", payload["summary"])
            self.assertEqual(payload["summary"]["needs_verify_count"], 1)
            row = payload["needs_verify"][0]
            self.assertEqual(row["kind"], "capability_gap")
            self.assertEqual(row["promotion_status"], "needs_poc")
            self.assertEqual(row["scanner_advisory_id"], "scanner-promo-test")
            self.assertEqual(row["severity_floor"], "LOW")
            self.assertFalse(row["severity_promotion_allowed"])
            self.assertEqual(row["source_citation"]["file"], "src/RevertLikeFactory.sol")
            self.assertEqual(row["source_citation"]["line"], 9)
            self.assertEqual(row["evidence_class"], "generated_hypothesis")

    def test_scanner_advisory_discovered_from_custom_scan_out_manifest(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            custom_out = ws / ".audit_logs" / "scan" / "run-1"
            custom_out.mkdir(parents=True)
            advisory_path = custom_out / "scanner_promotion_advisories.json"
            advisory_path.write_text(
                json.dumps(
                    {
                        "schema_version": "auditooor.scanner_promotion_advisories.v1",
                        "workspace": str(ws),
                        "advisory_count": 1,
                        "advisories": [
                            {
                                "id": "scanner-promo-custom-out",
                                "kind": "capability_gap",
                                "promotion_status": "needs_poc",
                                "severity_floor": "LOW",
                                "severity_promotion_allowed": False,
                                "contract": "CustomOutFactory",
                                "file": "src/CustomOutFactory.sol",
                                "line": 17,
                                "reason": "LOW scanner hit needs pool liveness PoC.",
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (custom_out / "detector_environment_manifest.json").write_text(
                json.dumps(
                    {
                        "schema_version": "auditooor.detector_environment.v1",
                        "workspace": str(ws),
                        "scanner_promotion_advisories": {
                            "schema_version": "auditooor.scanner_promotion_advisories.v1",
                            "artifact": "scanner_promotion_advisories.json",
                            "artifact_path": str(advisory_path),
                            "artifact_relative_to_manifest": "scanner_promotion_advisories.json",
                            "advisory_count": 1,
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = tool.synthesize_brief_candidates(ws)

            self.assertEqual(payload["summary"]["candidate_count"], 1)
            self.assertEqual(payload["summary"]["scanner_promotion_advisories"], 1)
            candidate = payload["candidates"][0]
            self.assertEqual(candidate["kind"], "capability_gap")
            self.assertEqual(candidate["scanner_advisory_id"], "scanner-promo-custom-out")
            self.assertEqual(candidate["source_file"], str(advisory_path))
            self.assertFalse(candidate["severity_promotion_allowed"])

            normal_payload = tool.synthesize_findings([], ws)
            self.assertEqual(len(normal_payload["scanner_promotion_advisories"]), 1)
            self.assertNotIn("scanner_promotion_advisories", normal_payload["summary"])
            self.assertEqual(normal_payload["summary"]["needs_verify_count"], 1)
            self.assertEqual(normal_payload["needs_verify"][0]["source"], str(advisory_path))
            self.assertFalse(normal_payload["needs_verify"][0]["severity_promotion_allowed"])

    def test_scanner_advisory_discovered_from_scanners_directory(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            scanners = ws / "scanners"
            scanners.mkdir()
            (scanners / "scanner_promotion_advisories.json").write_text(
                json.dumps(
                    {
                        "schema_version": "auditooor.scanner_promotion_advisories.v1",
                        "workspace": str(ws),
                        "advisory_count": 1,
                        "advisories": [
                            {
                                "id": "scanner-promo-scanners-dir",
                                "contract": "ScannerDirFactory",
                                "file": "src/ScannerDirFactory.sol",
                                "line": 21,
                                "reason": "LOW scanner hit needs PoC.",
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = tool.synthesize_findings([], ws)

            self.assertEqual(len(payload["scanner_promotion_advisories"]), 1)
            self.assertNotIn("scanner_promotion_advisories", payload["summary"])
            self.assertEqual(payload["needs_verify"][0]["scanner_advisory_id"], "scanner-promo-scanners-dir")

    def test_schema_mismatch_reports_diagnostic_but_keeps_useful_rows(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "scanner_promotion_advisories.json").write_text(
                json.dumps(
                    {
                        "schema_version": "legacy.schema",
                        "workspace": str(ws),
                        "advisory_count": 2,
                        "advisories": [
                            {
                                "id": "scanner-promo-legacy-schema",
                                "schema_version": "legacy.row",
                                "contract": "LegacyFactory",
                                "file": "src/LegacyFactory.sol",
                                "line": 31,
                                "reason": "Legacy advisory row still has useful triage context.",
                            },
                            "not-an-object",
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = tool.synthesize_brief_candidates(ws)

            self.assertEqual(payload["summary"]["candidate_count"], 1)
            self.assertEqual(payload["summary"]["scanner_promotion_advisories"], 1)
            self.assertGreaterEqual(payload["summary"]["scanner_promotion_advisory_diagnostics"], 3)
            codes = {item["code"] for item in payload["scanner_promotion_advisory_diagnostics"]}
            self.assertIn("schema_version_mismatch", codes)
            self.assertIn("row_schema_version_mismatch", codes)
            self.assertIn("invalid_advisory_row", codes)
            candidate = payload["candidates"][0]
            self.assertEqual(candidate["scanner_advisory_id"], "scanner-promo-legacy-schema")
            self.assertEqual(candidate["severity_floor"], "LOW")
            self.assertFalse(candidate["severity_promotion_allowed"])


    def test_no_double_count_when_parser_and_scanner_advisories_both_present(self) -> None:
        # Regression test for: scanner_promotion_advisories double-counted in summary.
        # Root cause: scanner advisories were appended to needs_verify list (line ~685),
        # but also reported as a separate count in summary["scanner_promotion_advisories"]
        # (line ~715). Consumers that summed needs_verify_count + scanner_promotion_advisories
        # got N extra. Fix: remove scanner_promotion_advisories from the summary sub-dict so
        # only needs_verify_count (the total, inclusive) is reported there.
        #
        # Setup: 1 parser NEEDS_VERIFY + 2 scanner advisories.
        #   needs_verify list length = 3 (1 + 2, correct)
        #   needs_verify_count must == 3
        #   scanner_promotion_advisories must NOT appear in summary (it is embedded in the count)
        #   needs_verify_count_from_parsers must == 1 (parser-only sub-count)
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "scanner_promotion_advisories.json").write_text(
                json.dumps(
                    {
                        "schema_version": "auditooor.scanner_promotion_advisories.v1",
                        "workspace": str(ws),
                        "advisory_count": 2,
                        "advisories": [
                            {
                                "id": "scanner-promo-dc-1",
                                "contract": "FooFactory",
                                "file": "src/FooFactory.sol",
                                "line": 10,
                                "reason": "First advisory.",
                            },
                            {
                                "id": "scanner-promo-dc-2",
                                "contract": "BarFactory",
                                "file": "src/BarFactory.sol",
                                "line": 20,
                                "reason": "Second advisory.",
                            },
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            # One parser-sourced NEEDS_VERIFY item
            parsed_list = [
                {
                    "source_file": "agent_output_1.md",
                    "word_count": 50,
                    "verdicts": [{"type": "NEEDS_VERIFY", "details": "Potential reentrancy", "severity": "HIGH"}],
                    "citations": [],
                    "attack_paths": [],
                }
            ]

            result = tool.synthesize_findings(parsed_list, ws)
            summary = result["summary"]

            # The needs_verify list must contain all 3 items
            self.assertEqual(len(result["needs_verify"]), 3)

            # needs_verify_count must equal the actual list length (no inflation)
            self.assertEqual(summary["needs_verify_count"], 3)
            self.assertEqual(summary["needs_verify_count"], len(result["needs_verify"]))

            # Parser-only sub-count must be present and correct
            self.assertEqual(summary["needs_verify_count_from_parsers"], 1)

            # scanner_promotion_advisories must NOT be in the summary dict:
            # it is already embedded in needs_verify_count, so its presence would
            # mislead consumers into double-counting (the regression being guarded).
            self.assertNotIn(
                "scanner_promotion_advisories",
                summary,
                "scanner_promotion_advisories should not be in summary: it is already "
                "included in needs_verify_count and would cause double-count if summed.",
            )

            # The top-level scanner_promotion_advisories list (not the summary) still has 2 items
            self.assertEqual(len(result["scanner_promotion_advisories"]), 2)

            # The fundamental invariant: total == parsers + scanner advisory count (from top-level list)
            self.assertEqual(
                summary["needs_verify_count"],
                summary["needs_verify_count_from_parsers"] + len(result["scanner_promotion_advisories"]),
            )


if __name__ == "__main__":
    unittest.main()
