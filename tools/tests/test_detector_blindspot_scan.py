from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "detector-blindspot-scan.py"
SOURCE_REF_FIXTURES = ROOT / "tools" / "tests" / "fixtures" / "source_ref_replay_manifest"


def _load_tool():
    spec = importlib.util.spec_from_file_location("detector_blindspot_scan_under_test", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


class DetectorBlindspotScanTests(unittest.TestCase):
    def test_extract_github_refs_keeps_commit_pinned_blob_links(self) -> None:
        refs = MOD.extract_github_refs(
            "See https://github.com/code-423n4/2024-04-dyad/blob/"
            "9f5b3e2c1a0d9876543210abcdefabcdefabcd12/src/VaultManagerV2.sol#L20"
        )

        self.assertEqual(
            refs,
            [{
                "repo": "code-423n4/2024-04-dyad",
                "commit": "9f5b3e2c1a0d9876543210abcdefabcdefabcd12",
                "ref_type": "commit",
                "filepath": "src/VaultManagerV2.sol",
                "url": (
                    "https://github.com/code-423n4/2024-04-dyad/blob/"
                    "9f5b3e2c1a0d9876543210abcdefabcdefabcd12/src/VaultManagerV2.sol"
                ),
            }],
        )

    def test_extract_github_refs_accepts_named_ref_blob_links(self) -> None:
        refs = MOD.extract_github_refs(
            "The draft cites "
            "https://github.com/code-423n4/2022-10-inverse/blob/main/src/Oracle.sol#L15"
        )

        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["repo"], "code-423n4/2022-10-inverse")
        self.assertEqual(refs[0]["commit"], "main")
        self.assertEqual(refs[0]["ref_type"], "named_ref")
        self.assertEqual(refs[0]["filepath"], "src/Oracle.sol")

    def test_extract_github_refs_accepts_raw_githubusercontent_links(self) -> None:
        refs = MOD.extract_github_refs(
            "raw source: https://raw.githubusercontent.com/org/protocol/"
            "abcdef1234567890abcdef1234567890abcdef12/contracts/Vault.sol"
        )

        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["repo"], "org/protocol")
        self.assertEqual(refs[0]["commit"], "abcdef1234567890abcdef1234567890abcdef12")
        self.assertEqual(refs[0]["ref_type"], "commit")
        self.assertEqual(refs[0]["filepath"], "contracts/Vault.sol")

    def test_extract_github_refs_dedupes_markdown_and_html_copies(self) -> None:
        content = (
            "[Vault](https://github.com/org/protocol/blob/main/src/Vault.sol#L1) "
            '<a href="https://github.com/org/protocol/blob/main/src/Vault.sol#L1">'
            "Vault</a>"
        )

        refs = MOD.extract_github_refs(content)

        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["repo"], "org/protocol")
        self.assertEqual(refs[0]["commit"], "main")
        self.assertEqual(refs[0]["filepath"], "src/Vault.sol")

    def test_input_validation_classifier_uses_phrase_level_signals(self) -> None:
        self.assertEqual(
            MOD.classify_finding(
                "Missing debt validation in group burn function",
                "The burn path fails to validate expired debt before updating balances.",
                ["validation", "erc1155", "burn", "missing-check"],
            ),
            "input-validation",
        )
        self.assertEqual(
            MOD.classify_finding(
                "Fallback handler supplied address missing validation",
                "The fallback handler setter accepts an invalid input address.",
                ["gnosis-safe", "erc721", "erc1155", "missing-check"],
            ),
            "input-validation",
        )

    def test_input_validation_classifier_does_not_collapse_mixed_missing_check_tags(self) -> None:
        self.assertNotEqual(
            MOD.classify_finding(
                "USDs stability compromised because Gamma vault collateral is ignored",
                "Liquidation health checks omit Gamma vault collateral from accounting.",
                ["liquidation", "collateral", "missing-check", "accounting"],
            ),
            "input-validation",
        )
        self.assertNotEqual(
            MOD.classify_finding(
                "Missing enough exogenous collateral check in VaultManagerV2::liquidate",
                "The liquidate path should check exogenous collateral before liquidation.",
                ["liquidation", "missing-check", "collateral", "validation"],
            ),
            "input-validation",
        )
        self.assertNotEqual(
            MOD.classify_finding(
                "Reroll with different fighterType bypasses maxRerollsAllowed",
                "Changing fighterType bypasses the reroll limit state machine.",
                ["validation", "missing-check", "nft", "bypass"],
            ),
            "input-validation",
        )

    def test_uncategorized_gap_rows_get_narrow_taxonomy_classes(self) -> None:
        self.assertEqual(
            MOD.classify_finding(
                "USDs stability can be compromised as collateral deposited to Gamma vaults "
                "is not considered during liquidation",
                "Vault collateral supports health but is excluded from liquidation seizure.",
                [],
            ),
            "yield-vault-collateral-excluded-from-liquidation-seizure",
        )
        self.assertEqual(
            MOD.classify_finding(
                "[C-01] Decreasing position size via leverage update can be abused to "
                "steal from diamond",
                (
                    "The trader can decrease position size using leverage update; "
                    "handleTradePnl then misaligns partial profit/loss and closing fee "
                    "value flow."
                ),
                [],
            ),
            "perps-partial-position-decrease-pnl-fee-value-flow-mismatch",
        )
        self.assertEqual(
            MOD.classify_finding(
                "[H-07] Missing enough exogenous collateral check in "
                "VaultManagerV2::liquidate",
                "Liquidation can revert when non-kerosene collateral is insufficient.",
                [],
            ),
            "exogenous-collateral-liquidation-eligibility-check-missing",
        )
        self.assertEqual(
            MOD.classify_finding(
                "[H-04] Can reroll with different fighterType and bypass maxRerollsAllowed",
                "The caller supplied fighterType is not bound to the owned token type.",
                [],
            ),
            "token-attribute-type-parameter-not-bound-to-owned-token",
        )

    def test_requested_tier_filter_controls_keyword_coverage(self) -> None:
        detector_help = {
            "swap-missing-slippage-protection": ("B", "missing slippage check"),
            "flashloan-callback-missing-initiator-check": ("B", "flashloan callback auth"),
            "oracle-stale-price": ("A", "oracle freshness"),
        }

        self.assertEqual(
            MOD.detectors_cover_class("slippage", detector_help, tier_filter="S,E,A"),
            [],
        )
        self.assertEqual(
            MOD.detectors_cover_class("flashloan", detector_help, tier_filter="S,E,A"),
            [],
        )
        self.assertEqual(
            MOD.detectors_cover_class("slippage", detector_help, tier_filter="S,E,A,B"),
            ["swap-missing-slippage-protection"],
        )
        self.assertEqual(
            MOD.detectors_cover_class("flashloan", detector_help, tier_filter="S,E,A,B"),
            ["flashloan-callback-missing-initiator-check"],
        )

    def test_all_tier_filter_accepts_any_registry_tier(self) -> None:
        detector_help = {
            "swap-missing-slippage-protection": ("B", "missing slippage check"),
            "experimental-slippage-shape": ("D", "draft slippage shape"),
        }

        self.assertEqual(MOD.parse_tier_filter("ALL"), set())
        self.assertEqual(
            MOD.detectors_cover_class("slippage", detector_help, tier_filter="ALL"),
            ["swap-missing-slippage-protection", "experimental-slippage-shape"],
        )

    def test_analyze_finding_preserves_github_ref_when_checkout_fails(self) -> None:
        original_sparse_checkout = MOD.sparse_checkout
        MOD.sparse_checkout = lambda *args, **kwargs: None
        try:
            with tempfile.TemporaryDirectory() as tmp:
                row = MOD.analyze_finding(
                    {
                        "id": "F-preserve",
                        "title": "Missing slippage",
                        "content": (
                            "See https://github.com/org/protocol/blob/"
                            "abcdef1234567890abcdef1234567890abcdef12/src/Vault.sol"
                        ),
                        "tags": ["slippage"],
                        "severity": "HIGH",
                    },
                    detector_help={},
                    scratch_dir=Path(tmp),
                    tier="S,E,A,B",
                )
        finally:
            MOD.sparse_checkout = original_sparse_checkout

        self.assertEqual(row["github_ref"]["repo"], "org/protocol")
        self.assertEqual(row["github_ref"]["filepath"], "src/Vault.sol")
        self.assertEqual(row["detectors_run"], 0)
        self.assertEqual(row["analysis_mode"], "keyword-based")

    def test_emit_source_ref_replay_manifest_uses_gap_report_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "detector_gap_source_ref_replay_manifest.json"

            manifest = MOD.emit_source_ref_replay_manifest(
                [
                    MOD.normalize_finding(
                        {
                            "id": "F-manifest",
                            "title": "Pinned source",
                            "description": (
                                "See https://github.com/org/protocol/blob/"
                                "abcdef1234567890abcdef1234567890abcdef12/src/Vault.sol"
                            ),
                        }
                    )
                ],
                out,
            )

            written = json.loads(out.read_text())

        self.assertEqual(manifest["row_count"], 1)
        self.assertEqual(written, manifest)
        row = manifest["rows"][0]
        self.assertEqual(row["finding_id"], "F-manifest")
        self.assertEqual(row["repo"], "org/protocol")
        self.assertEqual(row["filepath"], "src/Vault.sol")
        self.assertEqual(row["resolved_commit"], "abcdef1234567890abcdef1234567890abcdef12")
        self.assertEqual(row["replay_status"], "blocked_local_source_missing")

    def test_default_source_ref_manifest_path_is_derived_from_detector_gap_output(self) -> None:
        self.assertEqual(
            MOD.default_source_ref_manifest_path(Path("reports/detector_gap.json")),
            Path("reports/detector_gap_source_ref_replay_manifest.json"),
        )

    def test_markdown_report_records_companion_source_ref_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "gap.md"
            MOD.emit_markdown_report(
                [
                    {
                        "finding_id": "F-md",
                        "title": "Missing slippage",
                        "severity": "HIGH",
                        "bug_class": "slippage",
                        "solodit_url": "https://example.invalid/finding",
                        "status": "analyzed",
                        "is_blindspot": True,
                        "covering_detectors": [],
                        "github_ref": None,
                    }
                ],
                out,
                {
                    "queried": 1,
                    "skipped_language": 0,
                    "checkout_ok": 0,
                    "checkout_skip": 1,
                    "avg_detectors_run": 0,
                    "tier": "S,E,A,B",
                    "active_detectors": 0,
                    "total_detectors": 0,
                    "mode": "keyword-based",
                    "estimated_cost_usd": 0,
                    "source_ref_manifest": "reports/detector_gap_source_ref_replay_manifest.json",
                    "source_ref_manifest_rows": 1,
                },
            )

            text = out.read_text(encoding="utf-8")

        self.assertIn("| Source-ref replay manifest rows | 1 |", text)
        self.assertIn(
            "| Source-ref replay manifest | `reports/detector_gap_source_ref_replay_manifest.json` |",
            text,
        )

    def test_source_ref_preservation_guard_passes_when_gap_row_keeps_ref(self) -> None:
        guard = MOD.enforce_source_ref_preservation(
            [
                {
                    "finding_id": "F-guard",
                    "github_ref": {
                        "repo": "org/protocol",
                        "commit": "abcdef1234567890abcdef1234567890abcdef12",
                        "filepath": "src/Vault.sol",
                    },
                }
            ],
            {
                "rows": [
                    {
                        "finding_id": "F-guard",
                        "source_url": (
                            "https://github.com/org/protocol/blob/"
                            "abcdef1234567890abcdef1234567890abcdef12/src/Vault.sol"
                        ),
                    }
                ]
            },
        )

        self.assertEqual(guard["status"], "pass")
        self.assertEqual(guard["detector_gap_missing_github_ref_finding_ids"], [])

    def test_source_ref_preservation_guard_blocks_manifest_backed_null_ref(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "F-dropped"):
            MOD.enforce_source_ref_preservation(
                [{"finding_id": "F-dropped", "github_ref": None}],
                {
                    "rows": [
                        {
                            "finding_id": "F-dropped",
                            "source_url": (
                                "https://github.com/org/protocol/blob/"
                                "abcdef1234567890abcdef1234567890abcdef12/src/Vault.sol"
                            ),
                        }
                    ]
                },
            )

    def test_main_hydrates_gap_report_from_raw_manifest_source_refs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            data = tmp_path / "findings.json"
            out_json = tmp_path / "detector_gap.json"
            out_md = tmp_path / "detector_gap.md"
            out_manifest = tmp_path / "detector_gap_source_ref_replay_manifest.json"
            data.write_text(
                json.dumps(
                    [
                        {
                            "id": "F-raw-source",
                            "title": "Missing slippage protection",
                            "description": "The swap accepts zero minimum output.",
                            "severity": "HIGH",
                            "tags": ["slippage"],
                            "source_urls": [
                                "https://github.com/acme/vault/blob/main/src/Vault.sol"
                            ],
                        }
                    ]
                ),
                encoding="utf-8",
            )

            old_argv = sys.argv
            old_load_detector_help = MOD.load_detector_help
            try:
                MOD.load_detector_help = lambda _: {}
                sys.argv = [
                    str(TOOL),
                    "--data",
                    str(data),
                    "--max-findings",
                    "1",
                    "--scratch",
                    str(tmp_path / "scratch"),
                    "--out-json",
                    str(out_json),
                    "--out-md",
                    str(out_md),
                    "--out-source-ref-manifest",
                    str(out_manifest),
                    "--named-ref-lockfile",
                    str(SOURCE_REF_FIXTURES / "named_ref_locks.json"),
                    "--local-source-root",
                    str(SOURCE_REF_FIXTURES / "source_root"),
                ]
                MOD.main()
            finally:
                MOD.load_detector_help = old_load_detector_help
                sys.argv = old_argv

            rows = json.loads(out_json.read_text(encoding="utf-8"))
            manifest = json.loads(out_manifest.read_text(encoding="utf-8"))

        self.assertEqual(manifest["row_count"], 1)
        self.assertEqual(manifest["rows"][0]["replay_status"], "immutable_ready")
        github_ref = rows[0]["github_ref"]
        self.assertEqual(github_ref["repo"], "acme/vault")
        self.assertEqual(github_ref["commit"], "a" * 40)
        self.assertEqual(github_ref["original_ref"], "main")
        self.assertEqual(github_ref["filepath"], "src/Vault.sol")
        self.assertEqual(github_ref["replay_status"], "immutable_ready")


if __name__ == "__main__":
    unittest.main()
