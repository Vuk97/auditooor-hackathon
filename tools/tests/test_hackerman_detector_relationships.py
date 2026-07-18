from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-detector-relationships.py"
FIXTURES = REPO_ROOT / "tools" / "tests" / "fixtures" / "hackerman_records"


def _load_tool():
    spec = importlib.util.spec_from_file_location("hackerman_detector_relationships", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {TOOL}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


CUSTOM_REENTRANCY_RECORD = textwrap.dedent(
    """\
    schema_version: auditooor.hackerman_record.v1
    record_id: custom:reentrancy-withdraw:1111aaaa
    source_audit_ref: custom:reentrancy-withdraw
    target_domain: lending
    target_language: solidity
    target_repo: sample/vault
    target_component: Vault.withdraw
    function_shape:
      raw_signature: "function withdraw(uint256 assets) external"
      shape_tags:
        - withdraw-callback
        - external-withdraw
    bug_class: reentrancy
    attack_class: reentrancy-via-hook-or-callback
    attacker_role: unprivileged
    attacker_action_sequence: "Step 1: withdraw. Step 2: reenter via callback."
    required_preconditions:
      - callback-enabled token
    impact_class: theft
    impact_actor: liquidity-providers
    impact_dollar_class: "$10K-$100K"
    fix_pattern: move accounting before external callback and lock reentry
    fix_anti_pattern_avoided: external callback before accounting
    severity_at_finding: high
    year: 2025
    cross_language_analogues: []
    related_records: []
    """
)


CUSTOM_WEAKER_SHARE_RECORD = textwrap.dedent(
    """\
    schema_version: auditooor.hackerman_record.v1
    record_id: custom:preview-share-skew:2222bbbb
    source_audit_ref: custom:preview-share-skew
    target_domain: lending
    target_language: solidity
    target_repo: sample/vault
    target_component: Previewer.previewDeposit
    function_shape:
      raw_signature: "function previewDeposit(uint256 assets) public view returns (uint256 shares)"
      shape_tags:
        - preview-deposit
    bug_class: share-inflation
    attack_class: share-price-manipulation
    attacker_role: unprivileged
    attacker_action_sequence: "Step 1: perturb exchange rate. Step 2: preview victim deposit."
    required_preconditions:
      - share pricing uses live balances
    impact_class: theft
    impact_actor: depositor-class
    impact_dollar_class: "$10K-$100K"
    fix_pattern: keep preview and deposit accounting on the same internal state
    fix_anti_pattern_avoided: preview on attacker-influenced balances
    severity_at_finding: medium
    year: 2024
    cross_language_analogues: []
    related_records: []
    """
)


class HackermanDetectorRelationshipsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_tool()

    def _build_tag_dir(self, root: Path) -> Path:
        tag_dir = root / "tags"
        tag_dir.mkdir()
        shutil.copy(FIXTURES / "valid_lending_share_inflation.yaml", tag_dir / "valid_lending_share_inflation.yaml")
        shutil.copy(FIXTURES / "valid_go_fee_bypass.yml", tag_dir / "valid_go_fee_bypass.yml")
        shutil.copy(FIXTURES / "invalid_missing_attack_class.yaml", tag_dir / "invalid_missing_attack_class.yaml")
        shutil.copy(FIXTURES / "legacy_verdict_tag.yaml", tag_dir / "legacy_verdict_tag.yaml")
        (tag_dir / "custom_reentrancy.yaml").write_text(CUSTOM_REENTRANCY_RECORD, encoding="utf-8")
        (tag_dir / "custom_weaker_share.yaml").write_text(CUSTOM_WEAKER_SHARE_RECORD, encoding="utf-8")
        return tag_dir

    def test_json_engage_report_groups_and_ranks_relationships(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman_detector_rel_json_") as tmp:
            base = Path(tmp)
            tag_dir = self._build_tag_dir(base)
            engage = base / "engage_report.json"
            _write_json(
                engage,
                {
                    "schema": "auditooor.engage_report.sidecar.v1",
                    "clusters": [
                        {
                            "detector_slug": "deposit-share-inflation",
                            "hit_count": 2,
                            "hits": [
                                {
                                    "severity": "HIGH",
                                    "file_path": "src/EVault.sol:55",
                                    "snippet": "deposit mints shares from live balance after attacker donation",
                                }
                            ],
                        },
                        {
                            "detector_slug": "reentrancy-no-guard",
                            "hit_count": 1,
                            "hits": [
                                {
                                    "severity": "HIGH",
                                    "file_path": "src/Vault.sol:42",
                                    "snippet": "withdraw callback path lacks reentrancy guard before accounting update",
                                }
                            ],
                        },
                        {
                            "detector_slug": "blocked-addr-check-missing",
                            "hit_count": 1,
                            "hits": [
                                {
                                    "severity": "MEDIUM",
                                    "file_path": "x/affiliates/keeper/keeper.go:88",
                                    "snippet": "keeper writes affiliate recipient without blocked address validation",
                                }
                            ],
                        },
                    ],
                },
            )

            payload = self.mod.build_payload(
                self.mod.build_parser().parse_args(
                    [
                        "--tag-dir",
                        str(tag_dir),
                        "--engage-report",
                        str(engage),
                        "--limit",
                        "3",
                    ]
                )
            )

            self.assertEqual(payload["schema"], "auditooor.hackerman.detector_relationships.v1")
            self.assertTrue(payload["advisory_only"])
            self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
            self.assertEqual(payload["summary"]["records_loaded"], 4)
            self.assertEqual(payload["summary"]["records_skipped_invalid"], 1)
            self.assertEqual(payload["summary"]["records_skipped_non_record"], 1)
            self.assertEqual(payload["summary"]["detectors_scanned"], 3)
            self.assertEqual(payload["summary"]["detectors_returned"], 3)

            detector_ids = [row["detector_slug"] for row in payload["detectors"]]
            self.assertEqual(detector_ids, ["deposit-share-inflation", "reentrancy-no-guard", "blocked-addr-check-missing"])

            deposit = payload["detectors"][0]
            self.assertEqual(deposit["relationships"][0]["record_id"], "solodit:euler-2024-10-15:42:a1b2c3d4")
            self.assertGreaterEqual(deposit["relationships"][0]["score"], deposit["relationships"][1]["score"])
            self.assertIn("attack_class overlap", deposit["relationships"][0]["match_reasons"])
            self.assertIn("component overlap", deposit["relationships"][0]["match_reasons"])

            blocked = next(row for row in payload["detectors"] if row["detector_slug"] == "blocked-addr-check-missing")
            self.assertEqual(blocked["relationships"][0]["record_id"], "audit:dydx-2025-01-10:fee-bypass:bbbbcccc")
            self.assertEqual(blocked["relationships"][0]["bug_class"], "missing-blocked-address-check")
            matched_sources = {item["source"] for item in blocked["relationships"][0]["attack_matches"]}
            self.assertIn("record_attack_class", matched_sources)

            reentrancy = next(row for row in payload["detectors"] if row["detector_slug"] == "reentrancy-no-guard")
            self.assertEqual(reentrancy["relationships"][0]["record_id"], "custom:reentrancy-withdraw:1111aaaa")
            self.assertIn("reentrancy", reentrancy["relationships"][0]["bug_match"]["matched_tokens"])

    def test_markdown_engage_report_cli_json_out(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman_detector_rel_md_") as tmp:
            base = Path(tmp)
            tag_dir = self._build_tag_dir(base)
            engage_md = base / "engage_report.md"
            out_json = base / "relationships.json"
            engage_md.write_text(
                textwrap.dedent(
                    """\
                    # Engagement Report

                    ## Clusters

                    ### blocked-addr-check-missing
                    - x/affiliates/keeper/keeper.go:88: keeper writes affiliate recipient without blocked address validation
                    """
                ),
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--tag-dir",
                    str(tag_dir),
                    "--engage-report",
                    str(engage_md),
                    "--limit",
                    "2",
                    "--json",
                    "--out",
                    str(out_json),
                ],
                cwd=REPO_ROOT,
                check=True,
                capture_output=True,
                text=True,
            )

            self.assertEqual(proc.stdout, "")
            payload = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["detectors_returned"], 1)
            self.assertEqual(payload["detectors"][0]["detector_slug"], "blocked-addr-check-missing")
            self.assertEqual(payload["detectors"][0]["relationships"][0]["record_id"], "audit:dydx-2025-01-10:fee-bypass:bbbbcccc")

    def test_empty_input_returns_empty_payload(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman_detector_rel_empty_") as tmp:
            tag_dir = Path(tmp) / "tags"
            tag_dir.mkdir()

            payload = self.mod.build_payload(
                self.mod.build_parser().parse_args(
                    [
                        "--tag-dir",
                        str(tag_dir),
                        "--limit",
                        "4",
                    ]
                )
            )

            self.assertEqual(payload["summary"]["records_loaded"], 0)
            self.assertEqual(payload["summary"]["detectors_scanned"], 0)
            self.assertEqual(payload["summary"]["relationship_rows_returned"], 0)
            self.assertEqual(payload["detectors"], [])
            md = self.mod.render_markdown(payload)
            self.assertIn("No detector clusters were loaded", md)

    def test_v1_1_schema_records_are_loaded(self) -> None:
        # Regression: the Wave-2-A corpus migration flipped every record to
        # schema_version v1.1. An exact-match `== v1` filter in `_is_record`
        # silently rejected the entire migrated corpus (6/36475 loaded).
        with tempfile.TemporaryDirectory() as tmp:
            tag_dir = Path(tmp) / "tags"
            tag_dir.mkdir()
            v11_record = CUSTOM_REENTRANCY_RECORD.replace(
                "schema_version: auditooor.hackerman_record.v1",
                "schema_version: auditooor.hackerman_record.v1.1",
            )
            (tag_dir / "v11.yaml").write_text(v11_record, encoding="utf-8")
            records, summary = self.mod._load_records(tag_dir, {})
            self.assertEqual(summary["records_loaded"], 1)
            self.assertEqual(summary["records_skipped_non_record"], 0)
            self.assertEqual(records[0]["record_id"], "custom:reentrancy-withdraw:1111aaaa")


if __name__ == "__main__":
    unittest.main()
