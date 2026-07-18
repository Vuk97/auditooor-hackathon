from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-backfill-audit-firm-report-class.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def _record(
    *,
    record_id: str,
    source_path: str,
    attacker_action: str,
    attack_class: str = "audit-firm-public-report",
) -> dict:
    return {
        "schema_version": "auditooor.hackerman_record.v1.1",
        "record_id": record_id,
        "source_audit_ref": f"audit-firm:cyfrin-audit-reports:{source_path}",
        "target_domain": "vault",
        "target_language": "solidity",
        "target_repo": "unknown",
        "target_component": f"Cyfrin/cyfrin-audit-reports:{source_path}",
        "function_shape": {
            "raw_signature": f"audit-firm-report::cyfrin-audit-reports/{source_path}",
            "shape_tags": [
                "audit-firm-public-report",
                "firm-cyfrin-audit-reports",
                "ext-pdf",
                "verification_tier:tier-2-verified-public-archive",
            ],
        },
        "bug_class": "audit-firm-public-report-index",
        "attack_class": attack_class,
        "attacker_role": "unprivileged",
        "attacker_action_sequence": attacker_action,
        "required_preconditions": [
            "Source repo Cyfrin/cyfrin-audit-reports",
            f"Source path {source_path}",
        ],
        "impact_class": "theft",
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": "non-financial",
        "fix_pattern": "Apply the recommendations in the public audit report.",
        "fix_anti_pattern_avoided": "Ignoring public audit recommendations.",
        "severity_at_finding": "info",
        "year": 2026,
        "record_tier": "public-corpus",
        "record_quality_score": 3.0,
        "source_extraction_method": "corpus-etl",
        "source_extraction_confidence": 0.7,
        "verification_method": "manual",
        "verification_tier": "tier-2-verified-public-archive",
        "record_source_url": f"https://raw.githubusercontent.com/Cyfrin/cyfrin-audit-reports/main/{source_path}",
        "cross_language_analogues": [],
        "related_records": [],
    }


def _write_record(root: Path, slug: str, record: dict, *, record_path_override: str | None = None) -> Path:
    """Write a record.yaml (and record.json sibling) under root/slug/.

    ``record_path_override`` allows callers to supply a slug that differs from
    the directory name, simulating the real corpus layout where the directory
    name contains the project name keyword.
    """
    dir_name = record_path_override or slug
    rec_dir = root / dir_name
    rec_dir.mkdir(parents=True, exist_ok=True)
    yaml_path = rec_dir / "record.yaml"
    json_path = rec_dir / "record.json"
    import yaml

    yaml_path.write_text(yaml.safe_dump(record, sort_keys=False), encoding="utf-8")
    json_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return yaml_path


class AuditFirmReportClassBackfillTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL_PATH, "_audit_firm_report_class_backfill_test")

    # ------------------------------------------------------------------
    # Core happy-path tests
    # ------------------------------------------------------------------

    def test_dry_run_emits_conservative_candidates_only(self) -> None:
        """Dry run: 2 of 3 records classified, generic stays unclassified."""
        with tempfile.TemporaryDirectory(prefix="audit-firm-b2-", dir=str(REPO_ROOT)) as tmp:
            tag_dir = Path(tmp) / "audit_firm_public_reports"
            tag_dir.mkdir()
            _write_record(
                tag_dir,
                "bridge",
                _record(
                    record_id="audit-firm:cyfrin:bridge:aaaaaaaaaaaa",
                    source_path="reports/2026-02-10-cyfrin-securitize-bridge-wormhole-executor-v2.0.pdf",
                    attacker_action=(
                        "Report metadata references a bridge Wormhole executor and "
                        "cross-chain message processing."
                    ),
                ),
            )
            _write_record(
                tag_dir,
                "erc4626",
                _record(
                    record_id="audit-firm:oz:erc4626:bbbbbbbbbbbb",
                    source_path="audits/2022-10-ERC4626.pdf",
                    attacker_action="ERC4626 share inflation and first deposit donation attack context.",
                ),
            )
            _write_record(
                tag_dir,
                "generic",
                _record(
                    record_id="audit-firm:sherlock:nuva:cccccccccccc",
                    source_path="audits/Final Report - Nuva Labs.pdf",
                    attacker_action="Generic public audit report listing. PDF body not parsed at this stage.",
                ),
            )
            out = Path(tmp) / "candidates.jsonl"
            summary = self.tool.run(tag_dir, out, min_confidence=0.65, apply=False)
            rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(summary["scanned_records"], 3)
            self.assertEqual(summary["opaque_records"], 3)
            self.assertEqual(summary["candidate_count"], 2)
            self.assertEqual({row["new_attack_class"] for row in rows}, {
                "bridge-proof-domain-bypass",
                "share-accounting",
            })
            self.assertTrue(all(row["classification_scope"] == "report-title-and-metadata-only" for row in rows))

    def test_apply_updates_yaml_json_and_rollback(self) -> None:
        """Apply mode: YAML + JSON + rollback ledger all updated correctly."""
        with tempfile.TemporaryDirectory(prefix="audit-firm-b2-apply-", dir=str(REPO_ROOT)) as tmp:
            tag_dir = Path(tmp) / "audit_firm_public_reports"
            tag_dir.mkdir()
            yaml_path = _write_record(
                tag_dir,
                "bridge",
                _record(
                    record_id="audit-firm:cyfrin:bridge:dddddddddddd",
                    source_path="reports/2026-02-10-cyfrin-securitize-bridge-wormhole-executor-v2.0.pdf",
                    attacker_action="Bridge Wormhole executor cross-chain message report.",
                ),
            )
            out = Path(tmp) / "candidates.jsonl"
            rollback = Path(tmp) / "rollback.jsonl"
            summary = self.tool.run(
                tag_dir,
                out,
                min_confidence=0.65,
                apply=True,
                rollback_path=rollback,
            )
            self.assertEqual(summary["applied_writes"], 1)
            self.assertIn("attack_class: bridge-proof-domain-bypass", yaml_path.read_text(encoding="utf-8"))
            json_doc = json.loads(yaml_path.with_name("record.json").read_text(encoding="utf-8"))
            self.assertEqual(json_doc["attack_class"], "bridge-proof-domain-bypass")
            ext = json_doc["record_extensions"]["heuristic_attack_class_backfill"]
            self.assertEqual(ext["classification_scope"], "report-title-and-metadata-only")
            self.assertEqual(ext["old_attack_class"], "audit-firm-public-report")
            rollback_rows = [
                json.loads(line)
                for line in rollback.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual(rollback_rows[0]["old_attack_class"], "audit-firm-public-report")
            self.assertEqual(rollback_rows[0]["new_attack_class"], "bridge-proof-domain-bypass")

    def test_existing_specific_attack_class_is_ignored(self) -> None:
        """Already-classified records are skipped (idempotent)."""
        with tempfile.TemporaryDirectory(prefix="audit-firm-b2-specific-", dir=str(REPO_ROOT)) as tmp:
            tag_dir = Path(tmp) / "audit_firm_public_reports"
            tag_dir.mkdir()
            _write_record(
                tag_dir,
                "specific",
                _record(
                    record_id="audit-firm:already:specific:eeeeeeeeeeee",
                    source_path="reports/already-classified-bridge.pdf",
                    attacker_action="Bridge Wormhole executor cross-chain message report.",
                    attack_class="bridge-proof-domain-bypass",
                ),
            )
            out = Path(tmp) / "candidates.jsonl"
            summary = self.tool.run(tag_dir, out, min_confidence=0.65, apply=False)
            self.assertEqual(summary["opaque_records"], 0)
            self.assertEqual(summary["candidate_count"], 0)

    # ------------------------------------------------------------------
    # Idempotency: apply + re-apply = same result
    # ------------------------------------------------------------------

    def test_apply_twice_is_idempotent(self) -> None:
        """Applying the backfill twice writes 0 records on the second pass."""
        with tempfile.TemporaryDirectory(prefix="audit-firm-b2-idem-", dir=str(REPO_ROOT)) as tmp:
            tag_dir = Path(tmp) / "audit_firm_public_reports"
            tag_dir.mkdir()
            _write_record(
                tag_dir,
                "layerzero-report",
                _record(
                    record_id="audit-firm:zellic:layerzero:ffffffffffff",
                    source_path="LayerZero Core - Zellic Audit Report.pdf",
                    attacker_action="Report published in 2023 covering project 'LayerZero Core'.",
                ),
                record_path_override="zellic-publications__layerzero-core-zellic-audit-report-ffffffffffff",
            )
            out = Path(tmp) / "candidates.jsonl"
            rollback = Path(tmp) / "rollback.jsonl"
            s1 = self.tool.run(tag_dir, out, min_confidence=0.65, apply=True, rollback_path=rollback)
            self.assertEqual(s1["applied_writes"], 1)
            s2 = self.tool.run(tag_dir, out, min_confidence=0.65, apply=True, rollback_path=rollback)
            self.assertEqual(s2["applied_writes"], 0)
            self.assertEqual(s2["candidate_count"], 0)

    # ------------------------------------------------------------------
    # Slug-based classification: directory name carries the keyword
    # ------------------------------------------------------------------

    def test_slug_keyword_wormhole_classifies_bridge(self) -> None:
        """Single 'wormhole' in directory slug -> bridge-proof-domain-bypass."""
        with tempfile.TemporaryDirectory(prefix="audit-firm-b2-wh-", dir=str(REPO_ROOT)) as tmp:
            tag_dir = Path(tmp) / "audit_firm_public_reports"
            tag_dir.mkdir()
            # The attacker_action is boilerplate (like real records); the keyword
            # is only in the slug (directory name).
            _write_record(
                tag_dir,
                "wormhole-report",
                _record(
                    record_id="audit-firm:tob:wormhole:aabbccddee11",
                    source_path="reviews/2023-03-wormhole-securityreview.pdf",
                    attacker_action=(
                        "Audit-firm public report indexed for the Hackerman corpus. "
                        "Report published in 2023 covering project '03 wormhole'. "
                        "PDF/markdown content not parsed at this stage."
                    ),
                ),
                record_path_override="trailofbits-publications__2023-03-wormhole-securityreview-aabbccddee11",
            )
            out = Path(tmp) / "candidates.jsonl"
            summary = self.tool.run(tag_dir, out, min_confidence=0.65, apply=False)
            self.assertEqual(summary["candidate_count"], 1)
            rows = [json.loads(l) for l in out.read_text().splitlines()]
            self.assertEqual(rows[0]["new_attack_class"], "bridge-proof-domain-bypass")
            self.assertIn("wormhole", rows[0]["matched_terms"])

    def test_slug_keyword_layerzero_classifies_bridge(self) -> None:
        """Single 'layerzero' in slug -> bridge-proof-domain-bypass."""
        with tempfile.TemporaryDirectory(prefix="audit-firm-b2-lz-", dir=str(REPO_ROOT)) as tmp:
            tag_dir = Path(tmp) / "audit_firm_public_reports"
            tag_dir.mkdir()
            _write_record(
                tag_dir,
                "lz-report",
                _record(
                    record_id="audit-firm:zellic:lz:aabbccddeeff",
                    source_path="LayerZero Core - Zellic Audit Report.pdf",
                    attacker_action=(
                        "Audit-firm public report indexed for the Hackerman corpus. "
                        "Report published in 2022 covering project 'LayerZero Core'. "
                        "PDF/markdown content not parsed at this stage."
                    ),
                ),
                record_path_override="zellic-publications__layerzero-core-zellic-audit-report-aabbccddeeff",
            )
            out = Path(tmp) / "candidates.jsonl"
            summary = self.tool.run(tag_dir, out, min_confidence=0.65, apply=False)
            self.assertEqual(summary["candidate_count"], 1)
            rows = [json.loads(l) for l in out.read_text().splitlines()]
            self.assertEqual(rows[0]["new_attack_class"], "bridge-proof-domain-bypass")

    def test_slug_keyword_aave_classifies_liquidation(self) -> None:
        """'aave' in slug -> liquidation-mispricing."""
        with tempfile.TemporaryDirectory(prefix="audit-firm-b2-aave-", dir=str(REPO_ROOT)) as tmp:
            tag_dir = Path(tmp) / "audit_firm_public_reports"
            tag_dir.mkdir()
            _write_record(
                tag_dir,
                "aave-report",
                _record(
                    record_id="audit-firm:pashov:aave:112233445566",
                    source_path="team/pdf/Aave-security-review.pdf",
                    attacker_action=(
                        "Audit-firm public report indexed for the Hackerman corpus. "
                        "Report published in 2024 covering project 'Aave'. "
                        "PDF/markdown content not parsed at this stage."
                    ),
                ),
                record_path_override="pashov-audits__aave-security-review-112233445566",
            )
            out = Path(tmp) / "candidates.jsonl"
            summary = self.tool.run(tag_dir, out, min_confidence=0.65, apply=False)
            self.assertEqual(summary["candidate_count"], 1)
            rows = [json.loads(l) for l in out.read_text().splitlines()]
            self.assertEqual(rows[0]["new_attack_class"], "liquidation-mispricing")

    def test_slug_keyword_uniswap_classifies_amm(self) -> None:
        """'uniswap' in slug without 'wallet' -> amm-price-manipulation."""
        with tempfile.TemporaryDirectory(prefix="audit-firm-b2-uni-", dir=str(REPO_ROOT)) as tmp:
            tag_dir = Path(tmp) / "audit_firm_public_reports"
            tag_dir.mkdir()
            _write_record(
                tag_dir,
                "uniswap-report",
                _record(
                    record_id="audit-firm:cyfrin:uniswap:aabbccddeeff",
                    source_path="reports/2024-07-cyfrin-uniswap-v4-core.pdf",
                    attacker_action=(
                        "Audit-firm public report indexed for the Hackerman corpus. "
                        "Report published in 2024 covering project 'Uniswap V4 Core'. "
                        "PDF/markdown content not parsed at this stage."
                    ),
                ),
                record_path_override="cyfrin-audit-reports__2024-07-cyfrin-uniswap-v4-core-aabbccddeeff",
            )
            out = Path(tmp) / "candidates.jsonl"
            summary = self.tool.run(tag_dir, out, min_confidence=0.65, apply=False)
            self.assertEqual(summary["candidate_count"], 1)
            rows = [json.loads(l) for l in out.read_text().splitlines()]
            self.assertEqual(rows[0]["new_attack_class"], "amm-price-manipulation")

    def test_slug_keyword_staking_classifies_staking_reward(self) -> None:
        """'staking' in slug -> staking-reward-theft."""
        with tempfile.TemporaryDirectory(prefix="audit-firm-b2-stake-", dir=str(REPO_ROOT)) as tmp:
            tag_dir = Path(tmp) / "audit_firm_public_reports"
            tag_dir.mkdir()
            _write_record(
                tag_dir,
                "staking-report",
                _record(
                    record_id="audit-firm:pashov:staking:aabbccddeeff",
                    source_path="team/pdf/Bob-staking-security-review.pdf",
                    attacker_action=(
                        "Audit-firm public report indexed for the Hackerman corpus. "
                        "Report published in 2025 covering project 'Bob Staking'. "
                        "PDF/markdown content not parsed at this stage."
                    ),
                ),
                record_path_override="pashov-audits__bob-staking-security-review-aabbccddeeff",
            )
            out = Path(tmp) / "candidates.jsonl"
            summary = self.tool.run(tag_dir, out, min_confidence=0.65, apply=False)
            self.assertEqual(summary["candidate_count"], 1)
            rows = [json.loads(l) for l in out.read_text().splitlines()]
            self.assertEqual(rows[0]["new_attack_class"], "staking-reward-theft")

    def test_slug_keyword_governance_classifies_governance(self) -> None:
        """'governance' in slug -> governance-vote-manipulation."""
        with tempfile.TemporaryDirectory(prefix="audit-firm-b2-gov-", dir=str(REPO_ROOT)) as tmp:
            tag_dir = Path(tmp) / "audit_firm_public_reports"
            tag_dir.mkdir()
            _write_record(
                tag_dir,
                "governance-report",
                _record(
                    record_id="audit-firm:tob:compound-gov:aabbccddeeff",
                    source_path="reviews/compound-governance.pdf",
                    attacker_action=(
                        "Audit-firm public report indexed for the Hackerman corpus. "
                        "Report published in 2021 covering project 'Compound Governance'. "
                        "PDF/markdown content not parsed at this stage."
                    ),
                ),
                record_path_override="trailofbits-publications__compound-governance-aabbccddeeff",
            )
            out = Path(tmp) / "candidates.jsonl"
            summary = self.tool.run(tag_dir, out, min_confidence=0.65, apply=False)
            self.assertEqual(summary["candidate_count"], 1)
            rows = [json.loads(l) for l in out.read_text().splitlines()]
            self.assertEqual(rows[0]["new_attack_class"], "governance-vote-manipulation")

    def test_slug_dao_classifies_governance(self) -> None:
        """'dao' in slug -> governance-vote-manipulation."""
        with tempfile.TemporaryDirectory(prefix="audit-firm-b2-dao-", dir=str(REPO_ROOT)) as tmp:
            tag_dir = Path(tmp) / "audit_firm_public_reports"
            tag_dir.mkdir()
            _write_record(
                tag_dir,
                "dao-report",
                _record(
                    record_id="audit-firm:sherlock:nouns-dao:aabbccddeeff",
                    source_path="2022.12.27-final-nouns-dao-audit-report.pdf",
                    attacker_action=(
                        "Audit-firm public report indexed for the Hackerman corpus. "
                        "Report published in 2022 covering project 'Nouns DAO'. "
                        "PDF/markdown content not parsed at this stage."
                    ),
                ),
                record_path_override="sherlock-reports__2022-12-27-final-nouns-dao-audit-report-aabbccddeeff",
            )
            out = Path(tmp) / "candidates.jsonl"
            summary = self.tool.run(tag_dir, out, min_confidence=0.65, apply=False)
            self.assertEqual(summary["candidate_count"], 1)
            rows = [json.loads(l) for l in out.read_text().splitlines()]
            self.assertEqual(rows[0]["new_attack_class"], "governance-vote-manipulation")

    # ------------------------------------------------------------------
    # Veto phrases: FP suppression
    # ------------------------------------------------------------------

    def test_veto_wallet_suppresses_amm_for_uniswap_wallet(self) -> None:
        """'uniswap' + 'wallet' in slug -> suppressed, not classified as AMM."""
        with tempfile.TemporaryDirectory(prefix="audit-firm-b2-uni-wallet-", dir=str(REPO_ROOT)) as tmp:
            tag_dir = Path(tmp) / "audit_firm_public_reports"
            tag_dir.mkdir()
            _write_record(
                tag_dir,
                "wallet-report",
                _record(
                    record_id="audit-firm:tob:uniswap-wallet:aabbccddeeff",
                    source_path="reviews/2023-09-uniswap-wallet-securityreview.pdf",
                    attacker_action=(
                        "Audit-firm public report indexed for the Hackerman corpus. "
                        "Report published in 2023 covering project 'Uniswap Wallet'. "
                        "PDF/markdown content not parsed at this stage."
                    ),
                ),
                record_path_override="trailofbits-publications__2023-09-uniswap-wallet-securityreview-aabbccddeeff",
            )
            out = Path(tmp) / "candidates.jsonl"
            summary = self.tool.run(tag_dir, out, min_confidence=0.65, apply=False)
            self.assertEqual(summary["candidate_count"], 0,
                             "wallet-tagged report should not be classified as amm-price-manipulation")

    def test_veto_governance_suppresses_lending_for_compound_governance(self) -> None:
        """'compound' + 'governance' -> governance class wins, not liquidation."""
        with tempfile.TemporaryDirectory(prefix="audit-firm-b2-comp-gov-", dir=str(REPO_ROOT)) as tmp:
            tag_dir = Path(tmp) / "audit_firm_public_reports"
            tag_dir.mkdir()
            _write_record(
                tag_dir,
                "comp-gov-report",
                _record(
                    record_id="audit-firm:tob:compound-gov:aabbccddeeff",
                    source_path="reviews/compound-governance.pdf",
                    attacker_action=(
                        "Audit-firm public report indexed for the Hackerman corpus. "
                        "Report published in 2021 covering project 'Compound Governance'. "
                        "PDF/markdown content not parsed at this stage."
                    ),
                ),
                record_path_override="trailofbits-publications__compound-governance-aabbccddeeff",
            )
            out = Path(tmp) / "candidates.jsonl"
            summary = self.tool.run(tag_dir, out, min_confidence=0.65, apply=False)
            self.assertEqual(summary["candidate_count"], 1)
            rows = [json.loads(l) for l in out.read_text().splitlines()]
            self.assertNotEqual(rows[0]["new_attack_class"], "liquidation-mispricing",
                                "governance veto should prevent lending classification")
            self.assertEqual(rows[0]["new_attack_class"], "governance-vote-manipulation")

    def test_veto_oracle_suppresses_lending_for_oracle_report(self) -> None:
        """'euler' + 'oracle' in slug -> NOT liquidation (oracle report about a lending protocol)."""
        with tempfile.TemporaryDirectory(prefix="audit-firm-b2-euler-oracle-", dir=str(REPO_ROOT)) as tmp:
            tag_dir = Path(tmp) / "audit_firm_public_reports"
            tag_dir.mkdir()
            _write_record(
                tag_dir,
                "euler-oracle-report",
                _record(
                    record_id="audit-firm:spearbit:euler-oracle:aabbccddeeff",
                    source_path="Euler-Spearbit-Security-Review-Oracle.pdf",
                    attacker_action=(
                        "Audit-firm public report indexed for the Hackerman corpus. "
                        "Report published in 2024 covering project 'Euler Oracle'. "
                        "PDF/markdown content not parsed at this stage."
                    ),
                ),
                record_path_override="spearbit-portfolio__euler-spearbit-security-review-oracle-aabbccddeeff",
            )
            out = Path(tmp) / "candidates.jsonl"
            summary = self.tool.run(tag_dir, out, min_confidence=0.65, apply=False)
            # Should be 0 because oracle veto suppresses liquidation-mispricing,
            # and no other rule fires.
            self.assertEqual(summary["candidate_count"], 0,
                             "oracle veto should suppress liquidation classification for euler-oracle report")

    # ------------------------------------------------------------------
    # Honest unclassified path
    # ------------------------------------------------------------------

    def test_generic_report_stays_unclassified(self) -> None:
        """A report with no classifiable keywords stays opaque (honest unclassified)."""
        with tempfile.TemporaryDirectory(prefix="audit-firm-b2-gen-", dir=str(REPO_ROOT)) as tmp:
            tag_dir = Path(tmp) / "audit_firm_public_reports"
            tag_dir.mkdir()
            _write_record(
                tag_dir,
                "generic-report",
                _record(
                    record_id="audit-firm:sherlock:nuva:99aabbccddee",
                    source_path="Final Report - Nuva Labs.pdf",
                    attacker_action=(
                        "Audit-firm public report indexed for the Hackerman corpus. "
                        "PDF body not parsed at this stage."
                    ),
                ),
                record_path_override="sherlock-reports__2024-09-final-nuva-labs-audit-report-99aabbccddee",
            )
            out = Path(tmp) / "candidates.jsonl"
            summary = self.tool.run(tag_dir, out, min_confidence=0.65, apply=False)
            self.assertEqual(summary["candidate_count"], 0,
                             "generic project name should stay unclassified (honest unclassified path)")
            self.assertEqual(summary["opaque_records"], 1)

    # ------------------------------------------------------------------
    # Real-corpus sanity: run against the live tag dir
    # ------------------------------------------------------------------

    def test_real_corpus_backfill_is_idempotent_after_apply(self) -> None:
        """After --apply has run on the real corpus, a second dry-run finds 0 candidates."""
        real_tag_dir = REPO_ROOT / "audit" / "corpus_tags" / "tags" / "audit_firm_public_reports"
        if not real_tag_dir.is_dir():
            self.skipTest("real tag dir not present")
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as fh:
            out_path = Path(fh.name)
        try:
            summary = self.tool.run(real_tag_dir, out_path, min_confidence=0.65, apply=False)
            self.assertEqual(
                summary["candidate_count"],
                0,
                f"Expected 0 candidates after apply, got {summary['candidate_count']}. "
                "Run the backfill tool with --apply first.",
            )
        finally:
            out_path.unlink(missing_ok=True)

    def test_real_corpus_has_differentiated_records(self) -> None:
        """At least 100 records in the real corpus carry a non-opaque attack_class."""
        real_tag_dir = REPO_ROOT / "audit" / "corpus_tags" / "tags" / "audit_firm_public_reports"
        if not real_tag_dir.is_dir():
            self.skipTest("real tag dir not present")
        import yaml as _yaml
        differentiated = 0
        for p in real_tag_dir.rglob("record.yaml"):
            try:
                doc = _yaml.safe_load(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            if doc.get("attack_class") not in (None, "audit-firm-public-report"):
                differentiated += 1
        self.assertGreaterEqual(
            differentiated,
            100,
            f"Expected >=100 differentiated records; got {differentiated}. "
            "Backfill may not have been applied.",
        )


if __name__ == "__main__":
    unittest.main()
