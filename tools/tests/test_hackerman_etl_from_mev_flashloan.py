"""Tests for tools/hackerman-etl-from-mev-flashloan.py."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-mev-flashloan.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromMevFlashloanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL_PATH, "_hackerman_etl_from_mev_flashloan")
        self.validator = _load(VALIDATOR_PATH, "_hackerman_record_validate_for_mev_flashloan")

    def test_seed_corpus_meets_target_volume(self) -> None:
        records = self.tool.build_all_records()
        # Target band per EXEC-WAVE4-MEV brief: ~400 records.
        self.assertGreaterEqual(len(records), 300, f"got {len(records)} records; target >= 300")
        self.assertLessEqual(len(records), 500, f"got {len(records)} records; target <= 500")

    def test_attack_class_taxonomy_includes_all_required_classes(self) -> None:
        records = self.tool.build_all_records()
        attack_classes = {record["attack_class"] for record in records}
        required = {
            "sandwich-attack-minimal-slippage",
            "sandwich-attack-uncapped-slippage",
            "jit-liquidity-front-run",
            "liquidation-mev-priority-gas-front-run",
            "flashloan-price-oracle-manipulation",
            "flashloan-governance-vote-flash",
            "flashloan-mint-collateral-arb",
            "flashloan-arb-cycle-bypass",
            "cross-domain-mev-bridge-frontrun",
            "mempool-replacement-fee-bypass",
            "tx-ordering-leak-on-private-mempool",
        }
        missing = required - attack_classes
        self.assertFalse(missing, f"missing required attack classes: {missing}")

    def test_records_validate_against_v1_schema(self) -> None:
        records = self.tool.build_all_records()
        errors = self.tool.validate_records(records)
        self.assertEqual(errors, [], f"schema validation errors: {errors[:5]}")

    def test_target_domain_covers_dex_lending_and_mev_proxy_domains(self) -> None:
        records = self.tool.build_all_records()
        domains = {record["target_domain"] for record in records}
        # Task spec said target_domain: dex / lending / mev. The schema
        # has no "mev" enum value, so MEV-only incidents route to
        # rpc-infra / consensus / bridge / governance. Assert the
        # canonical trio plus the proxy domains are all represented.
        self.assertIn("dex", domains)
        self.assertIn("lending", domains)
        self.assertTrue(
            {"rpc-infra", "consensus", "bridge", "governance"} & domains,
            f"expected at least one MEV-proxy domain, got {domains}",
        )

    def test_severity_walks_back_for_post_fix_states(self) -> None:
        records = self.tool.build_all_records()
        by_state = {"pre-fix": [], "post-fix-not-migrated": [], "post-fix-migrated-historical": []}
        for record in records:
            for state in by_state:
                if state in record["source_audit_ref"]:
                    by_state[state].append(record["severity_at_finding"])
                    break
        # Pre-fix should include critical entries (Cream, Beanstalk, Euler).
        self.assertIn("critical", by_state["pre-fix"])
        # Post-fix-not-migrated should never be critical (walks one tier).
        self.assertNotIn("critical", by_state["post-fix-not-migrated"])
        # Post-fix-migrated-historical should be info-only.
        self.assertTrue(
            all(sev == "info" for sev in by_state["post-fix-migrated-historical"]),
            f"non-info severity leaked into historical state: "
            f"{sorted(set(by_state['post-fix-migrated-historical']) - {'info'})}",
        )

    def test_related_records_cross_link_within_same_incident(self) -> None:
        records = self.tool.build_all_records()
        by_id = {record["record_id"]: record for record in records}
        target = None
        for record in records:
            if "mev-flashloan:cream-flashloan-2021:" in record["source_audit_ref"] and "pre-fix" in record["source_audit_ref"]:
                target = record
                break
        self.assertIsNotNone(target)
        self.assertGreater(len(target["related_records"]), 0)
        for related in target["related_records"]:
            self.assertIn(related, by_id, f"related record {related!r} not in emitted set")
            self.assertTrue(
                related.startswith("mev-flashloan:cream-flashloan-2021:"),
                f"related record {related!r} crosses incident boundary",
            )

    def test_canonical_incidents_present(self) -> None:
        records = self.tool.build_all_records()
        incident_slugs = {record["source_audit_ref"].split(":")[1] for record in records}
        # A representative subset of canonical incidents the brief called out.
        canonical_subset = {
            "cream-flashloan-2021",
            "beanstalk-governance-2022",
            "euler-donation-2023",
            "mango-oracle-2022",
            "cashio-infinite-mint-2022",
            "wormhole-sig-2022",
            "harvest-curve-sandwich-2020",
            "bzx-oracle-2020",
            "pancakebunny-mint-2021",
        }
        missing = canonical_subset - incident_slugs
        self.assertFalse(missing, f"missing canonical incidents: {missing}")

    def test_dollar_class_scaled_by_component_loss(self) -> None:
        records = self.tool.build_all_records()
        # Euler eWETH market lost ~$89M; pre-fix record must be >=$1M tier.
        for record in records:
            ref = record["source_audit_ref"]
            if "euler-donation-2023" in ref and "euler-eweth-market" in ref and "pre-fix" in ref:
                self.assertEqual(record["impact_dollar_class"], ">=$1M")
                return
        self.fail("expected Euler eWETH market pre-fix record not found")

    def test_cli_writes_schema_valid_yaml_and_deterministic_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = self.tool.main(
                    [
                        "--out-dir",
                        str(out_dir),
                        "--json-summary",
                    ]
                )
            self.assertEqual(rc, 0)
            files = sorted(out_dir.glob("*.yaml"))
            self.assertGreaterEqual(len(files), 300)
            # Filenames should be sorted-stable across runs.
            self.assertEqual([path.name for path in files], sorted(path.name for path in files))
            schema = self.validator.load_schema()
            for path in files[:10]:
                status, errors = self.validator.validate_file(path, schema)
                self.assertEqual(status, "valid", (path, errors))

    def test_cli_dry_run_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out_dry"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = self.tool.main(
                    [
                        "--out-dir",
                        str(out_dir),
                        "--dry-run",
                        "--json-summary",
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertFalse(out_dir.exists(), "dry-run must not create out_dir")

    def test_cli_limit_caps_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out_limit"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = self.tool.main(
                    [
                        "--out-dir",
                        str(out_dir),
                        "--limit",
                        "7",
                        "--json-summary",
                    ]
                )
            self.assertEqual(rc, 0)
            summary = json.loads(buf.getvalue())
            self.assertEqual(summary["records_emitted"], 7)
            self.assertEqual(summary["file_count"], 7)

    def test_extra_json_extends_seed(self) -> None:
        extra_entry = [{
            "incident_id": "TEST-EXTRA-2026",
            "year": 2026,
            "title": "Synthetic extra MEV entry for test harness",
            "description": "Synthetic extra entry used to verify --extra-json wiring works end-to-end.",
            "attacker_action_sequence": "Synthetic MEV action sequence used in test harness.",
            "fix_pattern": "Apply the synthetic MEV-resistance fix pattern.",
            "fix_anti_pattern": "Avoid the synthetic anti-pattern.",
            "attack_class": "sandwich-attack-uncapped-slippage",
            "bug_class": "tx-ordering-leak",
            "severity": "low",
            "impact_class": "griefing",
            "impact_actor": "arbitrary-user",
            "impact_dollar_class": "<$10K",
            "target_domain": "dex",
            "components": [{"pool": "Synthetic synthetic synthetic", "address": "n/a", "loss_usd": 0}],
            "preconditions": ["synthetic precondition"],
        }]
        with tempfile.TemporaryDirectory() as tmp:
            extra_path = Path(tmp) / "extra.json"
            extra_path.write_text(json.dumps(extra_entry), encoding="utf-8")
            out_dir = Path(tmp) / "out_extra"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = self.tool.main(
                    [
                        "--out-dir",
                        str(out_dir),
                        "--extra-json",
                        str(extra_path),
                        "--dry-run",
                        "--json-summary",
                    ]
                )
            self.assertEqual(rc, 0)
            summary = json.loads(buf.getvalue())
            self.assertEqual(summary["extra_entries"], 1)
            # 1 extra entry x 1 component x 3 mitigation states = 3 extra records.
            baseline = self.tool.build_all_records()
            self.assertEqual(summary["records_emitted"], len(baseline) + 3)

    def test_record_id_unique_and_pattern_safe(self) -> None:
        records = self.tool.build_all_records()
        ids = [record["record_id"] for record in records]
        self.assertEqual(len(ids), len(set(ids)), "record_ids must be unique")
        for rid in ids:
            self.assertRegex(rid, r"^[A-Za-z0-9._:/-]{8,160}$")

    def test_cross_language_analogues_present_for_sandwich_class(self) -> None:
        records = self.tool.build_all_records()
        sandwich = [r for r in records if "sandwich-attack" in r["attack_class"]]
        self.assertTrue(sandwich, "expected at least one sandwich-class record")
        for record in sandwich:
            langs = {item["target_language"] for item in record["cross_language_analogues"]}
            # Sandwich pattern translates to Solana / Cosmos contexts.
            self.assertIn("rust", langs, record["record_id"])
            self.assertIn("go", langs, record["record_id"])

    def test_cross_language_analogues_present_for_flashloan_oracle_class(self) -> None:
        records = self.tool.build_all_records()
        oracle = [r for r in records if "flashloan-price-oracle-manipulation" in r["attack_class"]]
        self.assertTrue(oracle)
        for record in oracle:
            langs = {item["target_language"] for item in record["cross_language_analogues"]}
            self.assertIn("rust", langs, record["record_id"])

    def test_address_appended_to_attacker_action_when_present(self) -> None:
        records = self.tool.build_all_records()
        # Cream's yUSDVault has a concrete address; the attacker_action_sequence
        # should cite it.
        for record in records:
            if (
                "cream-flashloan-2021" in record["source_audit_ref"]
                and "yusdvault" in record["source_audit_ref"]
                and "pre-fix" in record["source_audit_ref"]
            ):
                self.assertIn("0x4eE15f44c6F0d8d1136c83EfD2e8E4AC768954c6", record["attacker_action_sequence"])
                return
        self.fail("expected Cream yUSDVault pre-fix record not found")

    def test_target_language_rust_for_solana_incidents(self) -> None:
        records = self.tool.build_all_records()
        for record in records:
            ref = record["source_audit_ref"]
            if "cashio-infinite-mint-2022" in ref or "wormhole-sig-2022" in ref or "mango-oracle-2022" in ref:
                self.assertEqual(record["target_language"], "rust", record["record_id"])


if __name__ == "__main__":
    unittest.main()
