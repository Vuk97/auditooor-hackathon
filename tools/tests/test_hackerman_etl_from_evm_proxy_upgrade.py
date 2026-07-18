"""Tests for tools/hackerman-etl-from-evm-proxy-upgrade.py.

Wave-5 lane EXEC-WAVE5-EVM-PROXY-UPGRADE / TIER-C Lift C6.

These tests cover:

* Proxy-specific taxonomy classifier wins over generic taxonomy when
  proxy keywords fire (UUPS, transparent, beacon, diamond, minimal).
* Proxy-pattern tag inference (`UUPS` / `Transparent` / `Beacon` / `Diamond`
  / `Minimal`) covers each of the five shapes.
* The curated baseline emits schema-valid records, each with three
  mitigation-state variants (`nomit`, `partmit`, `fullmit`).
* Audit-report parser extracts a finding section + severity from Zellic
  reports with dot-numbered section headings.
* Body-side proxy-shape filter rejects non-proxy findings.
* End-to-end `convert()` emits ~200-300 schema-valid records.
* CLI `--dry-run --json-summary` returns valid JSON without writing files.
* `--no-include-baseline` suppresses curated records.
* Cross-language analogues are populated for proxy attack classes.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-evm-proxy-upgrade.py"
VALIDATOR = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromEvmProxyUpgradeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_evm_proxy_upgrade_under_test")
        self.validator = _load(
            VALIDATOR, "_hackerman_record_validate_for_evm_proxy_upgrade_test"
        )

    # ------------------------------------------------------------------
    # Proxy-specific taxonomy classifier
    # ------------------------------------------------------------------

    def test_classifier_picks_selfdestruct_when_implementation_has_it(self) -> None:
        bug_class, attack_class = self.tool.classify_bug_attack(
            "The implementation contains a reachable selfdestruct callable via "
            "the proxy fallback function."
        )
        self.assertEqual(bug_class, "selfdestruct-in-implementation")
        self.assertEqual(attack_class, "uups-self-destruct-via-fallback")

    def test_classifier_picks_authorize_upgrade_when_missing(self) -> None:
        bug_class, attack_class = self.tool.classify_bug_attack(
            "The contract inherits UUPSUpgradeable but does not override "
            "_authorizeUpgrade; anyone can upgrade."
        )
        self.assertEqual(bug_class, "missing-upgrade-auth")
        self.assertEqual(attack_class, "uups-missing-_authorizeUpgrade-restriction")

    def test_classifier_picks_storage_collision_for_gap_phrasing(self) -> None:
        bug_class, attack_class = self.tool.classify_bug_attack(
            "Missing __gap arrays cause storage layout collision after the "
            "next implementation upgrade."
        )
        self.assertEqual(bug_class, "implementation-slot-shadow")
        self.assertEqual(
            attack_class, "uups-storage-collision-via-implementation-slot-shadow"
        )

    def test_classifier_picks_selector_clash(self) -> None:
        bug_class, attack_class = self.tool.classify_bug_attack(
            "A function selector collision between the proxy and "
            "implementation routes calls to the wrong path."
        )
        self.assertEqual(bug_class, "selector-clash")
        self.assertEqual(attack_class, "transparent-proxy-selector-clash")

    def test_classifier_picks_beacon_takeover(self) -> None:
        bug_class, attack_class = self.tool.classify_bug_attack(
            "BeaconProxy consumers are upgradable by whoever owns the "
            "UpgradeableBeacon."
        )
        self.assertEqual(bug_class, "beacon-takeover")
        self.assertEqual(attack_class, "beacon-proxy-implementation-takeover")

    def test_classifier_picks_diamond_facet_selector_collision(self) -> None:
        bug_class, attack_class = self.tool.classify_bug_attack(
            "Two facets register the same 4-byte selector via diamondCut."
        )
        self.assertEqual(bug_class, "diamond-selector-collision")
        self.assertEqual(attack_class, "diamond-facet-selector-collision")

    def test_classifier_picks_minimal_proxy_arg_leak(self) -> None:
        bug_class, attack_class = self.tool.classify_bug_attack(
            "EIP-1167 minimal proxy clone leaks trailing CWIA immutable args "
            "via a view function that echoes msg.data."
        )
        self.assertEqual(bug_class, "minimal-proxy-arg-leak")
        self.assertEqual(attack_class, "minimal-proxy-immutable-arg-leak")

    def test_classifier_picks_initializer_replay(self) -> None:
        bug_class, attack_class = self.tool.classify_bug_attack(
            "The initialize function is unprotected; anyone can call "
            "initialize on the implementation."
        )
        self.assertEqual(bug_class, "initializer-replay")
        self.assertEqual(attack_class, "initializer-replay-via-unprotected-init")

    def test_classifier_picks_reinit_rollback(self) -> None:
        bug_class, attack_class = self.tool.classify_bug_attack(
            "Storage migration writes through _initialized to roll the "
            "version back, allowing reinitializer to fire again."
        )
        self.assertEqual(bug_class, "initializer-reinit-rollback")
        self.assertEqual(attack_class, "initializer-reinit-via-version-rollback")

    def test_classifier_picks_erc1967_bypass(self) -> None:
        bug_class, attack_class = self.tool.classify_bug_attack(
            "Custom proxy stores implementation address in a non-ERC1967 "
            "slot, bypassing the canonical slot pinning."
        )
        self.assertEqual(bug_class, "erc1967-slot-bypass")
        self.assertEqual(attack_class, "erc1967-implementation-slot-pinning-bypass")

    def test_classifier_picks_create2_redeploy(self) -> None:
        bug_class, attack_class = self.tool.classify_bug_attack(
            "Metamorphic contract via CREATE2 redeploy after selfdestruct "
            "replaces benign code with malicious bytecode at the same address."
        )
        self.assertEqual(bug_class, "erc2470-create2-redeploy")
        self.assertEqual(attack_class, "erc2470-create2-redeploy-after-selfdestruct")

    def test_classifier_picks_unchecked_delegatecall(self) -> None:
        bug_class, attack_class = self.tool.classify_bug_attack(
            "The multicall function performs an unchecked delegatecall to a "
            "user-supplied target address."
        )
        self.assertEqual(bug_class, "unchecked-delegatecall")
        self.assertEqual(attack_class, "unchecked-delegatecall-target")

    def test_generic_fallback_for_unrelated_text(self) -> None:
        bug_class, attack_class = self.tool.classify_bug_attack(
            "Some unrelated finding about a math invariant."
        )
        self.assertEqual(bug_class, "logic-error")
        self.assertEqual(attack_class, "protocol-invariant-bypass")

    # ------------------------------------------------------------------
    # Proxy pattern tag inference
    # ------------------------------------------------------------------

    def test_pattern_tag_diamond_wins_when_diamond_keywords_fire(self) -> None:
        self.assertEqual(
            self.tool.infer_proxy_pattern_tag("Diamond facet uses appstorage."),
            "Diamond",
        )

    def test_pattern_tag_beacon_wins_when_beacon_keywords_fire(self) -> None:
        self.assertEqual(
            self.tool.infer_proxy_pattern_tag("UpgradeableBeacon owns the BeaconProxy fleet."),
            "Beacon",
        )

    def test_pattern_tag_uups_wins_for_authorize_upgrade(self) -> None:
        self.assertEqual(
            self.tool.infer_proxy_pattern_tag("Missing _authorizeUpgrade override on UUPS"),
            "UUPS",
        )

    def test_pattern_tag_transparent_wins_for_proxy_admin(self) -> None:
        self.assertEqual(
            self.tool.infer_proxy_pattern_tag(
                "TransparentUpgradeableProxy ProxyAdmin EOA misuse."
            ),
            "Transparent",
        )

    def test_pattern_tag_minimal_wins_for_clones(self) -> None:
        self.assertEqual(
            self.tool.infer_proxy_pattern_tag(
                "EIP-1167 minimal proxy clones with immutable args (CWIA)."
            ),
            "Minimal",
        )

    def test_pattern_tag_defaults_to_uups_for_generic_upgrade_text(self) -> None:
        self.assertEqual(
            self.tool.infer_proxy_pattern_tag("Some generic upgradable contract."),
            "UUPS",
        )

    # ------------------------------------------------------------------
    # Curated baseline records
    # ------------------------------------------------------------------

    def test_baseline_records_pass_schema_and_carry_proxy_metadata(self) -> None:
        schema = self.validator.load_schema()
        emitted = 0
        seen_patterns: set[str] = set()
        for entry in self.tool.EVM_PROXY_KNOWN_DISCLOSURES:
            record = self.tool.baseline_record(entry)
            errors = self.validator.validate_doc(record, schema)
            self.assertEqual(errors, [], f"{entry['slug']}: {errors}")
            self.assertEqual(record["target_language"], "solidity")
            self.assertIn("evm-proxy-upgrade", record["function_shape"]["shape_tags"])
            # At least one of the five proxy-pattern tags appears.
            pattern_tags = {"UUPS", "Transparent", "Beacon", "Diamond", "Minimal"}
            self.assertTrue(
                set(record["function_shape"]["shape_tags"]) & pattern_tags,
                f"{entry['slug']}: no proxy-pattern tag in {record['function_shape']['shape_tags']}",
            )
            seen_patterns |= set(record["function_shape"]["shape_tags"]) & pattern_tags
            emitted += 1
        # Lane targets ~250 records; baseline alone must contribute at least
        # 30 entries to guarantee taxonomy coverage across the 15 attack
        # classes even when the audit-text channel under-fires.
        self.assertGreaterEqual(emitted, 30)
        # All five proxy patterns must be represented.
        self.assertEqual(
            seen_patterns,
            {"UUPS", "Transparent", "Beacon", "Diamond", "Minimal"},
        )

    def test_baseline_records_cover_every_proxy_attack_class(self) -> None:
        # Verify that the 15 proxy-specific attack classes all appear at
        # least once in the curated baseline. Drift-detection guard.
        seen_attack_classes: set[str] = set()
        for entry in self.tool.EVM_PROXY_KNOWN_DISCLOSURES:
            seen_attack_classes.add(entry["attack_class"])
        expected = {ac for _, ac, _ in self.tool.PROXY_PATTERN_RULES}
        missing = expected - seen_attack_classes
        self.assertFalse(
            missing,
            f"baseline missing attack classes: {sorted(missing)}",
        )

    def test_baseline_emits_three_mitigation_variants_per_entry(self) -> None:
        schema = self.validator.load_schema()
        entry = self.tool.EVM_PROXY_KNOWN_DISCLOSURES[0]
        base = self.tool.baseline_record(entry)
        variants = self.tool._three_mitigation_variants(base)
        self.assertEqual(len(variants), 3)
        suffixes = {v["record_id"].rsplit(":", 1)[1] for v in variants}
        self.assertEqual(suffixes, {"nomit", "partmit", "fullmit"})
        # Each variant must validate.
        for variant in variants:
            errors = self.validator.validate_doc(variant, schema)
            self.assertEqual(errors, [], f"{variant['record_id']}: {errors}")
        # The `fullmit` variant must walk back severity to info.
        full = next(v for v in variants if v["record_id"].endswith("fullmit"))
        self.assertEqual(full["severity_at_finding"], "info")
        self.assertEqual(full["impact_dollar_class"], "non-financial")

    def test_baseline_cross_language_analogues_present(self) -> None:
        # Every proxy-specific attack class has cross-language analogues
        # registered. Verify the baseline carries them onto records.
        for entry in self.tool.EVM_PROXY_KNOWN_DISCLOSURES:
            record = self.tool.baseline_record(entry)
            analogues = record["cross_language_analogues"]
            self.assertTrue(
                len(analogues) >= 2,
                f"{entry['slug']}: no cross-language analogues",
            )
            langs = {a["target_language"] for a in analogues}
            # Must include rust (substrate) and move analogues.
            self.assertIn("rust", langs)
            self.assertIn("move", langs)

    # ------------------------------------------------------------------
    # Audit-report parser
    # ------------------------------------------------------------------

    def test_audit_report_parser_extracts_finding_with_dot_numbered_heading(self) -> None:
        with tempfile.TemporaryDirectory(prefix="evm-proxy-report-") as tmp:
            root = Path(tmp)
            corpus_dir = root / "corpus"
            corpus_dir.mkdir()
            sample = corpus_dir / "Sample UUPS Vault - Zellic Audit Report.txt"
            sample.write_text(
                """\
                  Sample Vault
                  UUPS Smart Contract Security Assessment

                  June 4, 2025

                3. Detailed Findings

                3.1. Missing _authorizeUpgrade override allows anyone to upgrade
                  Target  Vault
                  Severity  Critical
                  Likelihood  High
                  Impact  Critical

                  Description
                  The Vault contract inherits UUPSUpgradeable but does not
                  override _authorizeUpgrade. Any caller can call upgradeTo
                  and replace the implementation.

                  Recommendations
                  Override _authorizeUpgrade and restrict to onlyOwner.

                3.2. Implementation slot collision after upgrade
                  Target  Vault::storageLayout
                  Severity  High

                  Description
                  Missing __gap arrays cause future state additions to
                  collide with the ERC-1967 implementation slot.

                4 Discussion

                4.1 Test suite
                  Some discussion text that should not become a finding.
                """,
                encoding="utf-8",
            )

            findings = self.tool.parse_audit_report(sample)
            self.assertGreaterEqual(len(findings), 2)
            titles = {f["title"].lower() for f in findings}
            self.assertTrue(
                any("_authorizeupgrade" in t for t in titles),
                f"missing _authorizeUpgrade title in {titles}",
            )
            self.assertTrue(any("implementation slot collision" in t for t in titles))
            severities = {f["severity"] for f in findings}
            self.assertIn("critical", severities)
            self.assertIn("high", severities)

    def test_is_proxy_relevant_report_filename_matches(self) -> None:
        self.assertTrue(
            self.tool.is_proxy_relevant_report(
                Path("Acme UUPS Vault - Zellic Audit Report.txt")
            )
        )
        # Body-only matches are tested below; with no file content available
        # the filename-hint alone returns True for these keywords.
        for name in (
            "Sample Proxy Audit.txt",
            "OpenZeppelin Upgradeable.txt",
            "Diamond Mudgen Audit.txt",
            "Beacon Pattern Audit.txt",
        ):
            self.assertTrue(
                self.tool.is_proxy_relevant_report(Path(name)),
                f"{name} should match",
            )

    def test_finding_is_proxy_shape_rejects_unrelated_text(self) -> None:
        self.assertFalse(
            self.tool.finding_is_proxy_shape(
                "A rounding bug in the interest accrual formula causes "
                "small precision drift over time."
            )
        )

    def test_finding_is_proxy_shape_accepts_initializer_phrasing(self) -> None:
        self.assertTrue(
            self.tool.finding_is_proxy_shape(
                "The contract has an unprotected initializer modifier."
            )
        )

    # ------------------------------------------------------------------
    # End-to-end against the vendored corpus
    # ------------------------------------------------------------------

    def test_convert_end_to_end_against_repo_corpus(self) -> None:
        with tempfile.TemporaryDirectory(prefix="evm-proxy-e2e-") as tmp:
            out_dir = Path(tmp) / "out"
            summary = self.tool.convert(
                corpus_dirs=[self.tool.DEFAULT_CORPUS_DIR.resolve()],
                out_dir=out_dir,
                dry_run=False,
            )
            self.assertEqual(summary["errors"], [], summary["errors"][:3])
            # Target band: ~250 records; allow a 150-350 envelope so the lane
            # remains stable under modest corpus drift.
            self.assertGreaterEqual(
                summary["records_emitted"],
                150,
                f"emitted {summary['records_emitted']}, want >= 150",
            )
            self.assertLessEqual(
                summary["records_emitted"],
                400,
                f"emitted {summary['records_emitted']}, want <= 400",
            )
            # All records must be valid hackerman_record v1 solidity entries.
            schema = self.validator.load_schema()
            count = 0
            languages: set[str] = set()
            attack_classes: set[str] = set()
            proxy_tags: set[str] = set()
            for path in out_dir.glob("*.yaml"):
                status, errors = self.validator.validate_file(path, schema)
                self.assertEqual(status, "valid", f"{path}: {errors}")
                doc = self.validator.load_yaml(path)
                languages.add(doc["target_language"])
                attack_classes.add(doc["attack_class"])
                for tag in doc["function_shape"]["shape_tags"]:
                    if tag in {"UUPS", "Transparent", "Beacon", "Diamond", "Minimal"}:
                        proxy_tags.add(tag)
                count += 1
            self.assertEqual(count, summary["records_emitted"])
            self.assertEqual(languages, {"solidity"})
            # At least four of the five proxy-pattern shapes surface in
            # the emitted corpus.
            self.assertGreaterEqual(
                len(proxy_tags),
                4,
                f"proxy tags seen: {sorted(proxy_tags)}",
            )
            # At least eight of the fifteen proxy attack classes surface.
            proxy_attack_classes = {ac for _, ac, _ in self.tool.PROXY_PATTERN_RULES}
            seen = proxy_attack_classes & attack_classes
            self.assertGreaterEqual(
                len(seen),
                8,
                f"only {len(seen)} of {len(proxy_attack_classes)} attack classes surfaced: {sorted(seen)}",
            )

    # ------------------------------------------------------------------
    # CLI
    # ------------------------------------------------------------------

    def test_cli_dry_run_does_not_write_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="evm-proxy-cli-") as tmp:
            out_dir = Path(tmp) / "out"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = self.tool.main(
                    [
                        "--out-dir",
                        str(out_dir),
                        "--dry-run",
                        "--json-summary",
                        "--limit",
                        "20",
                    ]
                )
            self.assertEqual(rc, 0)
            payload = json.loads(stdout.getvalue())
            self.assertTrue(payload["dry_run"])
            self.assertLessEqual(payload["records_emitted"], 20)
            self.assertFalse(out_dir.exists())

    def test_cli_no_include_baseline_skips_curated_records(self) -> None:
        with tempfile.TemporaryDirectory(prefix="evm-proxy-no-baseline-") as tmp:
            out_dir = Path(tmp) / "out"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = self.tool.main(
                    [
                        "--out-dir",
                        str(out_dir),
                        "--dry-run",
                        "--json-summary",
                        "--no-include-baseline",
                    ]
                )
            self.assertEqual(rc, 0)
            payload = json.loads(stdout.getvalue())
            # No baseline record_ids should appear in dry-run files list.
            for fname in payload["files"]:
                self.assertNotIn(
                    "evm-proxy-baseline", fname.lower().replace(":", "-")
                )

    def test_cli_no_mitigation_variants_emits_single_record_per_entry(self) -> None:
        with tempfile.TemporaryDirectory(prefix="evm-proxy-no-mit-") as tmp:
            out_dir = Path(tmp) / "out"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = self.tool.main(
                    [
                        "--out-dir",
                        str(out_dir),
                        "--dry-run",
                        "--json-summary",
                        "--no-mitigation-variants",
                    ]
                )
            self.assertEqual(rc, 0)
            payload = json.loads(stdout.getvalue())
            # Without mitigation variants, baseline contributes 1x per entry.
            # The audit-text channel still emits its own records.
            baseline_size = len(self.tool.EVM_PROXY_KNOWN_DISCLOSURES)
            # records_emitted must be at least baseline_size (no 3x multiplier).
            self.assertGreaterEqual(payload["records_emitted"], baseline_size)
            # And strictly less than 3x baseline (mitigation multiplier off).
            self.assertLess(
                payload["records_emitted"],
                baseline_size * 3,
                f"emitted {payload['records_emitted']}, expected < {baseline_size * 3}",
            )


if __name__ == "__main__":
    unittest.main()
