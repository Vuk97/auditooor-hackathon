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
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-pattern-docs.py"
VALIDATOR = REPO_ROOT / "tools" / "hackerman-record-validate.py"
PATTERNS_DIR = REPO_ROOT / "patterns"

# The 12 pattern doc filenames this ETL is bound to. Tests assert that every
# attack-class slug emitted by the tool corresponds to an on-disk markdown
# pattern file under patterns/, so the docs and the ETL cannot drift.
EXPECTED_PATTERN_FILES = {
    "erc4626-share-rounding-favoring-attacker",
    "cross-chain-message-replay-no-nonce",
    "initializer-replay-via-unprotected-init",
    "oracle-twap-window-too-short",
    "liquidation-bonus-applied-before-debt-clear",
    "governance-proposal-vote-with-flash-loan",
    "staking-reward-claim-replay",
    "permit-signature-no-domain-separator",
    "fee-on-transfer-double-accounting",
    "diamond-facet-selector-collision",
    "uups-self-destruct-via-fallback",
    "cosmos-msgexec-nested-msg-bypass",
}


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules.setdefault(spec.name, mod)
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromPatternDocsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_pattern_docs")
        self.validator = _load(VALIDATOR, "_hackerman_record_validate_for_pattern_docs")

    # 1. Schema validation: every emitted record must validate, zero errors.
    def test_dry_run_emits_records_with_zero_errors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pattern-docs-dry-") as tmp:
            summary = self.tool.convert(Path(tmp) / "out", dry_run=True)
        self.assertEqual(summary["errors"], [])
        self.assertGreater(summary["records_emitted"], 0)

    # 2. Target record count: 12 patterns x ~6 rows = ~72; allow a band.
    def test_target_record_count_is_in_band(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pattern-docs-count-") as tmp:
            summary = self.tool.convert(Path(tmp) / "out", dry_run=True)
        self.assertGreaterEqual(summary["records_emitted"], 60)
        self.assertLessEqual(summary["records_emitted"], 250)

    # 3. Every required attack class is present (12 of them).
    def test_taxonomy_covers_all_12_pattern_families(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pattern-docs-tax-") as tmp:
            summary = self.tool.convert(Path(tmp) / "out", dry_run=True)
        for cls in EXPECTED_PATTERN_FILES:
            self.assertIn(cls, summary["by_attack_class"], f"missing attack class {cls}")

    # 4. On-disk pattern doc exists for every attack class the ETL emits.
    def test_every_attack_class_has_an_on_disk_pattern_doc(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pattern-docs-disk-") as tmp:
            summary = self.tool.convert(Path(tmp) / "out", dry_run=True)
        for cls in summary["by_attack_class"]:
            doc = PATTERNS_DIR / f"{cls}.md"
            self.assertTrue(doc.exists(), f"missing pattern doc on disk: {doc}")
            # Doc must contain the attack_class slug somewhere in the body.
            body = doc.read_text(encoding="utf-8")
            self.assertIn(cls, body, f"{doc.name} does not reference its slug")

    # 5. Every emitted record validates against v1 schema on real write.
    def test_all_emitted_records_validate_against_v1_schema(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pattern-docs-write-") as tmp:
            out_dir = Path(tmp) / "out"
            summary = self.tool.convert(out_dir)
            self.assertEqual(summary["errors"], [])
            self.assertGreater(summary["file_count"], 0)
            schema = self.validator.load_schema()
            seen = 0
            for path in out_dir.glob("*.yaml"):
                seen += 1
                status, errors = self.validator.validate_file(path, schema)
                self.assertEqual(status, "valid", f"{path}: {errors}")
            self.assertEqual(seen, summary["file_count"])

    # 6. Family-seed and incident rows share a related-records anchor.
    def test_incident_rows_reference_family_seed(self) -> None:
        records = self.tool.build_records()
        seeds_by_pattern = {}
        for r in records:
            rid = r["record_id"]
            if ":family-seed:" in rid:
                attack_class = r["attack_class"]
                seeds_by_pattern[attack_class] = rid
        for r in records:
            rid = r["record_id"]
            if ":incident-" in rid or ":cross-lang-" in rid:
                seed_id = seeds_by_pattern[r["attack_class"]]
                self.assertIn(seed_id, r["related_records"],
                              f"{rid} does not link back to family-seed {seed_id}")

    # 7. Cross-language analogues table is non-empty on every family seed
    #    and the analogue language matches the schema enum.
    def test_family_seeds_have_non_empty_cross_language_analogues(self) -> None:
        records = self.tool.build_records()
        valid_langs = {
            "solidity", "go", "rust", "vyper", "move", "cairo", "huff",
            "assembly", "typescript-onchain", "python-onchain",
        }
        seeds = [r for r in records if ":family-seed:" in r["record_id"]]
        self.assertEqual(len(seeds), 12)
        for r in seeds:
            self.assertGreater(len(r["cross_language_analogues"]), 0)
            for cl in r["cross_language_analogues"]:
                self.assertIn(cl["target_language"], valid_langs)
                self.assertGreater(len(cl["pattern_translation"]), 10)

    # 8. record_id collisions are forbidden.
    def test_record_ids_are_unique(self) -> None:
        records = self.tool.build_records()
        ids = [r["record_id"] for r in records]
        self.assertEqual(len(ids), len(set(ids)), "record_id collisions detected")

    # 9. Additive-only dedup: re-running into a non-empty out-dir doesn't
    #    overwrite existing files.
    def test_additive_dedup_does_not_overwrite_existing_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pattern-docs-dedup-") as tmp:
            out_dir = Path(tmp) / "out"
            self.tool.convert(out_dir, limit=3)
            paths = sorted(out_dir.glob("*.yaml"))
            self.assertGreater(len(paths), 0)
            for p in paths:
                p.write_text(p.read_text(encoding="utf-8") + "# sentinel\n", encoding="utf-8")
            self.tool.convert(out_dir, limit=3)
            for p in paths:
                self.assertTrue(
                    p.read_text(encoding="utf-8").endswith("# sentinel\n"),
                    f"{p.name} was overwritten by re-run",
                )

    # 10. YAML scalar primitives behave as documented.
    def test_yaml_scalar_emits_bool_and_float(self) -> None:
        self.assertEqual(self.tool.yaml_scalar(True), "true")
        self.assertEqual(self.tool.yaml_scalar(False), "false")
        self.assertEqual(self.tool.yaml_scalar(0.85), "0.85")
        self.assertEqual(self.tool.yaml_scalar(4.0), "4.0")

    # 11. YAML scalar quotes ambiguous strings.
    def test_yaml_scalar_quotes_trailing_colon(self) -> None:
        self.assertEqual(self.tool.yaml_scalar("foo:"), '"foo:"')

    # 12. CLI dry-run + json-summary works.
    def test_cli_dry_run_and_json_summary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pattern-docs-cli-") as tmp:
            out_dir = Path(tmp) / "out"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = self.tool.main(
                    ["--out-dir", str(out_dir), "--dry-run", "--json-summary", "--limit", "5"]
                )
            self.assertEqual(rc, 0)
            self.assertIn('"records_emitted": 5', stdout.getvalue())
            self.assertFalse(out_dir.exists())  # dry-run must not create

    # 13. CLI --limit rejects negative.
    def test_cli_limit_rejects_negative(self) -> None:
        rc = self.tool.main(
            ["--out-dir", "/tmp/should-not-be-created", "--limit", "-1"]
        )
        self.assertEqual(rc, 2)

    # 14. CLI --apply + --dry-run are mutually exclusive.
    def test_cli_apply_and_dry_run_are_mutually_exclusive(self) -> None:
        rc = self.tool.main(
            ["--out-dir", "/tmp/should-not-be-created", "--apply", "--dry-run"]
        )
        self.assertEqual(rc, 2)

    # 15. CLI --apply writes records to disk.
    def test_cli_apply_writes_records(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pattern-docs-apply-") as tmp:
            out_dir = Path(tmp) / "out"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = self.tool.main(
                    ["--out-dir", str(out_dir), "--apply", "--json-summary", "--limit", "4"]
                )
            self.assertEqual(rc, 0)
            written = list(out_dir.glob("*.yaml"))
            self.assertEqual(len(written), 4)

    # 16. CLI --filter-attack-class restricts output.
    def test_cli_filter_attack_class_restricts_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pattern-docs-filter-") as tmp:
            out_dir = Path(tmp) / "out"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = self.tool.main(
                    ["--out-dir", str(out_dir), "--dry-run", "--json-summary",
                     "--filter-attack-class", "uups-self-destruct-via-fallback"]
                )
            self.assertEqual(rc, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(set(payload["by_attack_class"].keys()),
                             {"uups-self-destruct-via-fallback"})

    # 17. target_domain values stay within the v1 schema enum on every row.
    def test_target_domain_values_are_in_schema_enum(self) -> None:
        allowed = {
            "lending", "dex", "bridge", "oracle", "governance", "staking",
            "vault", "rollup", "zk-proof", "consensus", "rpc-infra", "dao",
            "escrow", "nft", "gaming", "l1-client",
        }
        records = self.tool.build_records()
        for r in records:
            self.assertIn(r["target_domain"], allowed,
                          f"{r['record_id']}: target_domain {r['target_domain']} not in schema")

    # 18. The cosmos-msgexec pattern doc references the dYdX cantina-213
    #     anchor verbatim (Rule 25 empirical anchor).
    def test_cosmos_msgexec_doc_cites_dydx_cantina_213(self) -> None:
        doc = (PATTERNS_DIR / "cosmos-msgexec-nested-msg-bypass.md").read_text(encoding="utf-8")
        self.assertIn("cantina-213", doc.lower())

    # 19. Each pattern doc contains at minimum the required structural
    #     headings (surface, anti-pattern, correct-pattern, detector hint).
    def test_each_pattern_doc_has_required_sections(self) -> None:
        for slug in EXPECTED_PATTERN_FILES:
            body = (PATTERNS_DIR / f"{slug}.md").read_text(encoding="utf-8")
            for heading in [
                "## Surface description",
                "## Anti-pattern",
                "## Correct pattern",
                "## Detector hint",
                "## Real-world incident references",
            ]:
                self.assertIn(heading, body,
                              f"{slug}.md missing heading: {heading}")


if __name__ == "__main__":
    unittest.main()
