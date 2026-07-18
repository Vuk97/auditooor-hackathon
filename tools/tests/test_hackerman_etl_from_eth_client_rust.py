from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-eth-client-rust.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromEthClientRustTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL_PATH, "_hackerman_etl_from_eth_client_rust")
        self.validator = _load(
            VALIDATOR_PATH, "_hackerman_record_validate_for_eth_client_rust_etl"
        )

    # ------------------------------------------------------------------
    # Seed catalogue shape
    # ------------------------------------------------------------------

    def test_seed_catalogue_covers_full_el_plus_cl_class_set(self) -> None:
        classes = {seed["attack_class"] for seed in self.tool.SEED_CATALOGUE}
        expected_el = {
            "consensus-fork-choice-divergence",
            "payload-builder-frontrun",
            "engine-api-rpc-auth-bypass",
            "block-validation-bypass-via-relaxed-rules",
            "txpool-eviction-policy-griefing",
            "precompile-incomplete-cancun",
            "precompile-incomplete-prague",
            "state-sync-merkle-trie-mismatch",
            "evm-storage-warm-cold-leak",
        }
        expected_cl = {
            "attestation-slashing-condition-bypass",
            "slashing-proof-replay",
            "committee-shuffling-divergence",
            "sync-committee-aggregate-mismatch",
            "light-client-update-replay",
        }
        self.assertTrue(expected_el.issubset(classes), expected_el - classes)
        self.assertTrue(expected_cl.issubset(classes), expected_cl - classes)
        # Brief mandates >=3 new classes; we have >=14 total.
        self.assertGreaterEqual(len(classes), 3)

    def test_seed_catalogue_component_count_in_target_band(self) -> None:
        total = sum(len(seed["components"]) for seed in self.tool.SEED_CATALOGUE)
        # Brief specifies ~250-500 records target.
        self.assertGreaterEqual(total, 250)
        self.assertLessEqual(total, 500)

    def test_target_language_is_canonical_rust(self) -> None:
        # Schema enum uses `rust`; eth-client-vs-substrate-vs-solana lives in
        # shape_tags / target_repo. Brief's `rust-eth-client` is a shape tag.
        self.assertEqual(self.tool.TARGET_LANGUAGE, "rust")
        self.assertEqual(self.tool.SHAPE_PLATFORM_TAG, "rust-eth-client")

    # ------------------------------------------------------------------
    # Record building
    # ------------------------------------------------------------------

    def test_extract_records_emits_expected_volume(self) -> None:
        records, counters = self.tool.extract_records()
        self.assertEqual(counters["attack_classes_seen"], len(self.tool.SEED_CATALOGUE))
        self.assertEqual(len(records), counters["components_seen"])
        self.assertGreaterEqual(len(records), 250)
        self.assertLessEqual(len(records), 500)

    def test_records_are_unique_by_record_id(self) -> None:
        records, _ = self.tool.extract_records()
        ids = [r["record_id"] for r in records]
        self.assertEqual(len(ids), len(set(ids)), "duplicate record_id collision")

    def test_records_carry_rust_eth_client_shape_tag(self) -> None:
        records, _ = self.tool.extract_records()
        for record in records:
            tags = record["function_shape"]["shape_tags"]
            self.assertIn(
                "rust-eth-client",
                tags,
                f"missing rust-eth-client shape tag on {record['record_id']}: {tags}",
            )

    def test_records_use_rust_language_enum(self) -> None:
        records, _ = self.tool.extract_records()
        for record in records:
            self.assertEqual(record["target_language"], "rust")

    def test_records_reference_known_eth_client_repos(self) -> None:
        # Eth-client specificity check: every target_repo must reference a
        # recognisable Rust eth-client repo. This is the structural
        # distinction from generic Rust records (solana, substrate, ink!).
        recognisable = (
            "paradigmxyz/",       # Reth
            "ethereum-optimism/",  # op-reth
            "op-rs/",              # Kona
            "sigp/",               # Lighthouse
            "erigontech/",         # Erigon-rs
        )
        records, _ = self.tool.extract_records()
        for record in records:
            repo = record["target_repo"]
            self.assertTrue(
                repo.startswith(recognisable),
                f"{repo!r} does not look like a Rust eth-client repo",
            )

    def test_records_carry_go_cross_language_analogue(self) -> None:
        # Brief item 6: cross-language analogue lift -- every record must
        # point to its canonical Go (geth / op-geth / prysm) counterpart so
        # the corpus router can lift `consensus-divergence` Go records into
        # Rust search results.
        records, _ = self.tool.extract_records()
        for record in records:
            analogues = record["cross_language_analogues"]
            self.assertTrue(
                analogues,
                f"record {record['record_id']} missing cross_language_analogues",
            )
            self.assertEqual(analogues[0]["target_language"], "go")
            self.assertIn(
                "Equivalent Go surface",
                analogues[0]["pattern_translation"],
                f"analogue payload malformed on {record['record_id']}",
            )

    def test_attack_class_coverage_spans_el_and_cl(self) -> None:
        # Reach into impact-actor distribution to confirm the corpus spans
        # both EL (validator-set, sequencer) and CL (validator-set,
        # yield-recipient, specific-user) targets.
        records, _ = self.tool.extract_records()
        actors = {r["impact_actor"] for r in records}
        # EL classes typically target sequencer / validator-set; CL classes
        # often target yield-recipient or specific-user via slashing /
        # light-client routes.
        self.assertIn("validator-set", actors)
        self.assertIn("sequencer", actors)
        self.assertGreaterEqual(len(actors), 3)

    def test_attacker_roles_use_schema_enum(self) -> None:
        # Spot-check that we did not invent attacker roles outside the
        # schema enum (block-proposer / validator / proposer / sequencer /
        # unprivileged / privileged-trusted / etc).
        allowed = {
            "unprivileged",
            "privileged-trusted",
            "privileged-compromised",
            "local-host-observer",
            "block-proposer",
            "governance",
            "validator",
            "sequencer",
            "proposer",
        }
        records, _ = self.tool.extract_records()
        seen = {r["attacker_role"] for r in records}
        self.assertTrue(
            seen.issubset(allowed),
            f"unknown attacker roles: {seen - allowed}",
        )

    # ------------------------------------------------------------------
    # Schema validity
    # ------------------------------------------------------------------

    def test_all_records_are_schema_valid(self) -> None:
        records, _ = self.tool.extract_records()
        schema = self.validator.load_schema()
        for record in records:
            errors = self.validator.validate_doc(record, schema)
            self.assertEqual(
                errors,
                [],
                f"schema errors on {record['record_id']}: {errors}",
            )

    def test_cli_writes_schema_valid_yaml_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = self.tool.main(
                    ["--out-dir", str(out_dir), "--json-summary"]
                )
            self.assertEqual(rc, 0)
            files = sorted(out_dir.glob("*.yaml"))
            self.assertGreaterEqual(len(files), 250)
            self.assertLessEqual(len(files), 500)

            schema = self.validator.load_schema()
            for path in files:
                status, errors = self.validator.validate_file(path, schema)
                self.assertEqual(status, "valid", (path, errors))

    # ------------------------------------------------------------------
    # CLI behaviour
    # ------------------------------------------------------------------

    def test_dry_run_does_not_write_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = self.tool.main(
                    ["--out-dir", str(out_dir), "--dry-run", "--json-summary"]
                )
            self.assertEqual(rc, 0)
            self.assertFalse(out_dir.exists())

    def test_limit_caps_record_count(self) -> None:
        records, _ = self.tool.extract_records(limit=12)
        self.assertEqual(len(records), 12)

    def test_negative_limit_is_rejected(self) -> None:
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            rc = self.tool.main(["--out-dir", "/tmp/nope", "--limit", "-3"])
        self.assertEqual(rc, 2)

    def test_json_summary_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = self.tool.main(
                    ["--out-dir", str(out_dir), "--dry-run", "--json-summary"]
                )
            self.assertEqual(rc, 0)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["target_language"], "rust")
            self.assertEqual(payload["platform_tag"], "rust-eth-client")
            self.assertGreaterEqual(payload["attack_classes_seen"], 14)
            self.assertIn("records_emitted", payload)
            self.assertIn("files", payload)

    def test_record_ids_fit_schema_pattern(self) -> None:
        # Defense-in-depth: assert the record_id pattern explicitly so a
        # regression that bloats the source_ref past 160 chars or smuggles
        # underscores in is caught at unit-test time, not schema-validate
        # time.
        import re
        pattern = re.compile(r"^[A-Za-z0-9._:/-]{8,160}$")
        records, _ = self.tool.extract_records()
        for record in records:
            self.assertRegex(record["record_id"], pattern)


if __name__ == "__main__":
    unittest.main()
