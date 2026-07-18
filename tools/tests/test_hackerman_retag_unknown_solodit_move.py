"""Tests for tools/hackerman-retag-unknown-solodit-move.py.

Wave-5 lane EXEC-WAVE5-MOVE-CVE-RETAG / TIER-D Lift D14.

These tests cover:

* Indicator-literal classifier distinguishes Aptos / Sui / Move-language
* Move-resource-safety subclass append when indicators co-fire
* `target_repo_original` and `shape_tags_original` are preserved for rollback
* Records that are not `target_language: move` are not emitted
* Records that are not `target_repo: unknown/solodit` are not emitted
* Candidate JSONL is one JSON object per line; the tool does NOT mutate
  the source YAML files in the corpus
* CLI `--dry-run --json-summary` returns a valid JSON summary without
  writing the output file
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
TOOL = REPO_ROOT / "tools" / "hackerman-retag-unknown-solodit-move.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


APTOS_YAML = """\
schema_version: auditooor.hackerman_record.v1
record_id: solodit-spec:m-aptos-test:abc123
source_audit_ref: solodit-spec:detectors/_specs/drafts_solodit_move/aptos-coin-mint-cap-leak.yaml:M-1
target_language: move
target_repo: unknown/solodit
target_component: "Aptos Framework managed_coin MintCapability leak"
function_shape:
  raw_signature: "public fun mint_with_cap<CoinType>(): Coin<CoinType>"
  shape_tags:
    - capability-pattern-bypass
    - move
bug_class: capability-pattern-bypass
attack_class: capability-leak-or-unbounded-mint
attacker_role: unprivileged
attacker_action_sequence: "Caller borrows MintCapability from aptos_framework::managed_coin and mints freely."
required_preconditions:
  - "managed_coin Capabilities is publicly borrowed"
impact_class: theft
impact_actor: arbitrary-user
impact_dollar_class: ">=$1M"
fix_pattern: "Wrap MintCapability behind typed Capability<MINT_ROLE>."
fix_anti_pattern_avoided: "shipping shared MintCapability"
severity_at_finding: critical
year: 2024
cross_language_analogues: []
related_records: []
"""


SUI_YAML = """\
schema_version: auditooor.hackerman_record.v1
record_id: solodit-spec:h-sui-test:def456
source_audit_ref: solodit-spec:detectors/_specs/drafts_solodit_move/sui-deepbook-fee-precision.yaml:H-1
target_language: move
target_repo: unknown/solodit
target_component: "Sui DeepBook fee accrual precision loss"
function_shape:
  raw_signature: "public fun accrue_fees<Base, Quote>(pool: &mut Pool<Base, Quote>, amount: u64)"
  shape_tags:
    - precision-loss
    - move
bug_class: precision-loss
attack_class: rounding-precision-loss
attacker_role: unprivileged
attacker_action_sequence: "Attacker submits many small taker fills through deepbook::custodian; sui::tx_context::sender is the attacker."
required_preconditions:
  - "DeepBook fee path uses integer division"
impact_class: theft
impact_actor: protocol-treasury
impact_dollar_class: "$100K-$1M"
fix_pattern: "Round protocol fee up; switch to fixed-point."
fix_anti_pattern_avoided: "shipping rounding-asymmetric accrual"
severity_at_finding: high
year: 2024
cross_language_analogues: []
related_records: []
"""


PLAIN_MOVE_YAML = """\
schema_version: auditooor.hackerman_record.v1
record_id: solodit-spec:h-plain:ghi789
source_audit_ref: solodit-spec:detectors/_specs/drafts_solodit_move/plain-move-record.yaml:H-1
target_language: move
target_repo: unknown/solodit
target_component: "Generic Move record without chain attribution"
function_shape:
  raw_signature: "public entry fun do_thing()"
  shape_tags:
    - flash-loan
    - move
bug_class: flash-loan
attack_class: flash-loan
attacker_role: unprivileged
attacker_action_sequence: "tbd"
required_preconditions:
  - "tbd"
impact_class: griefing
impact_actor: arbitrary-user
impact_dollar_class: $10K-$100K
fix_pattern: "tbd"
fix_anti_pattern_avoided: "tbd"
severity_at_finding: medium
year: 2024
cross_language_analogues: []
related_records: []
"""


SOLIDITY_YAML = """\
schema_version: auditooor.hackerman_record.v1
record_id: solodit-spec:m-evm:jkl012
source_audit_ref: solodit-spec:detectors/_specs/drafts_solodit_evm/sample.yaml:M-1
target_language: solidity
target_repo: unknown/solodit
target_component: "EVM record (should be ignored by Move retag)"
function_shape:
  raw_signature: "function withdraw() public"
  shape_tags:
    - reentrancy
bug_class: reentrancy
attack_class: reentrancy
attacker_role: unprivileged
attacker_action_sequence: "EVM-specific action"
required_preconditions:
  - "EVM"
impact_class: theft
impact_actor: arbitrary-user
impact_dollar_class: $10K-$100K
fix_pattern: "Apply CEI"
fix_anti_pattern_avoided: "shipping unguarded callback"
severity_at_finding: medium
year: 2024
cross_language_analogues: []
related_records: []
"""


MOVE_WITH_KNOWN_REPO_YAML = """\
schema_version: auditooor.hackerman_record.v1
record_id: solodit-spec:m-known-repo:mno345
source_audit_ref: solodit-spec:foo
target_language: move
target_repo: aptos-labs/aptos-core
target_component: "Already attributed (should be ignored)"
function_shape:
  raw_signature: "public fun already_known()"
  shape_tags:
    - move-aptos
bug_class: logic-error
attack_class: protocol-invariant-bypass
attacker_role: unprivileged
attacker_action_sequence: "tbd"
required_preconditions:
  - "tbd"
impact_class: griefing
impact_actor: arbitrary-user
impact_dollar_class: $10K-$100K
fix_pattern: "tbd"
fix_anti_pattern_avoided: "tbd"
severity_at_finding: low
year: 2024
cross_language_analogues: []
related_records: []
"""


class HackermanRetagUnknownSoloditMoveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_retag_unknown_solodit_move_under_test")

    # ------------------------------------------------------------------
    # Indicator classifier unit tests
    # ------------------------------------------------------------------

    def test_classifier_identifies_aptos(self) -> None:
        is_aptos, is_sui, _ = self.tool._classify(
            "aptos_framework::managed_coin MintCapability leak via aptos-stdlib"
        )
        self.assertTrue(is_aptos)
        self.assertFalse(is_sui)

    def test_classifier_identifies_sui(self) -> None:
        is_aptos, is_sui, _ = self.tool._classify(
            "Sui DeepBook custodian uses sui::tx_context::sender via mysten deepbook path"
        )
        self.assertFalse(is_aptos)
        self.assertTrue(is_sui)

    def test_classifier_returns_neither_for_plain_move(self) -> None:
        is_aptos, is_sui, _ = self.tool._classify(
            "Generic Move flash-loan invariant; no chain indicator surface"
        )
        self.assertFalse(is_aptos)
        self.assertFalse(is_sui)

    def test_classifier_returns_rs_class_when_indicator_fires(self) -> None:
        _, _, rs_class = self.tool._classify(
            "TreasuryCap leak gives unbounded mint via friend module"
        )
        self.assertIsNotNone(rs_class)
        self.assertEqual(rs_class[0], "capability-pattern-bypass")
        self.assertEqual(rs_class[1], "capability-leak-or-unbounded-mint")

    def test_classifier_recognises_ambiguous_aptos_and_sui(self) -> None:
        is_aptos, is_sui, _ = self.tool._classify(
            "Cross-chain bridge between aptos-core and mysten Sui referenced together"
        )
        self.assertTrue(is_aptos)
        self.assertTrue(is_sui)

    def test_classifier_does_not_bias_aptos_on_drafts_solodit_move_alone(self) -> None:
        # The `drafts_solodit_move` corpus is Move-language-generic; on its
        # own it must not bias the classifier toward Aptos. Without any
        # other indicator, both is_aptos and is_sui should be False.
        is_aptos, is_sui, _ = self.tool._classify(
            "solodit-spec:detectors/_specs/drafts_solodit_move/some-record.yaml:H-1 "
            "Generic Move record with no chain-specific indicators"
        )
        self.assertFalse(is_aptos)
        self.assertFalse(is_sui)

    # ------------------------------------------------------------------
    # read_record + build_candidate
    # ------------------------------------------------------------------

    def test_read_record_parses_move_unknown_record(self) -> None:
        with tempfile.TemporaryDirectory(prefix="retag-read-") as tmp:
            path = Path(tmp) / "rec.yaml"
            path.write_text(APTOS_YAML, encoding="utf-8")
            rec = self.tool.read_record(path)
            self.assertIsNotNone(rec)
            self.assertEqual(rec["target_language"], "move")
            self.assertEqual(rec["target_repo"], "unknown/solodit")
            self.assertIn("capability-pattern-bypass", rec["shape_tags"])
            self.assertIn("move", rec["shape_tags"])
            self.assertIn("Aptos", rec["target_component"])

    def test_build_candidate_for_aptos_record(self) -> None:
        with tempfile.TemporaryDirectory(prefix="retag-aptos-") as tmp:
            path = Path(tmp) / "rec.yaml"
            path.write_text(APTOS_YAML, encoding="utf-8")
            rec = self.tool.read_record(path)
            candidate = self.tool.build_candidate(path, rec)
            self.assertIsNotNone(candidate)
            self.assertEqual(candidate["verdict"], "retag-aptos")
            self.assertEqual(candidate["target_repo_proposed"], "aptos-labs/aptos-core")
            self.assertEqual(candidate["target_repo_original"], "unknown/solodit")
            self.assertIn("move-aptos", candidate["shape_tags_proposed"])
            # Original shape_tags preserved for rollback
            self.assertEqual(
                candidate["shape_tags_original"], ["capability-pattern-bypass", "move"]
            )

    def test_build_candidate_for_sui_record(self) -> None:
        with tempfile.TemporaryDirectory(prefix="retag-sui-") as tmp:
            path = Path(tmp) / "rec.yaml"
            path.write_text(SUI_YAML, encoding="utf-8")
            rec = self.tool.read_record(path)
            candidate = self.tool.build_candidate(path, rec)
            self.assertIsNotNone(candidate)
            self.assertEqual(candidate["verdict"], "retag-sui")
            self.assertEqual(candidate["target_repo_proposed"], "MystenLabs/sui")
            self.assertIn("move-sui", candidate["shape_tags_proposed"])

    def test_build_candidate_for_plain_move_falls_back(self) -> None:
        with tempfile.TemporaryDirectory(prefix="retag-plain-") as tmp:
            path = Path(tmp) / "rec.yaml"
            path.write_text(PLAIN_MOVE_YAML, encoding="utf-8")
            rec = self.tool.read_record(path)
            candidate = self.tool.build_candidate(path, rec)
            self.assertIsNotNone(candidate)
            self.assertEqual(candidate["verdict"], "language-only-fallback")
            self.assertEqual(candidate["target_repo_proposed"], "move-language/move")
            self.assertIn("move-language", candidate["shape_tags_proposed"])

    def test_build_candidate_skips_non_move(self) -> None:
        with tempfile.TemporaryDirectory(prefix="retag-skip-evm-") as tmp:
            path = Path(tmp) / "rec.yaml"
            path.write_text(SOLIDITY_YAML, encoding="utf-8")
            rec = self.tool.read_record(path)
            candidate = self.tool.build_candidate(path, rec)
            self.assertIsNone(candidate)

    def test_build_candidate_skips_known_repo(self) -> None:
        with tempfile.TemporaryDirectory(prefix="retag-skip-known-") as tmp:
            path = Path(tmp) / "rec.yaml"
            path.write_text(MOVE_WITH_KNOWN_REPO_YAML, encoding="utf-8")
            rec = self.tool.read_record(path)
            candidate = self.tool.build_candidate(path, rec)
            self.assertIsNone(candidate)

    # ------------------------------------------------------------------
    # convert end-to-end
    # ------------------------------------------------------------------

    def test_convert_emits_jsonl_and_does_not_mutate_corpus(self) -> None:
        with tempfile.TemporaryDirectory(prefix="retag-e2e-") as tmp:
            tags_dir = Path(tmp) / "tags"
            tags_dir.mkdir()
            (tags_dir / "aptos.yaml").write_text(APTOS_YAML, encoding="utf-8")
            (tags_dir / "sui.yaml").write_text(SUI_YAML, encoding="utf-8")
            (tags_dir / "plain.yaml").write_text(PLAIN_MOVE_YAML, encoding="utf-8")
            (tags_dir / "evm.yaml").write_text(SOLIDITY_YAML, encoding="utf-8")
            (tags_dir / "known.yaml").write_text(MOVE_WITH_KNOWN_REPO_YAML, encoding="utf-8")

            # Snapshot bytes for the inputs before running, so we can
            # verify the tool does NOT mutate the corpus files.
            snapshots = {
                p: p.read_bytes() for p in tags_dir.glob("*.yaml")
            }

            out_jsonl = Path(tmp) / "out.jsonl"
            summary = self.tool.convert(
                tags_dir=tags_dir,
                out_jsonl=out_jsonl,
                dry_run=False,
            )
            self.assertEqual(summary["errors"], [])
            self.assertEqual(summary["scanned"], 5)
            self.assertEqual(summary["matched_move_unknown"], 3)
            self.assertEqual(summary["candidates_emitted"], 3)
            self.assertEqual(
                summary["verdict_counts"],
                {"retag-aptos": 1, "retag-sui": 1, "language-only-fallback": 1},
            )

            # JSONL is one JSON object per line
            lines = [
                line for line in out_jsonl.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual(len(lines), 3)
            for line in lines:
                payload = json.loads(line)
                self.assertEqual(payload["schema_version"], "auditooor.move-retag-candidate.v1")
                self.assertEqual(payload["target_language"], "move")
                self.assertEqual(payload["target_repo_original"], "unknown/solodit")
                self.assertNotEqual(
                    payload["target_repo_proposed"], "unknown/solodit",
                    "candidate must propose a different repo",
                )
                self.assertIn(
                    payload["verdict"],
                    {"retag-aptos", "retag-sui", "language-only-fallback", "ambiguous-needs-operator"},
                )

            # Critical hard-rule check: the corpus files must NOT have
            # been mutated.
            for path, expected_bytes in snapshots.items():
                self.assertEqual(
                    path.read_bytes(), expected_bytes,
                    f"{path} was mutated; retag must be read-only on corpus",
                )

    # ------------------------------------------------------------------
    # CLI
    # ------------------------------------------------------------------

    def test_cli_dry_run_does_not_write_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="retag-cli-") as tmp:
            tags_dir = Path(tmp) / "tags"
            tags_dir.mkdir()
            (tags_dir / "aptos.yaml").write_text(APTOS_YAML, encoding="utf-8")
            out_jsonl = Path(tmp) / "out.jsonl"

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = self.tool.main(
                    [
                        "--tags-dir",
                        str(tags_dir),
                        "--out-jsonl",
                        str(out_jsonl),
                        "--dry-run",
                        "--json-summary",
                    ]
                )
            self.assertEqual(rc, 0)
            payload = json.loads(stdout.getvalue())
            self.assertTrue(payload["dry_run"])
            self.assertEqual(payload["candidates_emitted"], 1)
            self.assertFalse(out_jsonl.exists())

    def test_cli_handles_missing_tags_dir(self) -> None:
        with tempfile.TemporaryDirectory(prefix="retag-missing-") as tmp:
            missing_dir = Path(tmp) / "does_not_exist"
            out_jsonl = Path(tmp) / "out.jsonl"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = self.tool.main(
                    [
                        "--tags-dir",
                        str(missing_dir),
                        "--out-jsonl",
                        str(out_jsonl),
                        "--dry-run",
                        "--json-summary",
                    ]
                )
            # Tool should emit an error and rc != 0
            self.assertNotEqual(rc, 0)
            payload = json.loads(stdout.getvalue())
            self.assertGreaterEqual(len(payload["errors"]), 1)


if __name__ == "__main__":
    unittest.main()
