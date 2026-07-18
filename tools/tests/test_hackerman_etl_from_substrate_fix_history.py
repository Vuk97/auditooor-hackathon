"""Unit tests for ``tools/hackerman-etl-from-substrate-fix-history.py``.

These tests never call ``gh api``. They drive the miner through a patched
``gh_api`` function with synthetic commit-shaped payloads (modeled on the
real fields returned by the GitHub REST endpoint for paritytech repos) and
assert the records that come out:

* Validate against the v1 schema.
* Preserve the commit SHA / URL verbatim in ``source_audit_ref`` and
  ``attacker_action_sequence``.
* Classify substrate-subsystem (finality-grandpa-beefy, consensus-babe-aura,
  parachain-disputes-approval, bridge-xcm-messaging, frame-pallet, ...) correctly.
* Identify substrate bug classes (consensus-equivocation, fork-choice,
  finality-stall, fraud-proof, bridge-protocol, frame-storage, ...).
* Drop non-substrate / test-only commits.
* Honor per-repo cap and dedupe across multiple repos.

Wave-1 lane: wave-1-hackerman-capability-lift (PR #726).
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-substrate-fix-history.py"
VALIDATOR = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules.setdefault(spec.name, mod)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Fixtures mimicking real paritytech gh-api shapes.
# ---------------------------------------------------------------------------

_FIX_COMMIT_LIST: List[Dict[str, Any]] = [
    {
        "sha": "1111111111111111111111111111111111111111",
        "commit": {
            "message": (
                "fix(grandpa): guard against equivocation slash replay\n\n"
                "GRANDPA finality could double-slash on replay; add ensure! "
                "validating set_id and round before applying slash."
            ),
            "author": {"date": "2024-09-13T12:00:00Z"},
            "committer": {"date": "2024-09-13T12:00:00Z"},
        },
    },
    {
        "sha": "2222222222222222222222222222222222222222",
        "commit": {
            "message": (
                "fix: consensus fork-choice picks unjustified head on Aura\n\n"
                "Audit followup: validate finality justifications before "
                "advancing the fork-choice head."
            ),
            "author": {"date": "2023-04-01T08:00:00Z"},
            "committer": {"date": "2023-04-01T08:00:00Z"},
        },
    },
    {
        "sha": "3333333333333333333333333333333333333333",
        "commit": {
            "message": "revert: rollback paras_inherent fraud-proof change that broke disputes",
            "author": {"date": "2024-02-15T08:00:00Z"},
            "committer": {"date": "2024-02-15T08:00:00Z"},
        },
    },
    {
        "sha": "4444444444444444444444444444444444444444",
        "commit": {
            "message": "docs: typo in README",
            "author": {"date": "2024-08-15T08:00:00Z"},
            "committer": {"date": "2024-08-15T08:00:00Z"},
        },
    },
    {
        "sha": "5555555555555555555555555555555555555555",
        "commit": {
            "message": "chore: prettier formatting",
            "author": {"date": "2024-08-15T08:00:00Z"},
            "committer": {"date": "2024-08-15T08:00:00Z"},
        },
    },
    {
        "sha": "6666666666666666666666666666666666666666",
        "commit": {
            "message": "fix(xcm-bridge): validate origin on incoming HRMP message",
            "author": {"date": "2024-06-15T08:00:00Z"},
            "committer": {"date": "2024-06-15T08:00:00Z"},
        },
    },
    {
        "sha": "7777777777777777777777777777777777777777",
        "commit": {
            "message": "fix(pallet-staking): guard storage migration against overflow",
            "author": {"date": "2024-03-15T08:00:00Z"},
            "committer": {"date": "2024-03-15T08:00:00Z"},
        },
    },
    {
        "sha": "8888888888888888888888888888888888888888",
        "commit": {
            "message": "fix(ci): tests-only typo in pytest harness",
            "author": {"date": "2024-04-15T08:00:00Z"},
            "committer": {"date": "2024-04-15T08:00:00Z"},
        },
    },
]


_FIX_COMMIT_DETAILS: Dict[str, Dict[str, Any]] = {
    "1111111111111111111111111111111111111111": {
        "sha": "1111111111111111111111111111111111111111",
        "parents": [{"sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],
        "commit": {
            "message": (
                "fix(grandpa): guard against equivocation slash replay\n\n"
                "GRANDPA finality could double-slash on replay; add ensure! "
                "validating set_id and round before applying slash."
            ),
            "author": {"date": "2024-09-13T12:00:00Z"},
            "committer": {"date": "2024-09-13T12:00:00Z"},
        },
        "files": [
            {
                "filename": "substrate/client/finality-grandpa/src/equivocation.rs",
                "status": "modified",
                "additions": 5,
                "deletions": 2,
                "patch": (
                    "@@ -10,6 +10,9 @@\n"
                    "+pub fn validate_equivocation(set_id: u64, round: u64) -> Result<(), Error> {\n"
                    "+    ensure!(set_id == current_set_id, Error::InvalidSetId);\n"
                    "+    debug_assert!(round > 0);\n"
                ),
            },
        ],
    },
    "2222222222222222222222222222222222222222": {
        "sha": "2222222222222222222222222222222222222222",
        "parents": [{"sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],
        "commit": {
            "message": (
                "fix: consensus fork-choice picks unjustified head on Aura\n\n"
                "Audit followup: validate finality justifications before "
                "advancing the fork-choice head."
            ),
            "author": {"date": "2023-04-01T08:00:00Z"},
            "committer": {"date": "2023-04-01T08:00:00Z"},
        },
        "files": [
            {
                "filename": "polkadot/node/consensus/aura/src/fork_choice.rs",
                "status": "modified",
                "additions": 4,
                "deletions": 1,
                "patch": (
                    "@@ -1,3 +1,5 @@\n"
                    "+pub fn select_head(blocks: &[BlockId]) -> Option<BlockId> {\n"
                    "+    ensure!(blocks.iter().all(|b| b.finalized), Error::Unjustified);\n"
                ),
            },
        ],
    },
    "3333333333333333333333333333333333333333": {
        "sha": "3333333333333333333333333333333333333333",
        "parents": [{"sha": "cccccccccccccccccccccccccccccccccccccccc"}],
        "commit": {
            "message": "revert: rollback paras_inherent fraud-proof change that broke disputes",
            "author": {"date": "2024-02-15T08:00:00Z"},
            "committer": {"date": "2024-02-15T08:00:00Z"},
        },
        "files": [
            {
                "filename": "polkadot/runtime/parachains/src/paras_inherent.rs",
                "status": "modified",
                "additions": 1,
                "deletions": 5,
                "patch": (
                    "@@ -1,5 +1,1 @@\n"
                    "-fn validate_fraud_proof(proof: &FraudProof) -> Result<(), Error> {\n"
                    "+fn validate_fraud_proof(proof: &FraudProof) {\n"
                ),
            },
        ],
    },
    "6666666666666666666666666666666666666666": {
        "sha": "6666666666666666666666666666666666666666",
        "parents": [{"sha": "ffffffffffffffffffffffffffffffffffffffff"}],
        "commit": {
            "message": "fix(xcm-bridge): validate origin on incoming HRMP message",
            "author": {"date": "2024-06-15T08:00:00Z"},
            "committer": {"date": "2024-06-15T08:00:00Z"},
        },
        "files": [
            {
                "filename": "cumulus/pallets/xcmp-queue/src/lib.rs",
                "status": "modified",
                "additions": 6,
                "deletions": 1,
                "patch": (
                    "@@ -1,5 +1,11 @@\n"
                    "+pub fn process_hrmp(origin: ParaId, msg: Xcm) -> DispatchResult {\n"
                    "+    ensure!(is_valid_origin(origin), Error::<T>::BadOrigin);\n"
                ),
            },
        ],
    },
    "7777777777777777777777777777777777777777": {
        "sha": "7777777777777777777777777777777777777777",
        "parents": [{"sha": "0000000000000000000000000000000000000001"}],
        "commit": {
            "message": "fix(pallet-staking): guard storage migration against overflow",
            "author": {"date": "2024-03-15T08:00:00Z"},
            "committer": {"date": "2024-03-15T08:00:00Z"},
        },
        "files": [
            {
                "filename": "substrate/frame/staking/src/migrations.rs",
                "status": "modified",
                "additions": 3,
                "deletions": 0,
                "patch": (
                    "@@ -1,3 +1,6 @@\n"
                    "+fn migrate_v9_to_v10() -> Weight {\n"
                    "+    let total = old.saturating_add(new);\n"
                    "+    StorageVersion::new(10).put::<Self>();\n"
                ),
            },
        ],
    },
    "8888888888888888888888888888888888888888": {
        # tests-only commit -> should be dropped
        "sha": "8888888888888888888888888888888888888888",
        "parents": [{"sha": "0000000000000000000000000000000000000002"}],
        "commit": {
            "message": "fix(ci): tests-only typo in pytest harness",
            "author": {"date": "2024-04-15T08:00:00Z"},
            "committer": {"date": "2024-04-15T08:00:00Z"},
        },
        "files": [
            {
                "filename": "substrate/frame/staking/src/tests/migrations_test.rs",
                "status": "modified",
                "additions": 1,
                "deletions": 1,
                "patch": "-old\n+new",
            },
        ],
    },
}


class _FakeGhApiState:
    """Capture all gh_api / list_commits / get_commit_detail traffic."""

    def __init__(self) -> None:
        self.calls: List[str] = []

    def gh_api(self, path: str, paginate: bool = False) -> Any:
        self.calls.append(path)
        if "/commits?per_page" in path:
            if "page=1" in path or "page=" not in path:
                return _FIX_COMMIT_LIST
            return []
        for sha, detail in _FIX_COMMIT_DETAILS.items():
            if path.endswith(f"/commits/{sha}"):
                return detail
        return None


class HackermanEtlFromSubstrateFixHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_substrate_fix_history")
        self.validator = _load(
            VALIDATOR, "_hackerman_record_validate_for_substrate_fix_history"
        )
        self.fake = _FakeGhApiState()
        self._orig_gh_api = self.tool.gh_api
        self.tool.gh_api = self.fake.gh_api  # type: ignore[assignment]

    def tearDown(self) -> None:
        self.tool.gh_api = self._orig_gh_api  # type: ignore[assignment]

    # 1. Dry-run emits records with zero validator errors.
    def test_dry_run_emits_records_with_zero_errors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="substrate-fix-dry-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out",
                dry_run=True,
                repos=["paritytech/polkadot-sdk"],
                pages=1,
                per_page=10,
                max_per_repo=10,
                detail_cap=10,
            )
        self.assertEqual(summary["errors"], [], f"errors={summary['errors']}")
        self.assertGreater(summary["records_valid"], 0)
        self.assertEqual(summary["records_total"], summary["records_valid"])

    # 2. Negative filter drops doc / chore / prettier subjects.
    def test_negative_filter_drops_non_protocol_churn(self) -> None:
        self.assertFalse(self.tool.is_fix_shape("docs: typo in README", "x"))
        self.assertFalse(self.tool.is_fix_shape("chore: prettier formatting", "x"))

    # 3. Positive filter admits substrate fix-shapes including consensus / finality / fraud.
    def test_positive_filter_admits_fix_shapes(self) -> None:
        self.assertTrue(self.tool.is_fix_shape("fix(grandpa): guard equivocation slash replay", "x"))
        self.assertTrue(self.tool.is_fix_shape("audit: validate paras_inherent fraud proof", "x"))
        self.assertTrue(self.tool.is_fix_shape("revert: rollback fork-choice change", "x"))
        self.assertTrue(self.tool.is_fix_shape("security: patch finality bypass", "x"))
        self.assertTrue(self.tool.is_fix_shape("fix: consensus halt under high load", "x"))

    # 4. Detector seed extraction: Rust-style ensure! / asserts / consensus / saturating math.
    def test_detector_seed_extracts_ensure(self) -> None:
        patch = "+    ensure!(set_id == current_set_id, Error::InvalidSetId)"
        seed = self.tool.extract_detector_seed(patch, "fix(grandpa): set_id guard")
        self.assertIn("added ensure", seed)

    def test_detector_seed_extracts_consensus_primitive(self) -> None:
        patch = "+    let just = Justification::new(round, set_id);"
        seed = self.tool.extract_detector_seed(patch, "fix: grandpa justification")
        self.assertIn("consensus primitive", seed.lower())

    def test_detector_seed_extracts_bridge_primitive(self) -> None:
        patch = "+let xcm = Xcm::new();"
        seed = self.tool.extract_detector_seed(patch, "fix(xcm): origin check")
        self.assertIn("bridge / xcm primitive", seed.lower())

    def test_detector_seed_extracts_saturating_math(self) -> None:
        patch = "+    let total = a.saturating_add(b);"
        seed = self.tool.extract_detector_seed(patch, "fix: arithmetic overflow")
        self.assertIn("saturating / checked math", seed.lower())

    def test_detector_seed_fallback_is_nonempty(self) -> None:
        seed = self.tool.extract_detector_seed("@@ no body @@\n", "merge pr 1")
        self.assertTrue(seed)
        self.assertGreater(len(seed), 3)

    # 5. Record shape: every required field present, source_audit_ref is git-mining:<repo>@<full-sha>.
    def test_record_shape_has_source_audit_ref_and_url(self) -> None:
        detail = _FIX_COMMIT_DETAILS["1111111111111111111111111111111111111111"]
        rec = self.tool.commit_to_record("paritytech/polkadot-sdk", detail)
        assert rec is not None
        self.assertTrue(
            rec["source_audit_ref"].startswith("git-mining:paritytech/polkadot-sdk@")
        )
        self.assertTrue(rec["record_id"].startswith("git-mining:paritytech-polkadot-sdk:"))
        self.assertIn(
            "https://github.com/paritytech/polkadot-sdk/commit/"
            "1111111111111111111111111111111111111111",
            rec["attacker_action_sequence"],
        )
        self.assertEqual(rec["target_language"], "rust")
        self.assertEqual(rec["target_repo"], "paritytech/polkadot-sdk")
        schema = self.validator.load_schema()
        verrs = self.validator.validate_doc(rec, schema)
        self.assertEqual(verrs, [])

    # 6. Subsystem classification: finality vs consensus vs disputes vs bridge vs pallet.
    def test_subsystem_classification(self) -> None:
        rec_finality = self.tool.commit_to_record(
            "paritytech/substrate",
            _FIX_COMMIT_DETAILS["1111111111111111111111111111111111111111"],
        )
        rec_consensus = self.tool.commit_to_record(
            "paritytech/polkadot",
            _FIX_COMMIT_DETAILS["2222222222222222222222222222222222222222"],
        )
        rec_disputes = self.tool.commit_to_record(
            "paritytech/polkadot",
            _FIX_COMMIT_DETAILS["3333333333333333333333333333333333333333"],
        )
        rec_bridge = self.tool.commit_to_record(
            "paritytech/cumulus",
            _FIX_COMMIT_DETAILS["6666666666666666666666666666666666666666"],
        )
        rec_pallet = self.tool.commit_to_record(
            "paritytech/substrate",
            _FIX_COMMIT_DETAILS["7777777777777777777777777777777777777777"],
        )
        for rec in (rec_finality, rec_consensus, rec_disputes, rec_bridge, rec_pallet):
            assert rec is not None
        self.assertIn("finality-grandpa-beefy", rec_finality["function_shape"]["shape_tags"])
        self.assertIn("consensus-babe-aura", rec_consensus["function_shape"]["shape_tags"])
        self.assertIn("parachain-disputes-approval", rec_disputes["function_shape"]["shape_tags"])
        self.assertIn("bridge-xcm-messaging", rec_bridge["function_shape"]["shape_tags"])
        # rec_pallet is under substrate/frame/staking/src/migrations.rs - runtime-upgrade wins via path match.
        pallet_tags = rec_pallet["function_shape"]["shape_tags"]
        self.assertTrue(
            "runtime-upgrade" in pallet_tags or "frame-pallet" in pallet_tags,
            f"pallet tags={pallet_tags}",
        )

    # 7. Bug-class inference: equivocation, fork-choice, fraud-proof, bridge, migration.
    def test_bug_class_inference(self) -> None:
        rec_eq = self.tool.commit_to_record(
            "paritytech/substrate",
            _FIX_COMMIT_DETAILS["1111111111111111111111111111111111111111"],
        )
        rec_fc = self.tool.commit_to_record(
            "paritytech/polkadot",
            _FIX_COMMIT_DETAILS["2222222222222222222222222222222222222222"],
        )
        rec_fp = self.tool.commit_to_record(
            "paritytech/polkadot",
            _FIX_COMMIT_DETAILS["3333333333333333333333333333333333333333"],
        )
        rec_br = self.tool.commit_to_record(
            "paritytech/cumulus",
            _FIX_COMMIT_DETAILS["6666666666666666666666666666666666666666"],
        )
        rec_mig = self.tool.commit_to_record(
            "paritytech/substrate",
            _FIX_COMMIT_DETAILS["7777777777777777777777777777777777777777"],
        )
        assert rec_eq is not None and rec_fc is not None
        assert rec_fp is not None and rec_br is not None and rec_mig is not None
        self.assertEqual(rec_eq["bug_class"], "consensus-equivocation")
        self.assertEqual(rec_fc["bug_class"], "fork-choice-bug")
        self.assertEqual(rec_fp["bug_class"], "fraud-proof-bug")
        # rec_br subject says "xcm-bridge" - "xcm" matches first.
        self.assertIn(rec_br["bug_class"], {"xcm-bridge-bug", "bridge-protocol-bug"})
        # rec_mig subject has both "pallet-staking" and "storage migration"; "migration" wins per ordering.
        self.assertIn(
            rec_mig["bug_class"],
            {"storage-migration-bug", "frame-pallet-bug"},
        )

    # 8. attack_class always begins with "substrate-bug-class".
    def test_attack_class_prefix(self) -> None:
        for sha in _FIX_COMMIT_DETAILS:
            if sha == "8888888888888888888888888888888888888888":
                continue  # test-only file -> dropped
            rec = self.tool.commit_to_record(
                "paritytech/polkadot-sdk", _FIX_COMMIT_DETAILS[sha]
            )
            self.assertIsNotNone(rec, f"unexpected drop for {sha}")
            assert rec is not None
            self.assertTrue(
                rec["attack_class"].startswith("substrate-bug-class"),
                f"attack_class={rec['attack_class']} for {sha}",
            )

    # 9. Tests-only commits (only tests/ files) are dropped.
    def test_tests_only_commit_is_dropped(self) -> None:
        detail = _FIX_COMMIT_DETAILS["8888888888888888888888888888888888888888"]
        rec = self.tool.commit_to_record("paritytech/substrate", detail)
        self.assertIsNone(rec)

    # 10. End-to-end pipeline writes record.{yaml,json} pairs with repo__sha8 dir naming.
    def test_end_to_end_writes_json_and_yaml_pair(self) -> None:
        with tempfile.TemporaryDirectory(prefix="substrate-fix-e2e-") as tmp:
            out_dir = Path(tmp) / "out"
            summary = self.tool.convert(
                out_dir,
                dry_run=False,
                repos=["paritytech/polkadot-sdk"],
                pages=1,
                per_page=10,
                max_per_repo=10,
                detail_cap=10,
            )
            self.assertEqual(summary["errors"], [])
            self.assertGreater(summary["records_valid"], 0)
            yaml_files = list(out_dir.rglob("record.yaml"))
            self.assertGreater(len(yaml_files), 0)
            for yp in yaml_files:
                self.assertTrue((yp.parent / "record.json").exists())
                # Dir name format must include repo slug + sha8 separator.
                self.assertIn("__", yp.parent.name)

    # 11. Schema version pinned to v1.
    def test_schema_version_is_v1(self) -> None:
        rec = self.tool.commit_to_record(
            "paritytech/substrate",
            _FIX_COMMIT_DETAILS["1111111111111111111111111111111111111111"],
        )
        assert rec is not None
        self.assertEqual(rec["schema_version"], "auditooor.hackerman_record.v1")

    # 12. Summary tier is realtime-api.
    def test_summary_has_verification_tier_tag(self) -> None:
        with tempfile.TemporaryDirectory(prefix="substrate-fix-tier-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out",
                dry_run=True,
                repos=["paritytech/polkadot-sdk"],
                pages=1,
                per_page=10,
                max_per_repo=10,
                detail_cap=10,
            )
        self.assertEqual(summary["verification_tier"], "tier-1-verified-realtime-api")

    # 13. verification_tier=tier-1-verified-realtime-api embedded in every record's preconditions.
    def test_verification_tier_in_required_preconditions(self) -> None:
        rec = self.tool.commit_to_record(
            "paritytech/polkadot-sdk",
            _FIX_COMMIT_DETAILS["1111111111111111111111111111111111111111"],
        )
        assert rec is not None
        self.assertIn(
            "verification_tier=tier-1-verified-realtime-api",
            rec["required_preconditions"],
        )

    # 14. Per-repo cap honored across multiple repos.
    def test_per_repo_cap_honored(self) -> None:
        with tempfile.TemporaryDirectory(prefix="substrate-fix-cap-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out",
                dry_run=True,
                repos=["paritytech/polkadot-sdk", "paritytech/substrate"],
                pages=1,
                per_page=10,
                max_per_repo=2,
                detail_cap=10,
            )
        for repo, count in summary["records_per_repo"].items():
            self.assertLessEqual(count, 2, f"{repo} exceeded cap: {count}")

    # 15. Severity inference prefers consensus/finality keywords toward HIGH.
    def test_severity_inference_consensus(self) -> None:
        sev = self.tool.infer_severity("fix: grandpa finality stall", "x")
        self.assertEqual(sev, "high")
        sev2 = self.tool.infer_severity("fix: typo", "no body keywords")
        self.assertEqual(sev2, "low")

    # 16. Impact inference: equivocation collapses to enum-valid "dos" (liveness).
    def test_impact_inference_consensus_collapses_to_dos(self) -> None:
        imp = self.tool.infer_impact("fix(grandpa): equivocation slash", "double sign attack")
        self.assertEqual(imp, "dos")
        imp2 = self.tool.infer_impact("fix: runtime upgrade migration broke storage", "state corruption")
        self.assertEqual(imp2, "freeze")


if __name__ == "__main__":
    unittest.main()
