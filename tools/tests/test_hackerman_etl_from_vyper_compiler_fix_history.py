"""Unit tests for ``tools/hackerman-etl-from-vyper-compiler-fix-history.py``.

These tests never call ``gh api``. They drive the miner through a patched
``gh_api`` function with synthetic commit-shaped payloads (modeled on the
real fields returned by the GitHub REST endpoint for vyperlang/vyper) and
assert the records that come out:

* Validate against the v1 schema.
* Preserve the commit SHA / URL verbatim in ``source_audit_ref`` and
  ``attacker_action_sequence``.
* Classify compiler-subsystem (venom-ir, codegen, abi-codec, ...) correctly.
* Identify compiler-class bugs (miscompile, ICE, storage-layout, ...).
* Drop non-compiler / test-only commits.
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-vyper-compiler-fix-history.py"
VALIDATOR = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules.setdefault(spec.name, mod)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Fixtures mimicking real vyperlang/vyper gh-api shapes. Wave-1 schema fields
# preserved verbatim from a live `gh api /repos/vyperlang/vyper/commits/<sha>`
# call (file paths and patch hunks are realistic).
# ---------------------------------------------------------------------------

_FIX_COMMIT_LIST: List[Dict[str, Any]] = [
    {
        "sha": "1111111111111111111111111111111111111111",
        "commit": {
            "message": (
                "fix[venom]: fix store elimination pass\n\n"
                "Fixes incorrect codegen in the Venom store-elimination "
                "pass that miscompiles certain SLOAD / SSTORE sequences."
            ),
            "author": {"date": "2024-09-13T12:00:00Z"},
            "committer": {"date": "2024-09-13T12:00:00Z"},
        },
    },
    {
        "sha": "2222222222222222222222222222222222222222",
        "commit": {
            "message": (
                "fix[codegen]: incorrect ABI encoding for tuple of bytes\n\n"
                "Wrong codegen for `abi_encode((bytes, bytes))` produced "
                "misaligned offsets, miscompiling production contracts."
            ),
            "author": {"date": "2023-04-01T08:00:00Z"},
            "committer": {"date": "2023-04-01T08:00:00Z"},
        },
    },
    {
        "sha": "3333333333333333333333333333333333333333",
        "commit": {
            "message": "revert[venom]: rollback dft-pass change that broke storage layout",
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
            "message": "fix[stdlib]: validate `IERC4626` signatures",
            "author": {"date": "2024-06-15T08:00:00Z"},
            "committer": {"date": "2024-06-15T08:00:00Z"},
        },
    },
    {
        "sha": "7777777777777777777777777777777777777777",
        "commit": {
            "message": "fix[tool]: guard against ICE on empty contract source",
            "author": {"date": "2024-03-15T08:00:00Z"},
            "committer": {"date": "2024-03-15T08:00:00Z"},
        },
    },
    {
        "sha": "8888888888888888888888888888888888888888",
        "commit": {
            "message": "fix[ci]: tests-only typo in pytest harness",
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
                "fix[venom]: fix store elimination pass\n\n"
                "Fixes incorrect codegen in the Venom store-elimination "
                "pass that miscompiles certain SLOAD / SSTORE sequences."
            ),
            "author": {"date": "2024-09-13T12:00:00Z"},
            "committer": {"date": "2024-09-13T12:00:00Z"},
        },
        "files": [
            {
                "filename": "vyper/venom/passes/store_elimination.py",
                "status": "modified",
                "additions": 5,
                "deletions": 2,
                "patch": (
                    "@@ -10,6 +10,9 @@\n"
                    "+def _store_elimination(bb: BasicBlock):\n"
                    "+    assert bb.terminator is not None\n"
                    "+    if not bb.instructions:\n"
                ),
            },
        ],
    },
    "2222222222222222222222222222222222222222": {
        "sha": "2222222222222222222222222222222222222222",
        "parents": [{"sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],
        "commit": {
            "message": (
                "fix[codegen]: incorrect ABI encoding for tuple of bytes\n\n"
                "Wrong codegen for `abi_encode((bytes, bytes))` produced "
                "misaligned offsets, miscompiling production contracts."
            ),
            "author": {"date": "2023-04-01T08:00:00Z"},
            "committer": {"date": "2023-04-01T08:00:00Z"},
        },
        "files": [
            {
                "filename": "vyper/codegen/abi_encoder.py",
                "status": "modified",
                "additions": 4,
                "deletions": 1,
                "patch": (
                    "@@ -1,3 +1,5 @@\n"
                    "+def abi_encode(args):\n"
                    "+    assert isinstance(args, tuple)\n"
                ),
            },
        ],
    },
    "3333333333333333333333333333333333333333": {
        "sha": "3333333333333333333333333333333333333333",
        "parents": [{"sha": "cccccccccccccccccccccccccccccccccccccccc"}],
        "commit": {
            "message": "revert[venom]: rollback dft-pass change that broke storage layout",
            "author": {"date": "2024-02-15T08:00:00Z"},
            "committer": {"date": "2024-02-15T08:00:00Z"},
        },
        "files": [
            {
                "filename": "vyper/venom/passes/dft.py",
                "status": "modified",
                "additions": 1,
                "deletions": 5,
                "patch": (
                    "@@ -1,5 +1,1 @@\n"
                    "-def dft_pass(bb):\n"
                    "-    storage_layout.flatten(bb)\n"
                    "+def dft_pass(bb):\n"
                ),
            },
        ],
    },
    "6666666666666666666666666666666666666666": {
        "sha": "6666666666666666666666666666666666666666",
        "parents": [{"sha": "ffffffffffffffffffffffffffffffffffffffff"}],
        "commit": {
            "message": "fix[stdlib]: validate `IERC4626` signatures",
            "author": {"date": "2024-06-15T08:00:00Z"},
            "committer": {"date": "2024-06-15T08:00:00Z"},
        },
        "files": [
            {
                "filename": "vyper/builtin_functions/signatures.py",
                "status": "modified",
                "additions": 6,
                "deletions": 1,
                "patch": (
                    "@@ -1,5 +1,11 @@\n"
                    "+def validate_ierc4626(sig):\n"
                    "+    assert sig in EXPECTED_SIGS\n"
                ),
            },
        ],
    },
    "7777777777777777777777777777777777777777": {
        "sha": "7777777777777777777777777777777777777777",
        "parents": [{"sha": "0000000000000000000000000000000000000001"}],
        "commit": {
            "message": "fix[tool]: guard against ICE on empty contract source",
            "author": {"date": "2024-03-15T08:00:00Z"},
            "committer": {"date": "2024-03-15T08:00:00Z"},
        },
        "files": [
            {
                "filename": "vyper/cli/vyper_compile.py",
                "status": "modified",
                "additions": 3,
                "deletions": 0,
                "patch": (
                    "@@ -1,3 +1,6 @@\n"
                    "+def compile_files(files):\n"
                    "+    if not files:\n"
                    "+        raise CompilerError('empty source')\n"
                ),
            },
        ],
    },
    "8888888888888888888888888888888888888888": {
        # tests-only commit -> should be dropped (no compiler file touched)
        "sha": "8888888888888888888888888888888888888888",
        "parents": [{"sha": "0000000000000000000000000000000000000002"}],
        "commit": {
            "message": "fix[ci]: tests-only typo in pytest harness",
            "author": {"date": "2024-04-15T08:00:00Z"},
            "committer": {"date": "2024-04-15T08:00:00Z"},
        },
        "files": [
            {
                "filename": "tests/unit/test_harness.py",
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


class HackermanEtlFromVyperCompilerFixHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_vyper_compiler_fix_history")
        self.validator = _load(
            VALIDATOR, "_hackerman_record_validate_for_vyper_compiler_fix_history"
        )
        self.fake = _FakeGhApiState()
        self._orig_gh_api = self.tool.gh_api
        self.tool.gh_api = self.fake.gh_api  # type: ignore[assignment]

    def tearDown(self) -> None:
        self.tool.gh_api = self._orig_gh_api  # type: ignore[assignment]

    # ------------------------------------------------------------------
    # 1. Dry-run emits records with zero validator errors.
    # ------------------------------------------------------------------
    def test_dry_run_emits_records_with_zero_errors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vyper-fix-dry-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out",
                dry_run=True,
                repos=["vyperlang/vyper"],
                pages=1,
                per_page=10,
                max_records=10,
                detail_cap=10,
            )
        self.assertEqual(summary["errors"], [], f"errors={summary['errors']}")
        self.assertGreater(summary["records_valid"], 0)
        self.assertEqual(summary["records_total"], summary["records_valid"])

    # ------------------------------------------------------------------
    # 2. Negative filter drops doc / chore / prettier subjects.
    # ------------------------------------------------------------------
    def test_negative_filter_drops_non_protocol_churn(self) -> None:
        self.assertFalse(self.tool.is_fix_shape("docs: typo in README", "x"))
        self.assertFalse(self.tool.is_fix_shape("chore: prettier formatting", "x"))

    # ------------------------------------------------------------------
    # 3. Positive filter admits compiler fix-shapes including ICE / miscompile.
    # ------------------------------------------------------------------
    def test_positive_filter_admits_fix_shapes(self) -> None:
        self.assertTrue(self.tool.is_fix_shape("fix[venom]: fix store elimination", "x"))
        self.assertTrue(
            self.tool.is_fix_shape(
                "audit: validate IERC4626 signatures", "x"
            )
        )
        self.assertTrue(self.tool.is_fix_shape("revert: rollback prior change", "x"))
        self.assertTrue(self.tool.is_fix_shape("security: patch ICE on empty source", "x"))
        self.assertTrue(self.tool.is_fix_shape("fix: miscompile in optimizer", "x"))

    # ------------------------------------------------------------------
    # 4. Detector seed extraction: Python-style asserts / type-checks / IR ops.
    # ------------------------------------------------------------------
    def test_detector_seed_extracts_assert(self) -> None:
        patch = "+    assert bb.terminator is not None"
        seed = self.tool.extract_detector_seed(patch, "fix[venom]: pass guard")
        self.assertIn("added assert bb.terminator is not None", seed)

    def test_detector_seed_extracts_ir_op(self) -> None:
        patch = "+    return IRnode.from_list(['sstore', addr, val])"
        seed = self.tool.extract_detector_seed(patch, "fix[codegen]: sstore order")
        # Either IRnode or sstore (or both) should fire; verify at least
        # one IR-op signal is emitted into the seed bag.
        self.assertIn("touched ir op", seed.lower())

    def test_detector_seed_extracts_venom_pass(self) -> None:
        patch = "+from vyper.venom.passes.sccp import SCCP"
        seed = self.tool.extract_detector_seed(patch, "fix[venom]: sccp guard")
        self.assertIn("venom pass", seed.lower())

    def test_detector_seed_fallback_is_nonempty(self) -> None:
        seed = self.tool.extract_detector_seed("@@ no body @@\n", "merge pr 1")
        self.assertTrue(seed)
        self.assertGreater(len(seed), 3)

    # ------------------------------------------------------------------
    # 5. Record shape: every required field present, source_audit_ref is
    #    git-mining:<repo>@<full-sha>, commit URL embedded in action seq.
    # ------------------------------------------------------------------
    def test_record_shape_has_source_audit_ref_and_url(self) -> None:
        detail = _FIX_COMMIT_DETAILS["1111111111111111111111111111111111111111"]
        rec = self.tool.commit_to_record("vyperlang/vyper", detail)
        assert rec is not None
        self.assertTrue(
            rec["source_audit_ref"].startswith("git-mining:vyperlang/vyper@")
        )
        self.assertTrue(rec["record_id"].startswith("git-mining:vyperlang-vyper:"))
        self.assertIn(
            "https://github.com/vyperlang/vyper/commit/"
            "1111111111111111111111111111111111111111",
            rec["attacker_action_sequence"],
        )
        self.assertEqual(rec["target_language"], "vyper")
        self.assertEqual(rec["target_repo"], "vyperlang/vyper")
        schema = self.validator.load_schema()
        verrs = self.validator.validate_doc(rec, schema)
        self.assertEqual(verrs, [])

    # ------------------------------------------------------------------
    # 6. Subsystem classification: venom-ir vs codegen vs stdlib vs CLI.
    # ------------------------------------------------------------------
    def test_subsystem_classification_venom_codegen_stdlib_cli(self) -> None:
        rec_venom = self.tool.commit_to_record(
            "vyperlang/vyper",
            _FIX_COMMIT_DETAILS["1111111111111111111111111111111111111111"],
        )
        rec_codegen = self.tool.commit_to_record(
            "vyperlang/vyper",
            _FIX_COMMIT_DETAILS["2222222222222222222222222222222222222222"],
        )
        rec_stdlib = self.tool.commit_to_record(
            "vyperlang/vyper",
            _FIX_COMMIT_DETAILS["6666666666666666666666666666666666666666"],
        )
        rec_cli = self.tool.commit_to_record(
            "vyperlang/vyper",
            _FIX_COMMIT_DETAILS["7777777777777777777777777777777777777777"],
        )
        for rec in (rec_venom, rec_codegen, rec_stdlib, rec_cli):
            assert rec is not None
        # rec_venom subsystem-tag is in shape_tags.
        venom_tags = rec_venom["function_shape"]["shape_tags"]
        self.assertIn("venom-ir", venom_tags)
        codegen_tags = rec_codegen["function_shape"]["shape_tags"]
        self.assertIn("codegen", codegen_tags)
        stdlib_tags = rec_stdlib["function_shape"]["shape_tags"]
        self.assertIn("stdlib-builtin", stdlib_tags)
        cli_tags = rec_cli["function_shape"]["shape_tags"]
        self.assertIn("cli-frontend", cli_tags)

    # ------------------------------------------------------------------
    # 7. Bug-class inference: venom-ir-bug, codegen-miscompilation, stdlib,
    #    ICE class.
    # ------------------------------------------------------------------
    def test_bug_class_inference(self) -> None:
        rec_venom = self.tool.commit_to_record(
            "vyperlang/vyper",
            _FIX_COMMIT_DETAILS["1111111111111111111111111111111111111111"],
        )
        rec_codegen = self.tool.commit_to_record(
            "vyperlang/vyper",
            _FIX_COMMIT_DETAILS["2222222222222222222222222222222222222222"],
        )
        rec_ice = self.tool.commit_to_record(
            "vyperlang/vyper",
            _FIX_COMMIT_DETAILS["7777777777777777777777777777777777777777"],
        )
        assert rec_venom is not None
        assert rec_codegen is not None
        assert rec_ice is not None
        self.assertEqual(rec_venom["bug_class"], "venom-ir-bug")
        self.assertEqual(rec_codegen["bug_class"], "codegen-miscompilation")
        self.assertEqual(rec_ice["bug_class"], "internal-compiler-error")

    # ------------------------------------------------------------------
    # 8. attack_class always begins with "vyper-compiler-bug-class".
    # ------------------------------------------------------------------
    def test_attack_class_prefix(self) -> None:
        for sha in _FIX_COMMIT_DETAILS:
            if sha == "8888888888888888888888888888888888888888":
                continue  # test-only file -> dropped
            rec = self.tool.commit_to_record(
                "vyperlang/vyper", _FIX_COMMIT_DETAILS[sha]
            )
            self.assertIsNotNone(rec, f"unexpected drop for {sha}")
            assert rec is not None
            self.assertTrue(
                rec["attack_class"].startswith("vyper-compiler-bug-class"),
                f"attack_class={rec['attack_class']} for {sha}",
            )

    # ------------------------------------------------------------------
    # 9. Tests-only commits (no vyper/... source change) are dropped.
    # ------------------------------------------------------------------
    def test_tests_only_commit_is_dropped(self) -> None:
        detail = _FIX_COMMIT_DETAILS["8888888888888888888888888888888888888888"]
        rec = self.tool.commit_to_record("vyperlang/vyper", detail)
        self.assertIsNone(rec)

    # ------------------------------------------------------------------
    # 10. End-to-end pipeline writes record.{yaml,json} pairs.
    # ------------------------------------------------------------------
    def test_end_to_end_writes_json_and_yaml_pair(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vyper-fix-e2e-") as tmp:
            out_dir = Path(tmp) / "out"
            summary = self.tool.convert(
                out_dir,
                dry_run=False,
                repos=["vyperlang/vyper"],
                pages=1,
                per_page=10,
                max_records=10,
                detail_cap=10,
            )
            self.assertEqual(summary["errors"], [])
            self.assertGreater(summary["records_valid"], 0)
            yaml_files = list(out_dir.rglob("record.yaml"))
            self.assertGreater(len(yaml_files), 0)
            for yp in yaml_files:
                self.assertTrue((yp.parent / "record.json").exists())

    # ------------------------------------------------------------------
    # 11. Schema version pinned to v1.
    # ------------------------------------------------------------------
    def test_schema_version_is_v1(self) -> None:
        rec = self.tool.commit_to_record(
            "vyperlang/vyper",
            _FIX_COMMIT_DETAILS["1111111111111111111111111111111111111111"],
        )
        assert rec is not None
        self.assertEqual(rec["schema_version"], "auditooor.hackerman_record.v1")

    # ------------------------------------------------------------------
    # 12. Summary tier is realtime-api.
    # ------------------------------------------------------------------
    def test_summary_has_verification_tier_tag(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vyper-fix-tier-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out",
                dry_run=True,
                repos=["vyperlang/vyper"],
                pages=1,
                per_page=10,
                max_records=10,
                detail_cap=10,
            )
        self.assertEqual(summary["verification_tier"], "tier-1-verified-realtime-api")

    # ------------------------------------------------------------------
    # 13. verification_tier=tier-1-verified-realtime-api is embedded in
    #     required_preconditions of every record.
    # ------------------------------------------------------------------
    def test_verification_tier_in_required_preconditions(self) -> None:
        rec = self.tool.commit_to_record(
            "vyperlang/vyper",
            _FIX_COMMIT_DETAILS["1111111111111111111111111111111111111111"],
        )
        assert rec is not None
        self.assertIn(
            "verification_tier=tier-1-verified-realtime-api",
            rec["required_preconditions"],
        )


if __name__ == "__main__":
    unittest.main()
