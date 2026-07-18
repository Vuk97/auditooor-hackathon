"""Unit tests for ``tools/hackerman-etl-from-solc-bugs.py``.

These tests never hit the network. They drive the miner through patched
``fetch_url`` and ``gh_api`` shims that return synthetic payloads modeled on
real ethereum/solidity API shapes (bugs.json schema + /repos/.../commits/<sha>
shape) and assert the records that come out:

* Every record validates against the v1 hackerman_record schema.
* bugs.json `uid` + `name` survive into ``source_audit_ref`` / ``record_id``.
* Commit URLs (https://github.com/ethereum/solidity/commit/<sha>) survive
  verbatim into ``attacker_action_sequence``.
* Compiler subsystem classification (yul-optimizer / via-ir-codegen / abi-codec
  / codegen) routes correctly.
* Commit-history fix-shape filter accepts compiler-domain subjects and
  rejects merge / chore / docs subjects.
* Negative verdict trips when yield < 60.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-solc-bugs.py"
VALIDATOR = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules.setdefault(spec.name, mod)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Synthetic bugs.json mirroring the real ethereum/solidity schema (uid, name,
# summary, description, link, introduced, fixed, severity, conditions).
# ---------------------------------------------------------------------------

_BUGS_JSON_FIXTURE = [
    {
        "uid": "SOL-2026-1",
        "name": "TransientStorageClearingHelperCollision",
        "summary": (
            "Clearing both storage and transient storage variables in the "
            "same contract may result in only one of these locations being "
            "cleared."
        ),
        "description": (
            "The IR-based code generator provides a set of Yul helper "
            "functions for basic operations, such as clearing, copying, "
            "encoding or type conversions. The helper name was missing the "
            "location information, which resulted in a collision between the "
            "persistent and transient storage variants for the same type."
        ),
        "link": "https://blog.soliditylang.org/2026/02/18/transient-storage-clearing-helper-collision-bug/",
        "introduced": "0.8.28",
        "fixed": "0.8.34",
        "severity": "high",
        "conditions": {"viaIR": True, "evmVersion": ">=cancun"},
    },
    {
        "uid": "SOL-2023-2",
        "name": "FullInlinerNonExpressionSplitArgumentEvaluationOrder",
        "summary": "Full inliner can re-order evaluation of side-effecting expressions.",
        "description": "The Yul Full Inliner pass mishandles non-expression split arguments and may evaluate side-effecting calls in the wrong order, leading to wrong codegen.",
        "link": "https://blog.soliditylang.org/2023/07/19/full-inliner-non-expression-split-argument-evaluation-order/",
        "introduced": "0.6.7",
        "fixed": "0.8.21",
        "severity": "low",
        "conditions": None,
    },
    {
        "uid": "SOL-2022-6",
        "name": "AbiReencodingHeadOverflowWithStaticArrayCleanup",
        "summary": "ABI reencoding of a static array overflows when cleanup is performed.",
        "description": "An overflow in the ABI re-encoder writes outside the intended head buffer when a static array is reencoded with cleanup.",
        "link": "https://blog.soliditylang.org/2022/08/08/abi-reencoding-head-overflow-bug/",
        "introduced": "0.5.8",
        "fixed": "0.8.16",
        "severity": "medium",
        "conditions": None,
    },
    {
        "uid": "SOL-2017-3",
        "name": "ECRecoverMalformedInput",
        "summary": "ecrecover returns garbage for malformed input rather than reverting.",
        "description": "Calls to ecrecover with malformed input were not validating the recovery id and could return garbage data.",
        "link": "",
        "introduced": "",
        "fixed": "0.4.14",
        "severity": "medium",
        "conditions": None,
    },
    {
        "uid": "SOL-2016-1",
        "name": "AncientCompiler",
        "summary": "Old solc releases predating 0.3.0 are tracked as a class.",
        "description": "Use of an ancient compiler version.",
        "link": "",
        "introduced": "",
        "fixed": "0.3.0",
        "severity": "high",
        "conditions": None,
    },
]


# ---------------------------------------------------------------------------
# Synthetic commit-history fixtures mirroring /repos/ethereum/solidity/commits
# list shape + /commits/<sha> detail shape.
# ---------------------------------------------------------------------------

_COMMIT_LIST: List[Dict[str, Any]] = [
    {
        "sha": "1111111111111111111111111111111111111111",
        "commit": {
            "message": (
                "Fix incorrect ABI encoding for tuple of bytes\n\n"
                "Wrong codegen for abi.encode((bytes, bytes)) produced "
                "misaligned offsets, miscompiling production contracts."
            ),
            "author": {"date": "2023-04-01T08:00:00Z"},
            "committer": {"date": "2023-04-01T08:00:00Z"},
        },
    },
    {
        "sha": "2222222222222222222222222222222222222222",
        "commit": {
            "message": "SSA-CFG: Fix stack adjustments for codegen on conditional jump\n",
            "author": {"date": "2024-09-13T12:00:00Z"},
            "committer": {"date": "2024-09-13T12:00:00Z"},
        },
    },
    {
        "sha": "3333333333333333333333333333333333333333",
        "commit": {
            "message": "Yul optimizer: guard SCCP pass against missing terminator",
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
            "message": "Merge pull request #16574 from tavian-dev/fix-isoltest-failafter-stripping",
            "author": {"date": "2024-08-15T08:00:00Z"},
            "committer": {"date": "2024-08-15T08:00:00Z"},
        },
    },
    {
        "sha": "6666666666666666666666666666666666666666",
        "commit": {
            "message": "fix[via-ir]: guard against ICE on empty contract source",
            "author": {"date": "2024-03-15T08:00:00Z"},
            "committer": {"date": "2024-03-15T08:00:00Z"},
        },
    },
    {
        "sha": "7777777777777777777777777777777777777777",
        "commit": {
            "message": "test: extend yul test harness",  # tests-only -> dropped
            "author": {"date": "2024-04-15T08:00:00Z"},
            "committer": {"date": "2024-04-15T08:00:00Z"},
        },
    },
]


_COMMIT_DETAILS: Dict[str, Dict[str, Any]] = {
    "1111111111111111111111111111111111111111": {
        "sha": "1111111111111111111111111111111111111111",
        "parents": [{"sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],
        "commit": {
            "message": (
                "Fix incorrect ABI encoding for tuple of bytes\n\n"
                "Wrong codegen for abi.encode((bytes, bytes))."
            ),
            "author": {"date": "2023-04-01T08:00:00Z"},
            "committer": {"date": "2023-04-01T08:00:00Z"},
        },
        "files": [
            {
                "filename": "libsolidity/codegen/ABIFunctions.cpp",
                "status": "modified",
                "additions": 4,
                "deletions": 1,
                "patch": (
                    "@@ -1,3 +1,5 @@\n"
                    "+void ABIFunctions::abiEncodeTuple()\n"
                    "+    solAssert(tuple.size() == 2);\n"
                ),
            },
        ],
    },
    "2222222222222222222222222222222222222222": {
        "sha": "2222222222222222222222222222222222222222",
        "parents": [{"sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],
        "commit": {
            "message": "SSA-CFG: Fix stack adjustments for codegen on conditional jump",
            "author": {"date": "2024-09-13T12:00:00Z"},
            "committer": {"date": "2024-09-13T12:00:00Z"},
        },
        "files": [
            {
                "filename": "libyul/backends/evm/SSACFGLiveness.cpp",
                "status": "modified",
                "additions": 5,
                "deletions": 2,
                "patch": (
                    "@@ -10,6 +10,9 @@\n"
                    "+void SSACFGLiveness::adjustStack()\n"
                    "+    solAssert(block.terminator != nullptr);\n"
                ),
            },
        ],
    },
    "3333333333333333333333333333333333333333": {
        "sha": "3333333333333333333333333333333333333333",
        "parents": [{"sha": "cccccccccccccccccccccccccccccccccccccccc"}],
        "commit": {
            "message": "Yul optimizer: guard SCCP pass against missing terminator",
            "author": {"date": "2024-02-15T08:00:00Z"},
            "committer": {"date": "2024-02-15T08:00:00Z"},
        },
        "files": [
            {
                "filename": "libyul/optimiser/SCCP.cpp",
                "status": "modified",
                "additions": 3,
                "deletions": 0,
                "patch": (
                    "@@ -1,3 +1,6 @@\n"
                    "+void SCCP::run()\n"
                    "+    if (!block.terminator) return;\n"
                ),
            },
        ],
    },
    "6666666666666666666666666666666666666666": {
        "sha": "6666666666666666666666666666666666666666",
        "parents": [{"sha": "ffffffffffffffffffffffffffffffffffffffff"}],
        "commit": {
            "message": "fix[via-ir]: guard against ICE on empty contract source",
            "author": {"date": "2024-03-15T08:00:00Z"},
            "committer": {"date": "2024-03-15T08:00:00Z"},
        },
        "files": [
            {
                "filename": "libsolidity/codegen/ir/IRGenerator.cpp",
                "status": "modified",
                "additions": 3,
                "deletions": 0,
                "patch": (
                    "@@ -1,3 +1,6 @@\n"
                    "+void IRGenerator::compile()\n"
                    "+    if (sources.empty()) throw CompilerError(\"empty\");\n"
                ),
            },
        ],
    },
    "7777777777777777777777777777777777777777": {
        "sha": "7777777777777777777777777777777777777777",
        "parents": [{"sha": "0000000000000000000000000000000000000001"}],
        "commit": {
            "message": "test: extend yul test harness",
            "author": {"date": "2024-04-15T08:00:00Z"},
            "committer": {"date": "2024-04-15T08:00:00Z"},
        },
        "files": [
            {
                "filename": "test/libyul/yulSyntaxTests/foo.yul",
                "status": "modified",
                "additions": 1,
                "deletions": 1,
                "patch": "-old\n+new",
            },
        ],
    },
}


class _FakeGhApiState:
    def __init__(self) -> None:
        self.calls: List[str] = []

    def gh_api(self, path: str, paginate: bool = False) -> Any:
        self.calls.append(path)
        if "/commits?per_page" in path:
            if "page=1" in path or "page=" not in path:
                return _COMMIT_LIST
            return []
        for sha, detail in _COMMIT_DETAILS.items():
            if path.endswith(f"/commits/{sha}"):
                return detail
        return None


class HackermanEtlFromSolcBugsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_solc_bugs")
        self.validator = _load(VALIDATOR, "_hackerman_record_validate_for_solc_bugs")
        self.fake = _FakeGhApiState()
        self._orig_gh_api = self.tool.gh_api
        self.tool.gh_api = self.fake.gh_api  # type: ignore[assignment]
        self._bugs_json_text = json.dumps(_BUGS_JSON_FIXTURE)

    def tearDown(self) -> None:
        self.tool.gh_api = self._orig_gh_api  # type: ignore[assignment]

    # ------------------------------------------------------------------
    # 1. bugs.json-only run validates and emits one record per entry.
    # ------------------------------------------------------------------
    def test_bugs_json_only_validates_and_emits(self) -> None:
        recs = self.tool.mine_bugs_json(override_text=self._bugs_json_text)
        self.assertEqual(len(recs), len(_BUGS_JSON_FIXTURE))
        schema = self.validator.load_schema()
        for r in recs:
            verrs = self.validator.validate_doc(r, schema)
            self.assertEqual(verrs, [], f"record {r['record_id']} errors: {verrs}")

    # ------------------------------------------------------------------
    # 2. uid + name survive into source_audit_ref and record_id.
    # ------------------------------------------------------------------
    def test_uid_and_name_survive(self) -> None:
        recs = self.tool.mine_bugs_json(override_text=self._bugs_json_text)
        by_uid = {r["source_audit_ref"]: r for r in recs}
        self.assertIn("solc-bugs-json:SOL-2026-1:TransientStorageClearingHelperCollision", by_uid)
        rec = by_uid["solc-bugs-json:SOL-2026-1:TransientStorageClearingHelperCollision"]
        self.assertTrue(rec["record_id"].startswith("solc-compiler:sol-2026-1:"))
        self.assertIn("SOL-2026-1", rec["attacker_action_sequence"])
        self.assertIn("TransientStorageClearingHelperCollision", rec["attacker_action_sequence"])

    # ------------------------------------------------------------------
    # 3. canonical bugs.json anchor URL embedded in attacker_action_sequence.
    # ------------------------------------------------------------------
    def test_canonical_bugs_json_anchor_url_embedded(self) -> None:
        recs = self.tool.mine_bugs_json(override_text=self._bugs_json_text)
        for r in recs:
            uid = r["source_audit_ref"].split(":")[1]
            self.assertIn(
                f"https://github.com/ethereum/solidity/blob/develop/docs/bugs.json#{uid}",
                r["attacker_action_sequence"],
            )

    # ------------------------------------------------------------------
    # 4. Disclosure link (blog) survives when present in bugs.json entry.
    # ------------------------------------------------------------------
    def test_disclosure_link_preserved_when_present(self) -> None:
        recs = self.tool.mine_bugs_json(override_text=self._bugs_json_text)
        by_uid = {r["source_audit_ref"]: r for r in recs}
        rec = by_uid["solc-bugs-json:SOL-2026-1:TransientStorageClearingHelperCollision"]
        self.assertIn(
            "https://blog.soliditylang.org/2026/02/18/transient-storage-clearing-helper-collision-bug/",
            rec["attacker_action_sequence"],
        )

    # ------------------------------------------------------------------
    # 5. Severity normalization: 'very low' -> info, 'medium/high' -> high,
    #    'low/medium' -> medium.
    # ------------------------------------------------------------------
    def test_severity_normalization(self) -> None:
        self.assertEqual(self.tool.normalize_severity("very low"), "info")
        self.assertEqual(self.tool.normalize_severity("medium/high"), "high")
        self.assertEqual(self.tool.normalize_severity("low/medium"), "medium")
        self.assertEqual(self.tool.normalize_severity("high"), "high")
        self.assertEqual(self.tool.normalize_severity("low"), "low")
        self.assertEqual(self.tool.normalize_severity(""), "low")

    # ------------------------------------------------------------------
    # 6. Bug-class inference routes the transient-storage entry.
    # ------------------------------------------------------------------
    def test_bug_class_routes_transient_storage(self) -> None:
        recs = self.tool.mine_bugs_json(override_text=self._bugs_json_text)
        by_uid = {r["source_audit_ref"]: r for r in recs}
        rec = by_uid["solc-bugs-json:SOL-2026-1:TransientStorageClearingHelperCollision"]
        self.assertEqual(rec["bug_class"], "transient-storage-bug")
        self.assertTrue(rec["attack_class"].startswith("solc-compiler-bug-class:"))

    # ------------------------------------------------------------------
    # 7. Bug-class inference routes Yul/inliner correctly.
    # ------------------------------------------------------------------
    def test_bug_class_routes_inliner(self) -> None:
        recs = self.tool.mine_bugs_json(override_text=self._bugs_json_text)
        by_uid = {r["source_audit_ref"]: r for r in recs}
        rec = by_uid["solc-bugs-json:SOL-2023-2:FullInlinerNonExpressionSplitArgumentEvaluationOrder"]
        self.assertEqual(rec["bug_class"], "inliner-pass-bug")

    # ------------------------------------------------------------------
    # 8. Fix-shape filter accepts compiler-domain subjects and rejects
    #    merges / docs / chore.
    # ------------------------------------------------------------------
    def test_is_fix_shape_filter(self) -> None:
        self.assertTrue(self.tool.is_fix_shape("Fix SMT Encoder treatment of constant", ""))
        self.assertTrue(self.tool.is_fix_shape("SSA-CFG: Fix stack adjustments for codegen", ""))
        self.assertTrue(self.tool.is_fix_shape("Yul optimizer: guard SCCP pass", ""))
        self.assertTrue(self.tool.is_fix_shape("fix[via-ir]: ICE on empty source", ""))
        self.assertFalse(self.tool.is_fix_shape("docs: typo in README", ""))
        self.assertFalse(self.tool.is_fix_shape("chore: bump version", ""))
        self.assertFalse(self.tool.is_fix_shape("Merge pull request #16574 from foo", ""))
        self.assertFalse(self.tool.is_fix_shape("Pin pnpm to v9", ""))
        self.assertFalse(self.tool.is_fix_shape("Introduce typeWhenAttached helper", ""))

    # ------------------------------------------------------------------
    # 9. Commit -> record: subsystem classification, URL, schema-valid.
    # ------------------------------------------------------------------
    def test_commit_to_record_routes_subsystem_and_url(self) -> None:
        rec_abi = self.tool.commit_to_record(
            "ethereum/solidity",
            _COMMIT_DETAILS["1111111111111111111111111111111111111111"],
        )
        rec_yul = self.tool.commit_to_record(
            "ethereum/solidity",
            _COMMIT_DETAILS["3333333333333333333333333333333333333333"],
        )
        rec_viair = self.tool.commit_to_record(
            "ethereum/solidity",
            _COMMIT_DETAILS["6666666666666666666666666666666666666666"],
        )
        for r in (rec_abi, rec_yul, rec_viair):
            assert r is not None
            self.assertEqual(r["target_language"], "solidity")
            self.assertEqual(r["target_repo"], "ethereum/solidity")
            self.assertTrue(r["source_audit_ref"].startswith("git-mining:ethereum/solidity@"))
            self.assertIn(
                "https://github.com/ethereum/solidity/commit/",
                r["attacker_action_sequence"],
            )
        # Subsystems shape_tags
        assert rec_abi is not None
        self.assertIn("abi-codec", rec_abi["function_shape"]["shape_tags"])
        assert rec_yul is not None
        self.assertIn("yul-optimizer", rec_yul["function_shape"]["shape_tags"])
        assert rec_viair is not None
        self.assertIn("via-ir-codegen", rec_viair["function_shape"]["shape_tags"])

    # ------------------------------------------------------------------
    # 10. Tests-only commit (only test/ files) is dropped.
    # ------------------------------------------------------------------
    def test_tests_only_commit_dropped(self) -> None:
        rec = self.tool.commit_to_record(
            "ethereum/solidity",
            _COMMIT_DETAILS["7777777777777777777777777777777777777777"],
        )
        self.assertIsNone(rec)

    # ------------------------------------------------------------------
    # 11. End-to-end pipeline writes record.{yaml,json} pairs and reports
    #     records_by_source counts both streams.
    # ------------------------------------------------------------------
    def test_end_to_end_writes_pairs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="solc-bugs-e2e-") as tmp:
            out_dir = Path(tmp) / "out"
            summary = self.tool.convert(
                out_dir,
                dry_run=False,
                pages=1,
                per_page=10,
                max_records=10,
                detail_cap=10,
                bugs_json_override=self._bugs_json_text,
            )
            self.assertEqual(summary["errors"], [], f"errors={summary['errors']}")
            self.assertGreater(summary["records_valid"], 0)
            yaml_files = list(out_dir.rglob("record.yaml"))
            self.assertGreater(len(yaml_files), 0)
            for yp in yaml_files:
                self.assertTrue((yp.parent / "record.json").exists())
            self.assertGreater(summary["records_by_source"]["bugs_json"], 0)
            self.assertGreater(summary["records_by_source"]["commit_history"], 0)

    # ------------------------------------------------------------------
    # 12. Schema-version pinned to v1, verification_tier in summary.
    # ------------------------------------------------------------------
    def test_schema_version_and_verification_tier(self) -> None:
        recs = self.tool.mine_bugs_json(override_text=self._bugs_json_text)
        for r in recs:
            self.assertEqual(r["schema_version"], "auditooor.hackerman_record.v1")
            self.assertIn(
                "verification_tier=tier-1-verified-realtime-api",
                r["required_preconditions"],
            )
        with tempfile.TemporaryDirectory(prefix="solc-bugs-tier-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out",
                dry_run=True,
                pages=1,
                per_page=10,
                max_records=10,
                detail_cap=10,
                skip_commits=True,
                bugs_json_override=self._bugs_json_text,
            )
        self.assertEqual(summary["verification_tier"], "tier-1-verified-realtime-api")

    # ------------------------------------------------------------------
    # 13. Negative verdict fires when yield < 60.
    # ------------------------------------------------------------------
    def test_negative_verdict_when_yield_low(self) -> None:
        # Force commits OFF and feed only 5 bugs.json entries -> 5 records,
        # well below 60. Expect negative_verdict True.
        with tempfile.TemporaryDirectory(prefix="solc-bugs-neg-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out",
                dry_run=True,
                pages=0,
                per_page=10,
                max_records=10,
                detail_cap=10,
                skip_commits=True,
                bugs_json_override=self._bugs_json_text,
            )
        self.assertTrue(summary["negative_verdict"])
        self.assertEqual(summary["records_by_source"]["bugs_json"], 5)
        self.assertEqual(summary["records_by_source"]["commit_history"], 0)

    # ------------------------------------------------------------------
    # 14. Empty bugs.json text yields zero records (graceful fail).
    # ------------------------------------------------------------------
    def test_empty_bugs_json_yields_zero(self) -> None:
        import contextlib
        import io
        recs = self.tool.mine_bugs_json(override_text="")
        self.assertEqual(recs, [])
        with contextlib.redirect_stderr(io.StringIO()):
            recs2 = self.tool.mine_bugs_json(override_text="not json")
        self.assertEqual(recs2, [])

    # ------------------------------------------------------------------
    # 15. Pre-fix release window appears verbatim in preconditions.
    # ------------------------------------------------------------------
    def test_release_window_in_preconditions(self) -> None:
        recs = self.tool.mine_bugs_json(override_text=self._bugs_json_text)
        by_uid = {r["source_audit_ref"]: r for r in recs}
        rec = by_uid["solc-bugs-json:SOL-2026-1:TransientStorageClearingHelperCollision"]
        joined = " | ".join(rec["required_preconditions"])
        self.assertIn("0.8.28", joined)  # introduced
        self.assertIn("0.8.34", joined)  # fixed


if __name__ == "__main__":
    unittest.main()
