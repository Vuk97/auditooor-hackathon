"""Tests for the Wave-2 vault callable index opt-in path (PR #726).

Spec: ``docs/WAVE2_VAULT_CALLABLE_PERF_OPTIMIZATION_SPEC_2026-05-16.md``.

The three slow callables (``vault_corpus_search`` /
``vault_corpus_subtree_summary`` / ``vault_attack_class_evidence_v2``)
walk ``audit/corpus_tags/tags/**`` per invocation. The 11 derived
index files at ``audit/corpus_tags/index/by_*.jsonl`` are NOT
consulted by the existing path. This module exercises the new
opt-in index path:

- Helper unit tests (``_corpus_index_*``): row streaming, predicate
  picker, candidate-pool resolver, env-var opt-in toggle.
- Integration tests on ``vault_corpus_search``:
  - opt-in ON + index file present + index-serviceable predicate ->
    returns identical envelope (same ``context_pack_hash``) as the
    walk path; produces the same matched record set.
  - opt-in ON + index file missing -> falls back to walk path
    transparently.
  - opt-in ON + no index-serviceable predicate (substring-only
    query) -> falls back to walk path.
  - opt-in OFF (env var unset / false) -> walk path used regardless
    of index presence.

The fixture tags tree + projected index file are built in
``setUp``; the test asserts byte-identical envelopes between
``USE_INDEX=1`` and ``USE_INDEX=0`` for each query shape.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "vault_mcp_server_index_opt_in_test", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


def _record_reentrancy_aave() -> dict[str, Any]:
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": "lending:aave-v3:r1",
        "source_audit_ref": "https://example.test/aave-r1",
        "target_repo": "aave/aave-v3-core",
        "target_domain": "lending",
        "target_language": "solidity",
        "attack_class": "reentrancy-external-call",
        "bug_class": "smart-contract-lending-vulnerability",
        "severity_at_finding": "high",
    }


def _record_oracle_chainlink() -> dict[str, Any]:
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": "oracle:chainlink:r2",
        "source_audit_ref": "https://example.test/chainlink-r2",
        "target_repo": "smartcontractkit/chainlink",
        "target_domain": "oracle",
        "target_language": "solidity",
        "attack_class": "stale-or-manipulated-oracle",
        "bug_class": "oracle-manipulation",
        "severity_at_finding": "high",
    }


def _record_reentrancy_solend() -> dict[str, Any]:
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": "lending:solend:r3",
        "source_audit_ref": "https://example.test/solend-r3",
        "target_repo": "solendprotocol/solana-program",
        "target_domain": "lending",
        "target_language": "rust",
        "attack_class": "reentrancy-external-call",
        "bug_class": "smart-contract-lending-vulnerability",
        "severity_at_finding": "medium",
    }


def _record_bridge_misc() -> dict[str, Any]:
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": "bridge:misc:r4",
        "source_audit_ref": "https://example.test/bridge-r4",
        "target_repo": "example/bridge",
        "target_domain": "bridge",
        "target_language": "solidity",
        "attack_class": "signature-replay",
        "bug_class": "cross-chain-replay",
        "severity_at_finding": "critical",
    }


class CorpusIndexHelperTests(unittest.TestCase):
    """Unit tests for the ``_corpus_index_*`` helper surface."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="corpus-idx-helpers-")
        self.root = Path(self.tmp.name)
        self.index_dir = self.root / "index"
        self.index_dir.mkdir()

        # Minimal by_attack_class.jsonl with two rows for distinct
        # attack classes that share substring overlap with the query.
        by_ac = self.index_dir / "by_attack_class.jsonl"
        by_ac.write_text(
            json.dumps({"attack_class": "reentrancy-external-call", "tag_file": "lending/aave/record.json"})
            + "\n"
            + json.dumps({"attack_class": "reentrancy-token", "tag_file": "lending/solend/record.json"})
            + "\n"
            + json.dumps({"attack_class": "signature-replay", "tag_file": "bridge/misc/record.json"})
            + "\n"
            + "\n"  # blank line tolerated
            + "{not json}\n"  # corrupt row skipped
            + json.dumps({"attack_class": "oracle-manipulation", "tag_file": ""})  # blank tag_file
            + "\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # 1. env-var opt-in toggle ON for "1" / "true" / "yes"
    def test_opt_in_env_var_truthy_values(self) -> None:
        VaultQuery = vault_mcp_server.VaultQuery
        for truthy in ("1", "true", "TRUE", "yes", "on"):
            with self.subTest(value=truthy):
                old = os.environ.get("AUDITOOOR_VAULT_CALLABLE_USE_INDEX")
                os.environ["AUDITOOOR_VAULT_CALLABLE_USE_INDEX"] = truthy
                try:
                    self.assertTrue(VaultQuery._corpus_index_use_index_opt_in())
                finally:
                    if old is None:
                        os.environ.pop("AUDITOOOR_VAULT_CALLABLE_USE_INDEX", None)
                    else:
                        os.environ["AUDITOOOR_VAULT_CALLABLE_USE_INDEX"] = old

    # 2. env-var opt-in toggle OFF for unset / blank / arbitrary
    def test_opt_in_env_var_falsy_values(self) -> None:
        VaultQuery = vault_mcp_server.VaultQuery
        old = os.environ.get("AUDITOOOR_VAULT_CALLABLE_USE_INDEX")
        try:
            for falsy in ("", "0", "false", "no", "off", "maybe"):
                with self.subTest(value=falsy):
                    if falsy == "":
                        os.environ.pop("AUDITOOOR_VAULT_CALLABLE_USE_INDEX", None)
                    else:
                        os.environ["AUDITOOOR_VAULT_CALLABLE_USE_INDEX"] = falsy
                    self.assertFalse(VaultQuery._corpus_index_use_index_opt_in())
        finally:
            if old is None:
                os.environ.pop("AUDITOOOR_VAULT_CALLABLE_USE_INDEX", None)
            else:
                os.environ["AUDITOOOR_VAULT_CALLABLE_USE_INDEX"] = old

    # 3. picker returns attack_class index when both attack_class +
    #    severity are set (priority order honored).
    def test_pick_file_priority_attack_class_over_severity(self) -> None:
        VaultQuery = vault_mcp_server.VaultQuery
        # Create dummy by_severity.jsonl so both files exist.
        (self.index_dir / "by_severity.jsonl").write_text("", encoding="utf-8")
        picked = VaultQuery._corpus_index_pick_file(
            self.index_dir,
            {"attack_class": "reentrancy", "severity": "high"},
        )
        self.assertIsNotNone(picked)
        assert picked is not None  # mypy
        self.assertEqual(picked[0], "attack_class")
        self.assertEqual(picked[1].name, "by_attack_class.jsonl")

    # 4. picker returns None when no predicate maps to existing file.
    def test_pick_file_returns_none_for_substring_only_query(self) -> None:
        VaultQuery = vault_mcp_server.VaultQuery
        picked = VaultQuery._corpus_index_pick_file(
            self.index_dir, {"slug_substring": "x"}
        )
        self.assertIsNone(picked)

    # 5. picker returns None when predicate set but file missing.
    def test_pick_file_returns_none_when_file_missing(self) -> None:
        VaultQuery = vault_mcp_server.VaultQuery
        empty = self.root / "empty_index"
        empty.mkdir()
        picked = VaultQuery._corpus_index_pick_file(
            empty, {"attack_class": "reentrancy"}
        )
        self.assertIsNone(picked)

    # 6. stream_rows yields dict rows; tolerates blank / corrupt lines.
    def test_stream_rows_tolerates_blank_and_corrupt_lines(self) -> None:
        VaultQuery = vault_mcp_server.VaultQuery
        rows = list(
            VaultQuery._corpus_index_stream_rows(
                self.index_dir / "by_attack_class.jsonl"
            )
        )
        # 4 valid rows: 3 reentrancy/signature, 1 oracle-manipulation
        # (corrupt + blank lines skipped, but the blank-tag_file row is
        # still a valid dict so it appears here).
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(isinstance(r, dict) for r in rows))

    # 7. stream_rows on missing file returns no rows (no exception).
    def test_stream_rows_missing_file_returns_empty(self) -> None:
        VaultQuery = vault_mcp_server.VaultQuery
        rows = list(
            VaultQuery._corpus_index_stream_rows(self.root / "no_such.jsonl")
        )
        self.assertEqual(rows, [])

    # 8. candidate_tag_files: substring match honors case-insensitivity.
    def test_candidate_tag_files_case_insensitive_match(self) -> None:
        VaultQuery = vault_mcp_server.VaultQuery
        matched = VaultQuery._corpus_index_candidate_tag_files(
            self.index_dir / "by_attack_class.jsonl",
            "attack_class",
            "REENTRANCY",
        )
        self.assertEqual(
            matched,
            {"lending/aave/record.json", "lending/solend/record.json"},
        )

    # 9. candidate_tag_files: exact-match only when no substring overlap.
    def test_candidate_tag_files_no_match_returns_empty_set(self) -> None:
        VaultQuery = vault_mcp_server.VaultQuery
        matched = VaultQuery._corpus_index_candidate_tag_files(
            self.index_dir / "by_attack_class.jsonl",
            "attack_class",
            "completely-different-class",
        )
        self.assertEqual(matched, set())

    # 10. candidate_tag_files: blank tag_file rows excluded.
    def test_candidate_tag_files_blank_tag_files_excluded(self) -> None:
        VaultQuery = vault_mcp_server.VaultQuery
        matched = VaultQuery._corpus_index_candidate_tag_files(
            self.index_dir / "by_attack_class.jsonl",
            "attack_class",
            "oracle-manipulation",
        )
        # The matching row had tag_file="" so the set must be empty.
        self.assertEqual(matched, set())


class CorpusSearchIndexOptInIntegrationTests(unittest.TestCase):
    """Integration tests: walk-path vs index-path envelope equivalence."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="corpus-idx-integ-")
        self.root = Path(self.tmp.name)
        self.tags_dir = self.root / "tags"
        self.index_dir = self.root / "index"
        self.tags_dir.mkdir()
        self.index_dir.mkdir()

        # ---- write 4 records under tags/ ----
        records = [
            ("lending/aave-v3-r1", _record_reentrancy_aave()),
            ("oracle/chainlink-r2", _record_oracle_chainlink()),
            ("lending/solend-r3", _record_reentrancy_solend()),
            ("bridge/misc-r4", _record_bridge_misc()),
        ]
        # tag_file paths matching how the index would record them.
        self._tag_files: dict[str, str] = {}
        for rel_dir, record in records:
            d = self.tags_dir / rel_dir
            d.mkdir(parents=True, exist_ok=True)
            target = d / "record.json"
            target.write_text(json.dumps(record), encoding="utf-8")
            self._tag_files[str(record["record_id"])] = f"{rel_dir}/record.json"

        # ---- write the by_attack_class.jsonl index covering all 4 ----
        by_ac = self.index_dir / "by_attack_class.jsonl"
        index_rows = []
        for rel_dir, record in records:
            index_rows.append(
                {
                    "attack_class": record["attack_class"],
                    "tag_file": f"{rel_dir}/record.json",
                    "record_id": record["record_id"],
                    "target_repo": record["target_repo"],
                    "target_domain": record["target_domain"],
                    "target_language": record["target_language"],
                    "severity_at_finding": record["severity_at_finding"],
                    "bug_class": record["bug_class"],
                }
            )
        by_ac.write_text(
            "\n".join(json.dumps(r) for r in index_rows) + "\n",
            encoding="utf-8",
        )

        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir()
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

        self._old_env = os.environ.get("AUDITOOOR_VAULT_CALLABLE_USE_INDEX")

    def tearDown(self) -> None:
        if self._old_env is None:
            os.environ.pop("AUDITOOOR_VAULT_CALLABLE_USE_INDEX", None)
        else:
            os.environ["AUDITOOOR_VAULT_CALLABLE_USE_INDEX"] = self._old_env
        self.tmp.cleanup()

    def _call(self, **query: Any) -> dict[str, Any]:
        return self.vault.vault_corpus_search(
            workspace_path=str(self.root),
            query=query,
            tags_dir=str(self.tags_dir),
            index_dir=str(self.index_dir),
        )

    # 11. opt-in OFF: walk path used; envelope is a known-good baseline.
    def test_walk_path_baseline(self) -> None:
        os.environ.pop("AUDITOOOR_VAULT_CALLABLE_USE_INDEX", None)
        result = self._call(attack_class="reentrancy")
        self.assertEqual(result["degraded"], False)
        ids = sorted(r["record_id"] for r in result["records"])
        self.assertEqual(ids, ["lending:aave-v3:r1", "lending:solend:r3"])

    # 12. opt-in ON: index path used; envelope identical to walk path
    #     (same context_pack_hash + same records[]).
    def test_index_path_matches_walk_path_envelope(self) -> None:
        os.environ.pop("AUDITOOOR_VAULT_CALLABLE_USE_INDEX", None)
        walk_result = self._call(attack_class="reentrancy")

        os.environ["AUDITOOOR_VAULT_CALLABLE_USE_INDEX"] = "1"
        index_result = self._call(attack_class="reentrancy")

        # Drop generated_at_utc for fair compare (it's a wall-clock ts).
        for r in (walk_result, index_result):
            r.pop("generated_at_utc", None)
        self.assertEqual(
            walk_result["context_pack_hash"],
            index_result["context_pack_hash"],
            f"hash mismatch:\nwalk={walk_result}\nindex={index_result}",
        )
        self.assertEqual(walk_result["records"], index_result["records"])

    # 13. opt-in ON + index file missing -> falls back to walk path.
    def test_index_path_falls_back_when_index_missing(self) -> None:
        os.environ["AUDITOOOR_VAULT_CALLABLE_USE_INDEX"] = "1"
        empty_index = self.root / "empty_index"
        empty_index.mkdir()
        result = self.vault.vault_corpus_search(
            workspace_path=str(self.root),
            query={"attack_class": "reentrancy"},
            tags_dir=str(self.tags_dir),
            index_dir=str(empty_index),
        )
        # walk path still works -> 2 reentrancy records.
        ids = sorted(r["record_id"] for r in result["records"])
        self.assertEqual(ids, ["lending:aave-v3:r1", "lending:solend:r3"])

    # 14. opt-in ON + substring-only query (no indexed predicate) ->
    #     walks anyway; result is correct.
    def test_index_path_falls_back_for_substring_only_query(self) -> None:
        os.environ["AUDITOOOR_VAULT_CALLABLE_USE_INDEX"] = "1"
        result = self._call(slug_substring="solend")
        ids = [r["record_id"] for r in result["records"]]
        self.assertIn("lending:solend:r3", ids)

    # 15. opt-in ON: severity predicate selects the right index file
    #     when attack_class is absent.
    def test_index_path_uses_severity_when_attack_class_absent(self) -> None:
        # Also write by_severity.jsonl so the severity-index lookup
        # is exercised.
        by_sev = self.index_dir / "by_severity.jsonl"
        rows = []
        for rel_dir, record in (
            ("lending/aave-v3-r1", _record_reentrancy_aave()),
            ("oracle/chainlink-r2", _record_oracle_chainlink()),
            ("lending/solend-r3", _record_reentrancy_solend()),
            ("bridge/misc-r4", _record_bridge_misc()),
        ):
            rows.append(
                {
                    "severity_at_finding": record["severity_at_finding"],
                    "tag_file": f"{rel_dir}/record.json",
                    "record_id": record["record_id"],
                }
            )
        by_sev.write_text(
            "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
        )

        os.environ.pop("AUDITOOOR_VAULT_CALLABLE_USE_INDEX", None)
        walk_result = self._call(severity="critical")

        os.environ["AUDITOOOR_VAULT_CALLABLE_USE_INDEX"] = "1"
        index_result = self._call(severity="critical")

        for r in (walk_result, index_result):
            r.pop("generated_at_utc", None)
        self.assertEqual(
            walk_result["context_pack_hash"],
            index_result["context_pack_hash"],
        )
        self.assertEqual(walk_result["records"], index_result["records"])

    # 16. opt-in ON + AND-composed predicates: index narrows by the
    #     most selective indexed predicate (attack_class), then the
    #     full record-level filter applies the remaining predicates.
    def test_index_path_handles_and_composed_predicates(self) -> None:
        os.environ.pop("AUDITOOOR_VAULT_CALLABLE_USE_INDEX", None)
        walk_result = self._call(attack_class="reentrancy", language="solidity")

        os.environ["AUDITOOOR_VAULT_CALLABLE_USE_INDEX"] = "1"
        index_result = self._call(attack_class="reentrancy", language="solidity")

        for r in (walk_result, index_result):
            r.pop("generated_at_utc", None)
        self.assertEqual(
            walk_result["context_pack_hash"],
            index_result["context_pack_hash"],
        )
        # Only the solidity reentrancy record should remain.
        ids = [r["record_id"] for r in index_result["records"]]
        self.assertEqual(ids, ["lending:aave-v3:r1"])


if __name__ == "__main__":
    unittest.main()
