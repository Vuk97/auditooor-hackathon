#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "local-corpus-commit-inventory.py"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("local_corpus_commit_inventory", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOD = _load_module()
SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_C = "c" * 40


class LocalCorpusCommitInventoryTest(unittest.TestCase):
    def test_normalizes_split_commit_urls_version_hashes_and_remediation_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "reference" / "corpus_txt" / "hexens" / "Lido_February23_Public_upd18.04.txt"
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(
                "\n".join(
                    [
                        "The final validated version of the protocol:",
                        "https://github.com/lido\ufb01nance/lido-dao/commit/e45c4d6fb8120fd2",
                        "9426b8d969c19d8a798ca974",
                        f"Version nibiru: {SHA_A}",
                        f"This was remediated in commit {SHA_B} by changing the validator flow.",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            payload = MOD.build_inventory([root])

        self.assertEqual(payload["network_used"], False)
        self.assertEqual(payload["row_count"], 3)
        by_kind = {row["ref_kind"]: row for row in payload["rows"]}

        commit = by_kind["strict_github_commit_url"]
        self.assertEqual(commit["owner"], "lidofinance")
        self.assertEqual(commit["repo"], "lido-dao")
        self.assertEqual(commit["sha"], "e45c4d6fb8120fd29426b8d969c19d8a798ca974")
        self.assertEqual(commit["status"], "needs_local_mirror")

        version = by_kind["version_hash"]
        self.assertEqual(version["sha"], SHA_A)
        self.assertEqual(version["status"], "blocked_missing_repo")
        self.assertIn("Version nibiru", version["context_label"])

        remediation = by_kind["remediation_hash"]
        self.assertEqual(remediation["sha"], SHA_B)
        self.assertEqual(remediation["status"], "blocked_missing_repo")
        self.assertEqual(remediation["remediation_signal"], True)

    def test_pattern_near_repo_and_internal_rows_map_to_expected_statuses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            pattern = root / "reference" / "patterns.dsl" / "fixed.yaml"
            pattern.parent.mkdir(parents=True, exist_ok=True)
            pattern.write_text(
                f"https://github.com/acme/vault/blob/{SHA_A}/src/Vault.sol\n",
                encoding="utf-8",
            )

            corpus = root / "reference" / "corpus_txt" / "zellic" / "Vault Audit.txt"
            corpus.parent.mkdir(parents=True, exist_ok=True)
            corpus.write_text(
                f"repo https://github.com/acme/vault post audit commit {SHA_B}\n",
                encoding="utf-8",
            )

            doc = root / "docs" / "LOCAL_NOTE.md"
            doc.parent.mkdir(parents=True, exist_ok=True)
            doc.write_text(
                f"auditooor build hash {SHA_C}\n",
                encoding="utf-8",
            )

            payload = MOD.build_inventory([root])

        self.assertEqual(payload["row_count"], 3)
        rows = {row["ref_kind"]: row for row in payload["rows"]}

        blob = rows["pinned_github_blob_url"]
        self.assertEqual(blob["status"], "already_detectorized_or_patterned")
        self.assertEqual(blob["next_command"], f"rg -n '{SHA_A}' reference/patterns.dsl")

        near = rows["commit_hash_near_repo"]
        self.assertEqual(near["owner"], "acme")
        self.assertEqual(near["repo"], "vault")
        self.assertEqual(near["status"], "needs_local_mirror")
        self.assertEqual(near["nearby_repo_url"], "https://github.com/acme/vault")

        internal = rows["internal_hash_ignored"]
        self.assertEqual(internal["status"], "blocked_internal_hash")
        self.assertEqual(internal["next_command"], "record internal hash ignore disposition")

    def test_cli_writes_json_and_applies_row_bound(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "reference" / "corpus_txt" / "zellic" / "Example.txt"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                "\n".join(
                    [
                        f"Version v1-core: {SHA_A}",
                        f"This was remediated in commit {SHA_B} by removing the unsafe path.",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            out = root / "inventory.json"

            proc = subprocess.run(
                [sys.executable, str(TOOL), str(path), "--out", str(out), "--max-rows", "1"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, "")
            payload = json.loads(out.read_text(encoding="utf-8"))

        self.assertEqual(payload["row_count"], 1)
        self.assertEqual(payload["rows_truncated"], True)
        self.assertEqual(payload["rows"][0]["row_id"], "LCCI-00001")


if __name__ == "__main__":
    unittest.main()
