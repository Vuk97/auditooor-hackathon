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
TOOL = ROOT / "tools" / "local-corpus-commit-ref-inventory.py"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("local_corpus_commit_ref_inventory", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOD = _load_module()
SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_C = "c" * 40


class LocalCorpusCommitRefInventoryTest(unittest.TestCase):
    def test_extracts_url_and_near_repo_hash_routes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            note = root / "notes.md"
            note.write_text(
                "\n".join(
                    [
                        f"pinned source https://github.com/acme/vault/blob/{SHA_A}/src/Vault.sol",
                        f"fix commit https://github.com/acme/vault/commit/{SHA_B}",
                        f"repo https://github.com/acme/vault post audit commit {SHA_C}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            first = MOD.build_inventory([root])
            second = MOD.build_inventory([root])

        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))
        self.assertEqual(first["network_used"], False)
        self.assertEqual(first["row_count"], 3)
        by_evidence = {row["evidence_kind"]: row for row in first["rows"]}

        blob = by_evidence["github_blob_url"]
        self.assertEqual(blob["repo"], "acme/vault")
        self.assertEqual(blob["commit"], SHA_A)
        self.assertEqual(blob["ref_type"], "commit")
        self.assertEqual(blob["filepath"], "src/Vault.sol")
        self.assertEqual(blob["suggested_downstream_route"], "source_ref_manifest")

        commit = by_evidence["github_commit_url"]
        self.assertEqual(commit["commit"], SHA_B)
        self.assertEqual(commit["filepath"], None)
        self.assertEqual(commit["suggested_downstream_route"], "contest_fix_mine_review_lane")

        near = by_evidence["near_repo_url_commit_hash"]
        self.assertEqual(near["commit"], SHA_C)
        self.assertEqual(near["line"], 3)
        self.assertIn("post audit commit", near["snippet"])
        self.assertEqual(near["suggested_downstream_route"], "contest_fix_mine_review_lane")

    def test_named_refs_and_short_hashes_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "refs.txt"
            path.write_text(
                "\n".join(
                    [
                        "named https://github.com/acme/vault/blob/main/src/Vault.sol",
                        "short https://github.com/acme/vault/commit/abcdef1",
                        "near short https://github.com/acme/vault abcdef2",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            payload = MOD.build_inventory([path])

        self.assertEqual(payload["row_count"], 3)
        by_ref = {row["ref"]: row for row in payload["rows"]}
        self.assertEqual(by_ref["main"]["ref_type"], "named_ref")
        self.assertEqual(by_ref["main"]["commit"], None)
        self.assertEqual(
            by_ref["main"]["suggested_downstream_route"],
            "blocked_named_ref_unresolved",
        )
        self.assertEqual(by_ref["abcdef1"]["ref_type"], "short_hash")
        self.assertEqual(by_ref["abcdef1"]["route_status"], "blocked")
        self.assertEqual(
            by_ref["abcdef2"]["suggested_downstream_route"],
            "blocked_short_hash_unresolved",
        )

    def test_scans_json_jsonl_markdown_and_plain_text_under_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "one.json").write_text(
                json.dumps({"url": f"https://github.com/acme/one/blob/{SHA_A}/src/One.sol"}),
                encoding="utf-8",
            )
            (root / "two.jsonl").write_text(
                json.dumps({"url": f"https://github.com/acme/two/commit/{SHA_B}"}) + "\n",
                encoding="utf-8",
            )
            (root / "three.md").write_text(
                f"https://raw.githubusercontent.com/acme/three/{SHA_C}/src/Three.sol\n",
                encoding="utf-8",
            )
            (root / "four.txt").write_text(
                f"https://github.com/acme/four commit {SHA_A}\n",
                encoding="utf-8",
            )
            (root / "skip.bin").write_bytes(b"https://github.com/acme/skip/commit/" + SHA_B.encode())

            payload = MOD.build_inventory([root])

        self.assertEqual(payload["scanned_file_count"], 4)
        self.assertEqual(payload["row_count"], 4)
        self.assertEqual(
            sorted(row["repo"] for row in payload["rows"]),
            ["acme/four", "acme/one", "acme/three", "acme/two"],
        )
        self.assertNotIn("acme/skip", json.dumps(payload))

    def test_cli_writes_deterministic_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "input.md"
            out = root / "inventory.json"
            path.write_text(
                f"https://github.com/acme/vault/tree/{SHA_A}/contracts\n",
                encoding="utf-8",
            )

            proc = subprocess.run(
                [sys.executable, str(TOOL), str(path), "--out", str(out)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(out.read_text(encoding="utf-8"))

        self.assertEqual(proc.stdout, "")
        self.assertEqual(payload["row_count"], 1)
        self.assertEqual(payload["rows"][0]["evidence_kind"], "github_tree_url")
        self.assertEqual(payload["rows"][0]["filepath"], "contracts")
        self.assertEqual(payload["rows"][0]["suggested_downstream_route"], "source_ref_manifest")


if __name__ == "__main__":
    unittest.main()
