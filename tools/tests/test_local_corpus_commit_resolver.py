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
TOOL = ROOT / "tools" / "local-corpus-commit-resolver.py"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("local_corpus_commit_resolver", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_module()


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(proc.stdout + proc.stderr)
    return proc.stdout.strip()


def _make_repo(root: Path, relative: str, remote: str) -> Path:
    repo = root / relative
    repo.mkdir(parents=True)
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    _git(repo, "remote", "add", "origin", remote)
    return repo


def _commit(repo: Path, filename: str, content: str, message: str) -> str:
    path = repo / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    _git(repo, "add", filename)
    _git(repo, "commit", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


class LocalCorpusCommitResolverTest(unittest.TestCase):
    def _write_json(self, root: Path, relpath: str, payload: object) -> Path:
        path = root / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path

    def test_rebuilds_inventory_and_emits_fix_chain_packet_with_exact_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mirror_root = root / "mirrors"
            repo = _make_repo(mirror_root, "acme/vault", "https://github.com/acme/vault.git")
            version_sha = _commit(repo, "src/Vault.sol", "contract V1 {}\n", "version pin")
            remediation_sha = _commit(repo, "src/Vault.sol", "contract V2 {}\n", "fix bug")
            commit_url_sha = _commit(repo, "README.md", "docs\n", "reference commit")

            inventory_tool = root / "inventory_tool.py"
            inventory_tool.write_text(
                "\n".join(
                    [
                        "def build_inventory(inputs):",
                        "    return {",
                        "        'rows': [",
                        "            {",
                        "                'row_id': 'ROW-COMMIT',",
                        "                'source_path': 'reference/corpus_txt/zellic/Acme Vault.txt',",
                        "                'line': 10,",
                        "                'provider': 'zellic',",
                        "                'report_title': 'Acme Vault',",
                        "                'ref_kind': 'strict_github_commit_url',",
                        "                'owner': 'acme',",
                        "                'repo': 'vault',",
                        f"                'sha': '{commit_url_sha}',",
                        "                'sha_len': 40,",
                        "                'context_label': 'github commit url',",
                        "                'remediation_signal': False,",
                        "                'nearby_repo_url': 'https://github.com/acme/vault',",
                        "                'project_tags': ['provider:zellic'],",
                        "                'status': 'needs_local_mirror',",
                        "                'next_command': 'git -C <local-mirror/acme__vault> rev-parse --verify "
                        + commit_url_sha
                        + "^{commit}',",
                        "                'snippet': 'commit url',",
                        "            },",
                        "            {",
                        "                'row_id': 'ROW-VERSION',",
                        "                'source_path': 'reference/corpus_txt/zellic/Acme Vault.txt',",
                        "                'line': 11,",
                        "                'provider': 'zellic',",
                        "                'report_title': 'Acme Vault',",
                        "                'ref_kind': 'version_hash',",
                        "                'owner': None,",
                        "                'repo': None,",
                        f"                'sha': '{version_sha}',",
                        "                'sha_len': 40,",
                        "                'context_label': 'Version audited',",
                        "                'remediation_signal': False,",
                        "                'nearby_repo_url': None,",
                        "                'project_tags': ['provider:zellic'],",
                        "                'status': 'blocked_missing_repo',",
                        "                'next_command': 'rg -n version reference/corpus_txt/zellic/Acme Vault.txt',",
                        "                'snippet': 'version line',",
                        "            },",
                        "            {",
                        "                'row_id': 'ROW-FIX',",
                        "                'source_path': 'reference/corpus_txt/zellic/Acme Vault.txt',",
                        "                'line': 12,",
                        "                'provider': 'zellic',",
                        "                'report_title': 'Acme Vault',",
                        "                'ref_kind': 'remediation_hash',",
                        "                'owner': None,",
                        "                'repo': None,",
                        f"                'sha': '{remediation_sha}',",
                        "                'sha_len': 40,",
                        "                'context_label': 'remediated in commit',",
                        "                'remediation_signal': True,",
                        "                'nearby_repo_url': None,",
                        "                'project_tags': ['provider:zellic', 'remediation_signal'],",
                        "                'status': 'blocked_missing_repo',",
                        "                'next_command': 'rg -n remediation reference/corpus_txt/zellic/Acme Vault.txt',",
                        "                'snippet': 'fix line',",
                        "            },",
                        "        ]",
                        "    }",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            report = self._write_json(
                root,
                "reports/local_corpus_commit_mining_inventory_2026-05-05.json",
                {
                    "schema": "auditooor.local_corpus_commit_mining_inventory.v0",
                    "implemented_tool": {
                        "path": str(inventory_tool),
                        "default_inputs": ["reference/corpus_txt"],
                    },
                },
            )

            payload = MOD.build_resolver_report(
                input_report=report,
                mirror_roots=[mirror_root],
                max_packets=10,
                max_rows_per_packet=4,
            )

        self.assertTrue(payload["inventory_rows_rebuilt_locally"])
        rows = {row["row_id"]: row for row in payload["resolved_rows"]}
        self.assertEqual(rows["ROW-FIX"]["row_class"], "mirror_verified_fix_pair")
        self.assertEqual(rows["ROW-FIX"]["repo_inference"], "same_source_unique_repo")
        self.assertEqual(rows["ROW-FIX"]["mirror_verified"], True)
        expected_diff = f"git -C {repo.resolve()} diff --stat {version_sha} {remediation_sha}"
        self.assertIn(expected_diff, rows["ROW-FIX"]["next_commands"])

        self.assertEqual(payload["summary"]["packet_class_counts"]["mirror_verified_fix_chain"], 1)
        packet = payload["packets"][0]
        self.assertEqual(packet["packet_class"], "mirror_verified_fix_chain")
        self.assertIn("ROW-FIX", packet["selected_row_ids"])
        self.assertTrue(
            any(command.endswith(f"diff --stat {version_sha} {remediation_sha}") for command in packet["exact_next_commands"])
        )

    def test_emits_exact_commands_for_missing_mirror_and_missing_repo(self) -> None:
        full_sha = "a" * 40
        report_rows = [
            {
                "row_id": "ROW-FULL",
                "source_path": "reference/corpus_txt/hexens/Full Ref.txt",
                "line": 20,
                "provider": "hexens",
                "report_title": "Full Ref",
                "ref_kind": "strict_github_commit_url",
                "owner": "acme",
                "repo": "vault",
                "sha": full_sha,
                "sha_len": 40,
                "context_label": "github commit url",
                "remediation_signal": False,
                "nearby_repo_url": "https://github.com/acme/vault",
                "project_tags": [],
                "status": "needs_local_mirror",
                "next_command": "git -C <local-mirror/acme__vault> rev-parse --verify",
                "snippet": "commit url",
            },
            {
                "row_id": "ROW-MISSING-REPO",
                "source_path": "reference/corpus_txt/hexens/Missing Repo.txt",
                "line": 30,
                "provider": "hexens",
                "report_title": "Missing Repo",
                "ref_kind": "version_hash",
                "owner": None,
                "repo": None,
                "sha": "b" * 40,
                "sha_len": 40,
                "context_label": "Version audited",
                "remediation_signal": False,
                "nearby_repo_url": None,
                "project_tags": [],
                "status": "blocked_missing_repo",
                "next_command": "rg -n version reference/corpus_txt/hexens/Missing Repo.txt",
                "snippet": "version line",
            },
        ]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self._write_json(
                root,
                "reports/local_corpus_commit_mining_inventory_2026-05-05.json",
                {"schema": "auditooor.local_corpus_commit_mining_inventory.v0", "rows": report_rows},
            )
            payload = MOD.build_resolver_report(
                input_report=report,
                mirror_roots=[root / "nonexistent-mirrors"],
            )

        rows = {row["row_id"]: row for row in payload["resolved_rows"]}
        self.assertEqual(rows["ROW-FULL"]["row_class"], "mirror_candidate_full_sha")
        self.assertTrue(
            any(".git/config" in command and "acme/vault" in command for command in rows["ROW-FULL"]["next_commands"])
        )
        self.assertEqual(rows["ROW-MISSING-REPO"]["row_class"], "needs_repo_inference")
        self.assertEqual(rows["ROW-MISSING-REPO"]["next_commands"], ["rg -n '" + ("b" * 40) + "' 'reference/corpus_txt/hexens/Missing Repo.txt'"])

    def test_packet_bounding_records_omitted_rows_and_truncated_groups(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mirror_root = root / "mirrors"
            alpha = _make_repo(mirror_root, "acme/alpha", "https://github.com/acme/alpha.git")
            beta = _make_repo(mirror_root, "acme/beta", "https://github.com/acme/beta.git")
            alpha_shas = [_commit(alpha, f"alpha_{idx}.txt", f"{idx}\n", f"alpha {idx}") for idx in range(3)]
            beta_sha = _commit(beta, "beta.txt", "beta\n", "beta")
            rows = []
            for idx, sha in enumerate(alpha_shas, start=1):
                rows.append(
                    {
                        "row_id": f"ALPHA-{idx}",
                        "source_path": "reference/corpus_txt/zellic/Alpha.txt",
                        "line": idx,
                        "provider": "zellic",
                        "report_title": "Alpha",
                        "ref_kind": "strict_github_commit_url",
                        "owner": "acme",
                        "repo": "alpha",
                        "sha": sha,
                        "sha_len": 40,
                        "context_label": "github commit url",
                        "remediation_signal": False,
                        "nearby_repo_url": "https://github.com/acme/alpha",
                        "project_tags": [],
                        "status": "needs_local_mirror",
                        "next_command": "git -C alpha rev-parse --verify",
                        "snippet": "alpha row",
                    }
                )
            rows.append(
                {
                    "row_id": "BETA-1",
                    "source_path": "reference/corpus_txt/zellic/Beta.txt",
                    "line": 1,
                    "provider": "zellic",
                    "report_title": "Beta",
                    "ref_kind": "strict_github_commit_url",
                    "owner": "acme",
                    "repo": "beta",
                    "sha": beta_sha,
                    "sha_len": 40,
                    "context_label": "github commit url",
                    "remediation_signal": False,
                    "nearby_repo_url": "https://github.com/acme/beta",
                    "project_tags": [],
                    "status": "needs_local_mirror",
                    "next_command": "git -C beta rev-parse --verify",
                    "snippet": "beta row",
                }
            )
            report = self._write_json(
                root,
                "reports/local_corpus_commit_mining_inventory_2026-05-05.json",
                {"schema": "auditooor.local_corpus_commit_mining_inventory.v0", "rows": rows},
            )

            payload = MOD.build_resolver_report(
                input_report=report,
                mirror_roots=[mirror_root],
                max_packets=1,
                max_rows_per_packet=2,
            )

        self.assertEqual(payload["summary"]["packet_count"], 1)
        packet = payload["packets"][0]
        self.assertEqual(packet["selected_row_ids"], ["ALPHA-1", "ALPHA-2"])
        self.assertEqual(packet["omitted_row_ids"], ["ALPHA-3"])
        self.assertEqual(len(payload["truncated_packet_groups"]), 1)
        self.assertEqual(payload["truncated_packet_groups"][0]["row_ids"], ["BETA-1"])


if __name__ == "__main__":
    unittest.main()
