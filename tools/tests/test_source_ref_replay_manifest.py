#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "source-ref-replay-manifest.py"
FIXTURE_DIR = ROOT / "tools" / "tests" / "fixtures" / "source_ref_replay_manifest"
REPORT_FIXTURE = ROOT / "reports" / "source_ref_replay_manifest_fixture.json"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("source_ref_replay_manifest", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOD = _load_module()
FULL_SHA = "a" * 40


class SourceRefReplayManifestTest(unittest.TestCase):
    def test_named_ref_blob_is_blocked_offline_without_lockfile(self) -> None:
        manifest = MOD.build_manifest(
            [
                {
                    "id": "F-1",
                    "title": "Mutable source",
                    "content": "https://github.com/acme/vault/blob/main/src/Vault.sol",
                }
            ]
        )

        self.assertEqual(manifest["network_used"], False)
        self.assertEqual(manifest["row_count"], 1)
        row = manifest["rows"][0]
        self.assertEqual(row["replay_status"], "blocked_named_ref_unresolved")
        self.assertEqual(row["resolved_commit"], None)
        self.assertEqual(row["local_content_sha256"], None)
        self.assertEqual(row["network_used"], False)

    def test_full_commit_without_local_source_is_blocked_missing(self) -> None:
        manifest = MOD.build_manifest(
            [
                {
                    "finding_id": "F-2",
                    "title": "Pinned source",
                    "content": f"https://github.com/acme/vault/blob/{FULL_SHA}/src/Vault.sol",
                }
            ]
        )

        row = manifest["rows"][0]
        self.assertEqual(row["replay_status"], "blocked_local_source_missing")
        self.assertEqual(row["resolved_commit"], FULL_SHA)
        self.assertEqual(row["local_source_path"], None)

    def test_full_commit_with_local_source_root_is_immutable_ready(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src" / "Vault.sol"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"contract Vault {}\n")
            expected = hashlib.sha256(b"contract Vault {}\n").hexdigest()

            manifest = MOD.build_manifest(
                [
                    {
                        "id": "F-3",
                        "title": "Pinned with bytes",
                        "content": f"https://github.com/acme/vault/blob/{FULL_SHA}/src/Vault.sol",
                    }
                ],
                source_root=root,
            )

        row = manifest["rows"][0]
        self.assertEqual(row["replay_status"], "immutable_ready")
        self.assertEqual(row["resolved_commit"], FULL_SHA)
        self.assertEqual(row["local_content_sha256"], expected)
        self.assertTrue(row["local_source_path"].endswith("src/Vault.sol"))

    def test_short_hex_ref_is_blocked_until_full_sha_resolution(self) -> None:
        manifest = MOD.build_manifest(
            [
                {
                    "id": "F-4",
                    "content": "https://github.com/acme/vault/blob/abcdef1/src/Vault.sol",
                }
            ]
        )

        row = manifest["rows"][0]
        self.assertEqual(row["ref_type"], "commit")
        self.assertEqual(row["replay_status"], "blocked_short_sha_unresolved")
        self.assertEqual(row["resolved_commit"], None)

    def test_short_hex_ref_lockfile_sets_full_commit(self) -> None:
        short_ref = "abcdef1"
        resolved = "b" * 40
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src" / "Vault.sol"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"contract Vault {}\n")

            manifest = MOD.build_manifest(
                [
                    {
                        "id": "F-4b",
                        "content": f"https://github.com/acme/vault/blob/{short_ref}/src/Vault.sol",
                    }
                ],
                source_root=root,
                named_ref_locks={f"acme/vault@{short_ref}": resolved},
            )

        row = manifest["rows"][0]
        self.assertEqual(row["replay_status"], "immutable_ready")
        self.assertEqual(row["resolved_commit"], resolved)
        self.assertEqual(
            row["local_content_sha256"],
            hashlib.sha256(b"contract Vault {}\n").hexdigest(),
        )

    def test_named_ref_lockfile_sets_commit_but_still_requires_local_source(self) -> None:
        manifest = MOD.build_manifest(
            [
                {
                    "id": "F-5",
                    "content": "https://github.com/acme/vault/blob/v1.2.3/src/Vault.sol",
                }
            ],
            named_ref_locks={"acme/vault@v1.2.3": FULL_SHA},
        )

        row = manifest["rows"][0]
        self.assertEqual(row["replay_status"], "blocked_local_source_missing")
        self.assertEqual(row["resolved_commit"], FULL_SHA)
        self.assertEqual(row["local_content_sha256"], None)

    def test_local_proof_hash_must_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "Vault.sol"
            source.write_bytes(b"contract Vault {}\n")
            manifest = MOD.build_manifest(
                [
                    {
                        "id": "F-6",
                        "content": f"https://github.com/acme/vault/blob/{FULL_SHA}/src/Vault.sol",
                    }
                ],
                local_proofs={
                    f"acme/vault@{FULL_SHA}:src/Vault.sol": {
                        "local_source_path": str(source),
                        "sha256": "b" * 64,
                    }
                },
            )

        row = manifest["rows"][0]
        self.assertEqual(row["replay_status"], "blocked_local_source_missing")
        self.assertEqual(row["local_content_sha256"], None)
        self.assertIn("local proof hash does not match local source bytes", row["blockers"])

    def test_output_is_deterministic_and_preserves_distinct_source_urls(self) -> None:
        findings = [
            {
                "id": "B",
                "content": f"https://raw.githubusercontent.com/acme/vault/{FULL_SHA}/src/Vault.sol",
            },
            {
                "id": "A",
                "content": f"https://github.com/acme/vault/blob/{FULL_SHA}/src/Vault.sol",
            },
        ]

        first = MOD.build_manifest(findings)
        second = MOD.build_manifest(list(reversed(findings)))

        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))
        self.assertEqual(first["row_count"], 2)
        self.assertNotIn("timestamp", json.dumps(first, sort_keys=True).lower())
        self.assertEqual(
            [row["finding_id"] for row in first["rows"]],
            ["A", "B"],
        )

    def test_same_target_blob_and_raw_urls_emit_separate_rows(self) -> None:
        manifest = MOD.build_manifest(
            [
                {
                    "id": "F-7",
                    "content": (
                        f"https://github.com/acme/vault/blob/{FULL_SHA}/src/Vault.sol\n"
                        f"https://raw.githubusercontent.com/acme/vault/{FULL_SHA}/src/Vault.sol"
                    ),
                }
            ]
        )

        self.assertEqual(manifest["row_count"], 2)
        self.assertEqual(
            sorted(row["source_url"] for row in manifest["rows"]),
            [
                f"https://github.com/acme/vault/blob/{FULL_SHA}/src/Vault.sol",
                f"https://raw.githubusercontent.com/acme/vault/{FULL_SHA}/src/Vault.sol",
            ],
        )

    def test_load_finding_export_accepts_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "findings.jsonl"
            path.write_text(
                json.dumps({"id": "F-8", "content": "x"}) + "\n"
                + json.dumps({"id": "F-9", "content": "y"}) + "\n",
                encoding="utf-8",
            )

            rows = MOD.load_finding_export(path)

        self.assertEqual([row["id"] for row in rows], ["F-8", "F-9"])

    def test_detector_gap_guard_blocks_rows_that_drop_manifest_refs(self) -> None:
        manifest = {
            "rows": [
                {
                    "finding_id": "F-guard",
                    "source_url": f"https://github.com/acme/vault/blob/{FULL_SHA}/src/Vault.sol",
                }
            ]
        }

        guard = MOD.detector_gap_source_ref_guard(
            [{"finding_id": "F-guard", "github_ref": None}],
            manifest,
        )

        self.assertEqual(guard["status"], "blocked_detector_gap_missing_github_ref")
        self.assertEqual(guard["detector_gap_missing_github_ref_finding_ids"], ["F-guard"])
        with self.assertRaisesRegex(RuntimeError, "F-guard"):
            MOD.enforce_detector_gap_source_refs(
                [{"finding_id": "F-guard", "github_ref": None}],
                manifest,
            )

    def test_detector_gap_guard_passes_when_manifest_refs_are_preserved(self) -> None:
        manifest = {
            "rows": [
                {
                    "finding_id": "F-guard",
                    "source_url": f"https://github.com/acme/vault/blob/{FULL_SHA}/src/Vault.sol",
                }
            ]
        }

        guard = MOD.enforce_detector_gap_source_refs(
            [
                {
                    "finding_id": "F-guard",
                    "github_ref": {
                        "repo": "acme/vault",
                        "commit": FULL_SHA,
                        "filepath": "src/Vault.sol",
                    },
                }
            ],
            manifest,
        )

        self.assertEqual(guard["status"], "pass")
        self.assertEqual(guard["manifest_source_ref_finding_count"], 1)

    def test_apply_manifest_github_refs_fills_gap_row_with_local_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src" / "Vault.sol"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"contract Vault {}\n")
            manifest = MOD.build_manifest(
                [
                    {
                        "id": "F-fill",
                        "title": "Named ref locked locally",
                        "content": "https://github.com/acme/vault/blob/main/src/Vault.sol",
                    }
                ],
                source_root=root,
                named_ref_locks={"acme/vault@main": FULL_SHA},
            )

        rows = [{"finding_id": "F-fill", "github_ref": None}]
        summary = MOD.apply_manifest_github_refs(rows, manifest)

        self.assertEqual(summary["filled_github_ref_count"], 1)
        self.assertEqual(summary["detector_rows_with_github_ref"], 1)
        github_ref = rows[0]["github_ref"]
        self.assertEqual(github_ref["repo"], "acme/vault")
        self.assertEqual(github_ref["commit"], FULL_SHA)
        self.assertEqual(github_ref["original_ref"], "main")
        self.assertEqual(github_ref["filepath"], "src/Vault.sol")
        self.assertEqual(github_ref["replay_status"], "immutable_ready")
        self.assertTrue(github_ref["local_source_path"].endswith("src/Vault.sol"))

    def test_apply_manifest_github_refs_upgrades_named_ref_when_local_commit_known(self) -> None:
        manifest = {
            "rows": [
                {
                    "finding_id": "F-upgrade",
                    "source_url": "https://github.com/acme/vault/blob/main/src/Vault.sol",
                    "repo": "acme/vault",
                    "original_ref": "main",
                    "resolved_commit": FULL_SHA,
                    "filepath": "src/Vault.sol",
                    "ref_type": "named_ref",
                    "replay_status": "blocked_local_source_missing",
                }
            ]
        }
        rows = [
            {
                "finding_id": "F-upgrade",
                "github_ref": {
                    "repo": "acme/vault",
                    "commit": "main",
                    "ref_type": "named_ref",
                    "filepath": "src/Vault.sol",
                },
            }
        ]

        summary = MOD.apply_manifest_github_refs(rows, manifest)

        self.assertEqual(summary["upgraded_github_ref_count"], 1)
        self.assertEqual(rows[0]["github_ref"]["commit"], FULL_SHA)
        self.assertEqual(rows[0]["github_ref"]["original_ref"], "main")
        self.assertEqual(rows[0]["github_ref"]["resolved_commit"], FULL_SHA)

    def test_blocked_manifest_diagnostic_calls_out_missing_local_inputs(self) -> None:
        manifest = MOD.build_manifest(
            [
                {
                    "id": "F-diag-a",
                    "content": "https://github.com/acme/vault/blob/main/src/Vault.sol",
                },
                {
                    "id": "F-diag-b",
                    "content": f"https://github.com/acme/vault/blob/{FULL_SHA}/src/Vault.sol",
                },
            ]
        )

        diagnostic = MOD.format_blocked_manifest_diagnostic(manifest)

        assert diagnostic is not None
        self.assertIn("blocked_named_ref_unresolved=1", diagnostic)
        self.assertIn("blocked_local_source_missing=1", diagnostic)
        self.assertIn("--named-ref-lockfile", diagnostic)
        self.assertIn("--local-source-root or --local-proof", diagnostic)

    def test_cli_fails_closed_when_manifest_has_blocked_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            findings = tmp_path / "findings.json"
            out = tmp_path / "manifest.json"
            findings.write_text(
                json.dumps(
                    [
                        {
                            "id": "F-cli-blocked",
                            "content": "https://github.com/acme/vault/blob/main/src/Vault.sol",
                        }
                    ]
                ),
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    "--input",
                    str(findings),
                    "--out",
                    str(out),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            out_exists = out.exists()

        self.assertEqual(proc.returncode, 2, msg=f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
        self.assertTrue(out_exists)
        self.assertIn("[source-ref-replay-manifest] BLOCKED", proc.stdout)
        self.assertIn("downstream detector-gap/source-ref regeneration must stop", proc.stderr)
        self.assertIn("--named-ref-lockfile", proc.stderr)
        self.assertIn("--allow-blocked-output", proc.stderr)

    def test_cli_fixture_matches_checked_in_report(self) -> None:
        fixture_dir = FIXTURE_DIR.relative_to(ROOT)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "manifest.json"
            proc = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    "--input",
                    str(fixture_dir / "findings.json"),
                    "--named-ref-lockfile",
                    str(fixture_dir / "named_ref_locks.json"),
                    "--local-source-root",
                    str(fixture_dir / "source_root"),
                    "--local-proof",
                    str(fixture_dir / "local_proofs.json"),
                    "--out",
                    str(out),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )

            self.assertEqual(proc.returncode, 0, msg=f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
            self.assertEqual(
                json.loads(out.read_text(encoding="utf-8")),
                json.loads(REPORT_FIXTURE.read_text(encoding="utf-8")),
            )
            self.assertIn("rows=3", proc.stdout)


if __name__ == "__main__":
    unittest.main()
