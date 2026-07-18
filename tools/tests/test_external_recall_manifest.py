"""Tests for tools/audit/external-recall-manifest.py."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "audit" / "external-recall-manifest.py"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python3", str(TOOL), *args],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


class ExternalRecallManifestCliTest(unittest.TestCase):
    def test_build_from_explicit_samples_and_validate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="external-recall-manifest-") as td:
            root = Path(td) / "repo"
            contracts = root / "contracts"
            contracts.mkdir(parents=True)
            (contracts / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
            out = root / "external_recall_manifest.json"

            proc = _run(
                "build",
                "--repo-root",
                str(root),
                "--repo-id",
                "example/vault",
                "--attack-class",
                "access-control",
                "--severity",
                "high",
                "--sample",
                "contracts/Vault.sol",
                "--out",
                str(out),
                "--json",
            )

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            result = json.loads(proc.stdout)
            self.assertTrue(result["ok"])
            self.assertEqual(result["sample_count"], 1)
            self.assertIn("--external-manifest", result["scoreboard_command"])
            manifest = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema"], "auditooor.external_recall_samples.v1")
            row = manifest["samples"][0]
            self.assertEqual(row["path"], "contracts/Vault.sol")
            self.assertEqual(row["attack_class"], "access-control")
            self.assertEqual(row["severity"], "HIGH")
            self.assertEqual(row["source"], "external_repo:example/vault")

            validate = _run("validate", str(out), "--json")
            self.assertEqual(validate.returncode, 0, validate.stdout + validate.stderr)
            self.assertTrue(json.loads(validate.stdout)["ok"])

    def test_build_preserves_source_state_evidence_for_quality_gate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="external-recall-manifest-") as td:
            root = Path(td) / "repo"
            (root / "contracts").mkdir(parents=True)
            (root / "contracts" / "Verification.sol").write_text(
                "library Verification { function isCommitmentInHeaderDigest() internal {} }\n",
                encoding="utf-8",
            )
            out = root / "manifest.json"

            proc = _run(
                "build",
                "--repo-root",
                str(root),
                "--repo-id",
                "snowbridge/snowbridge",
                "--attack-class",
                "bridge-proof-domain-bypass",
                "--severity",
                "high",
                "--sample",
                "contracts/Verification.sol",
                "--source-state",
                "pre_fix",
                "--source-state-reason",
                "parent of fix commit accepts the v1 digest tag for a v2 proof path",
                "--finding-ref",
                "Snowbridge PR #1438 Audit Issue 2",
                "--source-snapshot-ref",
                "snowbridge@4855ace3^:contracts/src/Verification.sol",
                "--vulnerable-commit",
                "4855ace3^",
                "--fix-commit",
                "4855ace34a9836e544afa1329b805f6b5d6da11e",
                "--validated-by",
                "codex",
                "--proof-ref",
                "git show 4855ace3 -- contracts/src/Verification.sol",
                "--source-ref",
                "reports/snowbridge_prefix.md",
                "--out",
                str(out),
                "--json",
            )

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            row = json.loads(out.read_text(encoding="utf-8"))["samples"][0]
            self.assertEqual(row["source_state"], "pre_fix")
            self.assertEqual(row["vulnerable_commit"], "4855ace3^")
            self.assertEqual(row["fix_commit"], "4855ace34a9836e544afa1329b805f6b5d6da11e")
            self.assertEqual(row["source_refs"], ["reports/snowbridge_prefix.md"])

            quality = subprocess.run(
                [
                    "python3",
                    str(REPO_ROOT / "tools" / "audit" / "external-recall-manifest-quality.py"),
                    str(out),
                    "--json",
                ],
                capture_output=True,
                text=True,
                cwd=REPO_ROOT,
            )
            self.assertEqual(quality.returncode, 0, quality.stdout + quality.stderr)
            payload = json.loads(quality.stdout)
            self.assertEqual(payload["summary"]["gap_eligible"], 1)
            self.assertEqual(payload["summary"]["blockers"], 0)

    def test_build_from_glob_skips_common_dependency_dirs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="external-recall-manifest-") as td:
            root = Path(td) / "repo"
            (root / "src").mkdir(parents=True)
            (root / "node_modules" / "pkg").mkdir(parents=True)
            (root / "src" / "Target.sol").write_text("contract Target {}\n", encoding="utf-8")
            (root / "node_modules" / "pkg" / "Dep.sol").write_text("contract Dep {}\n", encoding="utf-8")
            out = root / "manifest.json"

            proc = _run(
                "build",
                "--repo-root",
                str(root),
                "--repo-id",
                "example/glob",
                "--attack-class",
                "accounting-state",
                "--include",
                "**/*.sol",
                "--out",
                str(out),
                "--json",
            )

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            manifest = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual([row["path"] for row in manifest["samples"]], ["src/Target.sol"])

    def test_validate_rejects_missing_file_and_attack_class(self) -> None:
        with tempfile.TemporaryDirectory(prefix="external-recall-manifest-") as td:
            manifest = Path(td) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.external_recall_samples.v1",
                        "samples": [
                            {
                                "id": "sample-1",
                                "path": "Missing.sol",
                                "attack_class": "",
                                "severity": "HIGH",
                                "source": "external_repo:test",
                                "exclude_detector_slug": "",
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            proc = _run("validate", str(manifest), "--json")

            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertFalse(payload["ok"])
            self.assertTrue(any("file not found" in err for err in payload["errors"]))
            self.assertTrue(any("missing attack_class" in err for err in payload["errors"]))

    def test_validate_rejects_duplicate_ids(self) -> None:
        with tempfile.TemporaryDirectory(prefix="external-recall-manifest-") as td:
            root = Path(td)
            (root / "A.sol").write_text("contract A {}\n", encoding="utf-8")
            (root / "B.sol").write_text("contract B {}\n", encoding="utf-8")
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.external_recall_samples.v1",
                        "samples": [
                            {"id": "dup", "path": "A.sol", "attack_class": "x"},
                            {"id": "dup", "path": "B.sol", "attack_class": "x"},
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            proc = _run("validate", str(manifest), "--json")

            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("sample dup duplicate id", json.loads(proc.stdout)["errors"])

    def test_select_ranks_bounded_candidates_and_prints_workflow_commands(self) -> None:
        with tempfile.TemporaryDirectory(prefix="external-recall-select-") as td:
            root = Path(td) / "repo"
            (root / "contracts").mkdir(parents=True)
            (root / "contracts" / "AccessVault.sol").write_text(
                "contract AccessVault { address owner; modifier onlyOwner() { _; } }\n",
                encoding="utf-8",
            )
            (root / "contracts" / "Plain.sol").write_text(
                "contract Plain { function ping() external {} }\n",
                encoding="utf-8",
            )

            proc = _run(
                "select",
                "--repo-root",
                str(root),
                "--repo-id",
                "example/vault",
                "--attack-class",
                "access-control",
                "--limit",
                "1",
                "--out",
                "reports/example_external.json",
                "--json",
            )

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["discovered_sample_count"], 2)
            self.assertEqual(payload["selected_sample_count"], 1)
            candidate = payload["candidates"][0]
            self.assertEqual(candidate["path"], "contracts/AccessVault.sol")
            self.assertGreater(candidate["score"], 0)
            self.assertTrue(any(reason.startswith("path:") for reason in candidate["reasons"]))
            self.assertIn("--sample contracts/AccessVault.sol", payload["commands"]["build_manifest"])
            self.assertIn("external-recall-manifest.py validate", payload["commands"]["validate_manifest"])
            self.assertIn("--external-only", payload["commands"]["run_scoreboard"])

    def test_select_falls_back_when_attack_class_hints_do_not_match(self) -> None:
        with tempfile.TemporaryDirectory(prefix="external-recall-select-") as td:
            root = Path(td) / "repo"
            (root / "src").mkdir(parents=True)
            (root / "src" / "Alpha.sol").write_text("contract Alpha {}\n", encoding="utf-8")
            (root / "src" / "Beta.sol").write_text("contract Beta {}\n", encoding="utf-8")

            proc = _run(
                "select",
                "--repo-root",
                str(root),
                "--repo-id",
                "example/fallback",
                "--attack-class",
                "rare-class",
                "--limit",
                "2",
                "--json",
            )

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["selected_sample_count"], 2)
            self.assertEqual(
                {tuple(row["reasons"]) for row in payload["candidates"]},
                {("fallback:no_attack_class_hints_matched",)},
            )


if __name__ == "__main__":
    unittest.main()
