#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "klbq006-real-source-anchors.py"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("klbq006_real_source_anchors", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_module()


def _make_renft_repo(root: Path) -> tuple[Path, str]:
    repo = root / "mirrors" / "renft"
    git = repo / ".git"
    git.mkdir(parents=True)
    (git / "config").write_text(
        "[remote \"origin\"]\n\turl = https://github.com/re-nft/smart-contracts.git\n",
        encoding="utf-8",
    )
    guard = repo / "src" / "policies" / "Guard.sol"
    guard.parent.mkdir(parents=True)
    guard.write_text(
        "\n".join(
            [
                "contract Guard {",
                "  function _checkTransaction(address from, address to, bytes memory data) private view {",
                "    bytes4 selector = bytes4(data);",
                "  }",
                "  function checkTransaction(address to, uint256 value, bytes memory data) external {}",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    factory = repo / "src" / "policies" / "Factory.sol"
    factory.write_text(
        "\n".join(
            [
                "contract Factory {",
                "  address public fallbackHandler;",
                "  function deployRentalSafe() external {",
                "    bytes memory initializerPayload = abi.encode(address(fallbackHandler));",
                "  }",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    commit = "f" * 40
    return repo, commit


def _git_read_stubs(repo: Path, commit: str):
    resolved_repo = repo.resolve()

    def fake_stdout(root: Path, args: list[str]) -> str | None:
        if root.resolve() != resolved_repo:
            return None
        if args == ["config", "--get", "remote.origin.url"]:
            return "https://github.com/re-nft/smart-contracts.git"
        if args == ["rev-parse", "--verify", f"{commit}^{{commit}}"]:
            return commit
        return None

    def fake_show_text(root: Path, commit_arg: str, rel_path: str) -> str | None:
        if root.resolve() != resolved_repo or commit_arg != commit:
            return None
        path = repo / rel_path
        if not path.is_file():
            return None
        return path.read_text(encoding="utf-8")

    return patch.object(MOD, "_git_stdout", side_effect=fake_stdout), patch.object(
        MOD, "_git_show_text", side_effect=fake_show_text
    )


class Klbq006RealSourceAnchorsTest(unittest.TestCase):
    def test_reference_only_hits_do_not_satisfy_real_source_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference = root / "reference" / "patterns.dsl.r94_solodit_nft" / "renft.yaml"
            reference.parent.mkdir(parents=True)
            reference.write_text(
                "reNFT Guard does not validate setFallbackHandler(address)\n",
                encoding="utf-8",
            )
            unrelated = root / "vendor" / "openzeppelin-contracts" / "contracts" / "Account.sol"
            unrelated.parent.mkdir(parents=True)
            unrelated.write_text(
                "function _fallbackHandler(bytes4 selector) internal view returns (address) {}\n",
                encoding="utf-8",
            )

            report = MOD.build_report(roots=[root])

        self.assertEqual(report["classification"]["exact_renft_source_root"], "absent")
        self.assertEqual(report["classification"]["real_source_anchors"], "absent")
        self.assertEqual(report["classification"]["local_reference_anchors"], "present")
        self.assertEqual(report["classification"]["third_party_or_unrelated_anchor_terms"], "present")

    def test_renft_remote_with_guard_anchor_satisfies_real_source_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "mirrors" / "renft"
            git = repo / ".git"
            git.mkdir(parents=True)
            (git / "config").write_text(
                "[remote \"origin\"]\n\turl = https://github.com/code-423n4/2024-01-renft.git\n",
                encoding="utf-8",
            )
            guard = repo / "src" / "Guard.sol"
            guard.parent.mkdir(parents=True)
            guard.write_text(
                "\n".join(
                    [
                        "contract Guard {",
                        "  function checkTransaction(bytes calldata data) external {",
                        "    bytes4 selector = bytes4(data[:4]);",
                        "    if (selector == 0xf08a0323) { }",
                        "  }",
                        "}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            report = MOD.build_report(roots=[root])

        self.assertEqual(report["classification"]["exact_renft_source_root"], "present")
        self.assertEqual(report["classification"]["real_source_anchors"], "present")
        self.assertEqual(report["summary"]["candidate_renft_roots"], 1)
        self.assertEqual(report["summary"]["possible_renft_source_hits"], 2)

    def test_sibling_blob_anchor_is_not_exact_finding_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sibling = root / "detectors" / "_specs" / "drafts_solodit" / "m-08.yaml"
            sibling.parent.mkdir(parents=True)
            sibling.write_text(
                "Solodit #30535 cites https://github.com/re-nft/smart-contracts/blob/"
                "3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L195-L293\n",
                encoding="utf-8",
            )

            report = MOD.build_report(roots=[root])

        self.assertEqual(report["classification"]["exact_finding_github_blob_anchors"], "absent")
        self.assertEqual(report["classification"]["renft_base_github_blob_anchors"], "present")
        self.assertEqual(report["summary"]["renft_base_github_blob_anchors"], 1)

    def test_generated_docs_do_not_satisfy_exact_finding_blob_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            generated = root / "docs" / "KLBQ_006_REAL_SOURCE_ANCHORS_2026-05-05.md"
            generated.parent.mkdir(parents=True)
            generated.write_text(
                "Solodit #30522 follow-up cites https://github.com/re-nft/smart-contracts/blob/"
                "3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L195-L293\n",
                encoding="utf-8",
            )

            report = MOD.build_report(roots=[root])

        self.assertEqual(report["classification"]["exact_finding_github_blob_anchors"], "absent")
        self.assertEqual(report["classification"]["renft_base_github_blob_anchors"], "present")
        self.assertFalse(report["renft_github_blob_anchors"][0]["exact_finding_anchor_eligible"])

    def test_source_spec_can_satisfy_exact_finding_blob_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_spec = (
                root
                / "detectors"
                / "_specs"
                / "drafts_solodit"
                / "h-02-an-attacker-is-able-to-hijack-any-erc721-erc1155-he-borrows.yaml"
            )
            source_spec.parent.mkdir(parents=True)
            source_spec.write_text(
                "Solodit #30522 cites https://github.com/re-nft/smart-contracts/blob/"
                "3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L195-L293\n",
                encoding="utf-8",
            )

            report = MOD.build_report(roots=[root])

        self.assertEqual(report["classification"]["exact_finding_github_blob_anchors"], "present")
        self.assertEqual(report["classification"]["exact_finding_source_specs"], "eligible")
        self.assertEqual(report["summary"]["eligible_exact_finding_source_specs"], 1)
        self.assertTrue(report["renft_github_blob_anchors"][0]["exact_finding_anchor_eligible"])
        self.assertTrue(
            report["exact_finding_source_spec_candidates"][0][
                "exact_source_spec_eligible_for_replay"
            ]
        )

    def test_exact_source_spec_without_line_anchor_is_disqualified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_spec = (
                root
                / "detectors"
                / "_specs"
                / "drafts_solodit"
                / "h-02-an-attacker-is-able-to-hijack-any-erc721-erc1155-he-borrows.yaml"
            )
            source_spec.parent.mkdir(parents=True)
            source_spec.write_text(
                "\n".join(
                    [
                        'source: "Solodit #30522 (Code4rena/reNFT)"',
                        'solodit_id: "30522"',
                        "help: |",
                        "  missing validation on setFallbackHandler(address)",
                        "source_url: https://solodit.cyfrin.io/issues/h-02-code4rena-renft",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            report = MOD.build_report(roots=[root])

        self.assertEqual(report["classification"]["exact_finding_source_specs"], "ineligible_present")
        self.assertEqual(report["summary"]["exact_finding_source_spec_candidates"], 1)
        self.assertEqual(report["summary"]["eligible_exact_finding_source_specs"], 0)
        candidate = report["absence_proof"]["disqualified_exact_source_spec_candidates"][0]
        self.assertEqual(candidate["source_artifact_kind"], "detector_source_spec")
        self.assertIn(
            "source spec has no line-level reNFT Guard.sol or Factory.sol citation",
            candidate["disqualification_reasons"],
        )
        self.assertIn("source spec has no GitHub blob citation", candidate["disqualification_reasons"])

    def test_solodit_raw_metadata_without_renft_line_anchor_is_ineligible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata = root / "patterns" / "fixtures" / "auto" / "finding_30522.meta.json"
            metadata.parent.mkdir(parents=True)
            metadata.write_text(
                "{\n"
                '  "fid": "30522",\n'
                '  "source": "solodit_raw",\n'
                '  "title": "[H-02] setFallbackHandler missing validation",\n'
                '  "url": "github.com/safe-global/safe-contracts/blob/'
                'b140318af6581e499506b11128a892e3f7a52aeb/contracts/base/FallbackManager.sol#",\n'
                '  "owner": "safe-global",\n'
                '  "repo": "safe-contracts",\n'
                '  "commit": "b140318af6581e499506b11128a892e3f7a52aeb"\n'
                "}\n",
                encoding="utf-8",
            )

            report = MOD.build_report(roots=[root])

        self.assertEqual(report["classification"]["exact_finding_github_blob_anchors"], "absent")
        self.assertEqual(report["classification"]["exact_finding_source_metadata"], "ineligible_present")
        self.assertEqual(report["summary"]["exact_finding_source_metadata_candidates"], 1)
        candidate = report["exact_finding_source_metadata_candidates"][0]
        self.assertFalse(candidate["exact_source_metadata_eligible_for_replay"])
        self.assertIn("metadata blob is not re-nft/smart-contracts", candidate["disqualification_reasons"])
        self.assertIn("metadata blob has no file-line range", candidate["disqualification_reasons"])
        self.assertIn("remaining_missing_inputs", report["absence_proof"])

    def test_solodit_raw_metadata_with_guard_line_anchor_is_eligible_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata = root / "patterns" / "fixtures" / "auto" / "finding_30522.meta.json"
            metadata.parent.mkdir(parents=True)
            metadata.write_text(
                "{\n"
                '  "fid": "30522",\n'
                '  "source": "solodit_raw",\n'
                '  "title": "[H-02] setFallbackHandler missing validation",\n'
                '  "url": "https://github.com/re-nft/smart-contracts/blob/'
                '3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L195-L293",\n'
                '  "owner": "re-nft",\n'
                '  "repo": "smart-contracts",\n'
                '  "commit": "3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291"\n'
                "}\n",
                encoding="utf-8",
            )

            report = MOD.build_report(roots=[root])

        self.assertEqual(report["classification"]["exact_finding_source_metadata"], "eligible")
        self.assertEqual(report["summary"]["eligible_exact_finding_source_metadata"], 1)
        self.assertTrue(
            report["exact_finding_source_metadata_candidates"][0][
                "exact_source_metadata_eligible_for_replay"
            ]
        )
        self.assertEqual(
            report["classification"]["exact_citation_local_ref_resolution"],
            "unresolved",
        )
        self.assertIn(
            "local checkout/ref verification for the exact Solodit #30522 citation",
            report["absence_proof"]["remaining_missing_inputs"],
        )

    def test_pinned_local_mirror_derives_canonical_source_anchors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, commit = _make_renft_repo(root)

            stdout_stub, show_stub = _git_read_stubs(repo, commit)
            with stdout_stub, show_stub:
                report = MOD.build_report(roots=[root], pinned_refs=[commit])

        self.assertEqual(report["classification"]["canonical_local_source_anchors"], "present")
        anchors = report["canonical_local_source_anchors"]
        self.assertGreaterEqual(len(anchors), 3)
        first = anchors[0]
        self.assertEqual(first["repo"], "re-nft/smart-contracts")
        self.assertEqual(first["remote"], "https://github.com/re-nft/smart-contracts.git")
        self.assertEqual(first["commit"], commit)
        self.assertIn(first["path"], {"src/policies/Factory.sol", "src/policies/Guard.sol"})
        self.assertIsInstance(first["line_start"], int)
        self.assertEqual(first["line_start"], first["line_end"])
        self.assertIn("/blob/", first["url"])
        self.assertNotIn("local_path", first)
        self.assertTrue(first["advisory_only"])

    def test_exact_source_spec_blob_range_resolves_against_local_pinned_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, commit = _make_renft_repo(root)
            source_spec = (
                root
                / "detectors"
                / "_specs"
                / "drafts_solodit"
                / "h-02-an-attacker-is-able-to-hijack-any-erc721-erc1155-he-borrows.yaml"
            )
            source_spec.parent.mkdir(parents=True)
            source_spec.write_text(
                "Solodit #30522 cites https://github.com/re-nft/smart-contracts/blob/"
                f"{commit}/src/policies/Guard.sol#L2-L3\n",
                encoding="utf-8",
            )

            stdout_stub, show_stub = _git_read_stubs(repo, commit)
            with stdout_stub, show_stub:
                report = MOD.build_report(roots=[root])

        cited = [
            anchor
            for anchor in report["canonical_local_source_anchors"]
            if anchor["anchor_kind"] == "cited_blob_range"
        ]
        self.assertEqual(len(cited), 1)
        self.assertEqual(cited[0]["commit"], commit)
        self.assertEqual(cited[0]["path"], "src/policies/Guard.sol")
        self.assertEqual(cited[0]["line_start"], 2)
        self.assertEqual(cited[0]["line_end"], 3)
        self.assertIn("_checkTransaction", cited[0]["snippet"])

    def test_missing_local_ref_degrades_without_source_anchors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, commit = _make_renft_repo(root)

            stdout_stub, show_stub = _git_read_stubs(repo, commit)
            with stdout_stub, show_stub:
                report = MOD.build_report(roots=[root], pinned_refs=["missing-ref"], max_hits=20)

        self.assertEqual(report["classification"]["canonical_local_source_anchors"], "absent")
        statuses = {
            record["ref"]: record["status"]
            for record in report["local_source_anchor_resolution"]
        }
        self.assertEqual(statuses["missing-ref"], "missing_local_ref")


if __name__ == "__main__":
    unittest.main()
