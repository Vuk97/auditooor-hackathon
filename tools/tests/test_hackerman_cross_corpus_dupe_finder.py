"""Tests for ``tools/hackerman-cross-corpus-dupe-finder.py``.

Coverage (>=10 cases):

1.  ``extract_identifiers`` returns the CVE id (normalised uppercase).
2.  ``extract_identifiers`` returns the GHSA id (normalised uppercase).
3.  ``extract_identifiers`` returns the ASA id (normalised uppercase).
4.  ``extract_identifiers`` returns the ISA id (normalised uppercase).
5.  ``extract_identifiers`` returns the (repo, sha40) commit-with-repo pair.
6.  ``extract_identifiers`` returns the raw-PDF-URL lowercased.
7.  ``extract_identifiers`` returns nothing on a record with no shared id.
8.  ``iter_records`` walks all three shapes (record.json wins over yaml;
    record.yaml fallback when no json sibling; flat ``tags/<n>.yaml``).
9.  ``build_groups`` filters out single-subtree groups (intra-subtree dupes
    are NOT cross-corpus duplicates).
10. ``build_groups`` returns cross-corpus groups when an id is in >=2
    subtrees and orders by (subtree_count desc, identifier_type rank,
    identifier_value asc).
11. ``render_docs`` produces top-30 table + high-signal section + summary
    stats; mentions the gitignored JSONL path.
12. End-to-end CLI run writes both artifacts atomically and emits a stable
    summary JSON.
13. Determinism: two CLI runs over the same tree produce byte-identical
    docs and JSONL when ``--generated-at`` is pinned.
14. The COMMIT_REPO bucket only fires when BOTH a github repo coord and a
    40-hex SHA are present in the same record (bare SHA without repo is
    not collected).
15. (W2.6 2026-05-16) ``verdict_artefact: true`` filter: records carrying
    the top-level boolean marker are skipped before identifier extraction
    so they cannot form cross-corpus groups. A truthy-but-non-boolean
    value (e.g. string ``"true"``) does NOT match (strict ``is True``).
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-cross-corpus-dupe-finder.py"


def _load_tool() -> Any:
    name = "_hackerman_cross_corpus_dupes_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


def _write_record_json(tags_dir: Path, subtree: str, slug: str, body: dict) -> Path:
    rec_dir = tags_dir / subtree / slug
    rec_dir.mkdir(parents=True, exist_ok=True)
    path = rec_dir / "record.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


def _write_record_yaml(tags_dir: Path, subtree: str, slug: str, text: str) -> Path:
    rec_dir = tags_dir / subtree / slug
    rec_dir.mkdir(parents=True, exist_ok=True)
    path = rec_dir / "record.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def _write_flat_yaml(tags_dir: Path, name: str, text: str) -> Path:
    tags_dir.mkdir(parents=True, exist_ok=True)
    path = tags_dir / f"{name}.yaml"
    path.write_text(text, encoding="utf-8")
    return path


class ExtractIdentifiersTests(unittest.TestCase):

    def test_cve_normalised_upper(self):
        ids = tool.extract_identifiers("see cve-2023-39363 and also CVE-2018-10299 here")
        self.assertEqual(ids.get("CVE"), ["CVE-2018-10299", "CVE-2023-39363"])

    def test_ghsa_normalised_upper(self):
        ids = tool.extract_identifiers("ghsa-64wf-29wj-rpgx is referenced")
        self.assertEqual(ids.get("GHSA"), ["GHSA-64WF-29WJ-RPGX"])

    def test_asa_normalised_upper(self):
        ids = tool.extract_identifiers("audit shoutout asa-2024-0012 covers MaxUnpack")
        self.assertEqual(ids.get("ASA"), ["ASA-2024-0012"])

    def test_isa_normalised_upper(self):
        ids = tool.extract_identifiers("informal systems audit isa-2023-0007")
        self.assertEqual(ids.get("ISA"), ["ISA-2023-0007"])

    def test_commit_repo_pair(self):
        # 40-hex SHA, paired with a github repo coord in the same record.
        sha = "deadbeefcafe1234567890abcdef0123456789ab"  # 40 chars exact
        text = f"https://github.com/foo/bar fixed in commit {sha}"
        ids = tool.extract_identifiers(text)
        self.assertEqual(ids.get("COMMIT_REPO"), [f"foo/bar@{sha}"])

    def test_pdf_url_lowercased(self):
        text = "see https://Raw.GitHubUserContent.com/Spearbit/PDFs/Centrifuge.pdf for details"
        ids = tool.extract_identifiers(text)
        self.assertEqual(
            ids.get("PDF_URL"),
            ["https://raw.githubusercontent.com/spearbit/pdfs/centrifuge.pdf"],
        )

    def test_no_identifiers(self):
        ids = tool.extract_identifiers("nothing of note here, just prose")
        self.assertEqual(ids, {})

    def test_commit_requires_repo(self):
        # A 40-hex string without a github repo coord must NOT yield a
        # COMMIT_REPO identifier.
        sha = "deadbeefcafe1234567890abcdef0123456789ab"  # 40 chars
        text = f"fixed in {sha}"
        ids = tool.extract_identifiers(text)
        self.assertNotIn("COMMIT_REPO", ids)


class WalkerTests(unittest.TestCase):

    def test_iter_records_all_three_shapes(self):
        with tempfile.TemporaryDirectory() as td:
            tags_dir = Path(td) / "tags"
            _write_record_json(tags_dir, "alpha", "rec1", {
                "schema_version": tool.HACKERMAN_V1_SCHEMA,
                "source_audit_ref": "see CVE-2024-1111",
            })
            # YAML-only record (no JSON sibling).
            _write_record_yaml(tags_dir, "beta", "rec2", "source_audit_ref: \"CVE-2024-1111\"\n")
            # Flat root-level YAML.
            _write_flat_yaml(tags_dir, "flat1", "source_audit_ref: \"CVE-2024-1111\"\n")
            # JSON wins over YAML sibling.
            _write_record_yaml(tags_dir, "gamma", "rec3", "source_audit_ref: \"CVE-2099-9999\"\n")
            _write_record_json(tags_dir, "gamma", "rec3", {
                "source_audit_ref": "CVE-2024-1111",  # JSON wins
            })

            records = list(tool.iter_records(tags_dir))
            subtrees = sorted({s for s, _, _ in records})
            self.assertEqual(subtrees, ["__flat__", "alpha", "beta", "gamma"])
            # gamma must be the JSON copy, not the YAML one.
            gamma = [(s, p, d) for s, p, d in records if s == "gamma"]
            self.assertEqual(len(gamma), 1)
            self.assertTrue(str(gamma[0][1]).endswith("record.json"))


class BuildGroupsTests(unittest.TestCase):

    def test_single_subtree_dupes_filtered(self):
        # Two records in the SAME subtree sharing one CVE - not cross-corpus.
        with tempfile.TemporaryDirectory() as td:
            tags_dir = Path(td) / "tags"
            _write_record_json(tags_dir, "alpha", "r1", {"x": "CVE-2024-1111"})
            _write_record_json(tags_dir, "alpha", "r2", {"x": "CVE-2024-1111"})
            records = list(tool.iter_records(tags_dir))
            groups = tool.build_groups(records, tags_dir)
            self.assertEqual(groups, [])

    def test_cross_subtree_group_emitted_and_ordered(self):
        with tempfile.TemporaryDirectory() as td:
            tags_dir = Path(td) / "tags"
            # CVE-2024-1111 in 3 subtrees -> subtree_count=3 (top).
            _write_record_json(tags_dir, "alpha", "r1", {"x": "CVE-2024-1111"})
            _write_record_json(tags_dir, "beta", "r2", {"x": "CVE-2024-1111"})
            _write_record_json(tags_dir, "gamma", "r3", {"x": "CVE-2024-1111"})
            # GHSA in 2 subtrees -> subtree_count=2.
            _write_record_json(tags_dir, "alpha", "r4", {"x": "GHSA-abcd-efgh-ijkl"})
            _write_record_json(tags_dir, "beta", "r5", {"x": "GHSA-abcd-efgh-ijkl"})
            # CVE-2023-9999 in 2 subtrees -> subtree_count=2.
            _write_record_json(tags_dir, "alpha", "r6", {"x": "CVE-2023-9999"})
            _write_record_json(tags_dir, "gamma", "r7", {"x": "CVE-2023-9999"})

            records = list(tool.iter_records(tags_dir))
            groups = tool.build_groups(records, tags_dir)
            # 3 groups total.
            self.assertEqual(len(groups), 3)
            # First group has the highest subtree count.
            self.assertEqual(groups[0]["identifier_value"], "CVE-2024-1111")
            self.assertEqual(groups[0]["subtree_count"], 3)
            self.assertEqual(groups[0]["subtrees"], ["alpha", "beta", "gamma"])
            # Tie at subtree_count=2: CVE (rank 0) comes before GHSA (rank 1).
            self.assertEqual(groups[1]["identifier_type"], "CVE")
            self.assertEqual(groups[1]["identifier_value"], "CVE-2023-9999")
            self.assertEqual(groups[2]["identifier_type"], "GHSA")


class RenderDocsTests(unittest.TestCase):

    def test_docs_contain_top_table_and_summary(self):
        groups = [
            {
                "identifier_type": "CVE",
                "identifier_value": "CVE-2024-1111",
                "subtree_count": 3,
                "record_count": 3,
                "subtrees": ["alpha", "beta", "gamma"],
                "records": [
                    {"subtree": "alpha", "path": "audit/corpus_tags/tags/alpha/r1/record.json"},
                    {"subtree": "beta", "path": "audit/corpus_tags/tags/beta/r2/record.json"},
                    {"subtree": "gamma", "path": "audit/corpus_tags/tags/gamma/r3/record.json"},
                ],
            },
            {
                "identifier_type": "GHSA",
                "identifier_value": "GHSA-ABCD-EFGH-IJKL",
                "subtree_count": 2,
                "record_count": 2,
                "subtrees": ["alpha", "beta"],
                "records": [
                    {"subtree": "alpha", "path": "audit/corpus_tags/tags/alpha/r4/record.json"},
                    {"subtree": "beta", "path": "audit/corpus_tags/tags/beta/r5/record.json"},
                ],
            },
        ]
        text = tool.render_docs(groups, "2026-05-16T00:00:00Z", Path("/tmp/tags"), 5)
        self.assertIn("Hackerman Cross-Corpus Duplicates", text)
        self.assertIn("CVE-2024-1111", text)
        self.assertIn("GHSA-ABCD-EFGH-IJKL", text)
        self.assertIn("`alpha`", text)
        self.assertIn("`.auditooor/cross_corpus_dupes.jsonl`", text)
        # High-signal section lists CVE-2024-1111 (3 subtrees) but NOT the
        # GHSA group (only 2 subtrees).
        self.assertIn("High-signal advisories (>=3 subtrees)", text)
        hs_section = text.split("## High-signal advisories")[1]
        self.assertIn("CVE-2024-1111", hs_section)
        self.assertNotIn("GHSA-ABCD-EFGH-IJKL", hs_section)


class VerdictArtefactFilterTests(unittest.TestCase):
    """W2.6 (2026-05-16) regression: ``verdict_artefact: true`` excludes the
    record from dupe-finder grouping. Anchor: ASA-2024-0012 cosmos-sdk
    residual; 2 dydx-iter-2 verdict outputs cite the ASA in their slug
    but are workspace verdict outputs, not advisory records.
    """

    def test_verdict_artefact_records_skipped_strict_true(self):
        # One advisory record + one verdict-artefact record citing the
        # same identifier. The dupe-finder must NOT emit a group; the
        # verdict-artefact record is filtered before identifier extraction.
        with tempfile.TemporaryDirectory() as td:
            tags_dir = Path(td) / "tags"
            # Canonical advisory record under the cosmos_sdk_ibc subtree.
            _write_record_json(tags_dir, "cosmos_sdk_ibc", "ghsa-canonical", {
                "schema_version": tool.HACKERMAN_V1_SCHEMA,
                "source_audit_ref": "GHSA-8WCC-M6J2-QXVM aka ASA-2024-0012",
            })
            # Flat verdict-artefact YAML citing the same ASA but marked.
            _write_flat_yaml(
                tags_dir,
                "dydx-hunt-iter-2_ASA-2024-0012-verdict",
                "verdict_id: dydx-hunt-iter-2/ASA-2024-0012\n"
                "verdict_artefact: true\n"
                "target_repo: cosmos/cosmos-sdk\n",
            )
            records = list(tool.iter_records(tags_dir))
            # The flat verdict-artefact must NOT appear in the records list.
            paths = [str(p) for _, p, _ in records]
            self.assertEqual(len(records), 1, msg=f"expected 1 record, got: {paths}")
            self.assertTrue(paths[0].endswith("record.json"))
            # And no dupe group is emitted (only 1 subtree present).
            groups = tool.build_groups(records, tags_dir)
            self.assertEqual(groups, [])

    def test_verdict_artefact_marker_only_filters_strict_boolean_true(self):
        # A truthy-but-non-boolean ``"true"`` string MUST NOT filter the
        # record. This guards against accidental filter widening when
        # YAML parsing coerces unexpected scalar shapes.
        with tempfile.TemporaryDirectory() as td:
            tags_dir = Path(td) / "tags"
            # Two records share the CVE; one has verdict_artefact="true"
            # (string, NOT boolean). The string-valued one is NOT filtered;
            # the dupe-finder still emits a cross-subtree group.
            _write_record_json(tags_dir, "alpha", "r1", {
                "source_audit_ref": "CVE-2099-1111",
                "verdict_artefact": "true",  # string, not boolean
            })
            _write_record_json(tags_dir, "beta", "r2", {
                "source_audit_ref": "CVE-2099-1111",
            })
            records = list(tool.iter_records(tags_dir))
            self.assertEqual(len(records), 2)
            groups = tool.build_groups(records, tags_dir)
            self.assertEqual(len(groups), 1)
            self.assertEqual(groups[0]["identifier_value"], "CVE-2099-1111")

    def test_verdict_artefact_marker_filters_record_yaml_too(self):
        # The filter must apply to record.yaml records as well, not only
        # to flat root-level YAML files.
        with tempfile.TemporaryDirectory() as td:
            tags_dir = Path(td) / "tags"
            _write_record_json(tags_dir, "cosmos_sdk_ibc", "ghsa-c1", {
                "source_audit_ref": "ASA-2024-0012",
            })
            _write_record_yaml(
                tags_dir, "dydx_verdicts", "asa-2024-0012",
                "verdict_id: dydx-hunt-iter-2/ASA-2024-0012\n"
                "verdict_artefact: true\n"
                "source_audit_ref: ASA-2024-0012\n",
            )
            records = list(tool.iter_records(tags_dir))
            subtrees = [s for s, _, _ in records]
            # dydx_verdicts subtree must not appear (filtered).
            self.assertNotIn("dydx_verdicts", subtrees)
            self.assertEqual(subtrees, ["cosmos_sdk_ibc"])


class CliIntegrationTests(unittest.TestCase):

    def test_cli_end_to_end_writes_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            tags_dir = Path(td) / "tags"
            jsonl_out = Path(td) / "out.jsonl"
            docs_out = Path(td) / "out.md"
            _write_record_json(tags_dir, "alpha", "r1", {"x": "CVE-2024-1111"})
            _write_record_json(tags_dir, "beta", "r2", {"x": "CVE-2024-1111"})

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--tags-dir", str(tags_dir),
                    "--jsonl-out", str(jsonl_out),
                    "--docs-out", str(docs_out),
                    "--generated-at", "2026-05-16T00:00:00Z",
                ],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            summary = json.loads(proc.stdout.strip().splitlines()[-1])
            self.assertEqual(summary["records_scanned"], 2)
            self.assertEqual(summary["group_count"], 1)
            self.assertTrue(jsonl_out.exists())
            self.assertTrue(docs_out.exists())
            jsonl_lines = jsonl_out.read_text().strip().splitlines()
            # First line is the header.
            header = json.loads(jsonl_lines[0])
            self.assertEqual(header["schema_version"], tool.SCHEMA)
            self.assertEqual(header["group_count"], 1)
            group = json.loads(jsonl_lines[1])
            self.assertEqual(group["identifier_value"], "CVE-2024-1111")
            self.assertEqual(group["subtree_count"], 2)

    def test_cli_deterministic(self):
        with tempfile.TemporaryDirectory() as td:
            tags_dir = Path(td) / "tags"
            jsonl_a = Path(td) / "a.jsonl"
            docs_a = Path(td) / "a.md"
            jsonl_b = Path(td) / "b.jsonl"
            docs_b = Path(td) / "b.md"
            _write_record_json(tags_dir, "alpha", "r1", {"x": "CVE-2024-1111"})
            _write_record_json(tags_dir, "beta", "r2", {"x": "CVE-2024-1111"})

            def _run(jsonl, docs):
                return subprocess.run(
                    [
                        sys.executable, str(TOOL_PATH),
                        "--tags-dir", str(tags_dir),
                        "--jsonl-out", str(jsonl),
                        "--docs-out", str(docs),
                        "--generated-at", "2026-05-16T00:00:00Z",
                    ], capture_output=True, text=True, check=True,
                )

            _run(jsonl_a, docs_a)
            _run(jsonl_b, docs_b)
            self.assertEqual(jsonl_a.read_bytes(), jsonl_b.read_bytes())
            self.assertEqual(docs_a.read_bytes(), docs_b.read_bytes())


if __name__ == "__main__":
    unittest.main()
