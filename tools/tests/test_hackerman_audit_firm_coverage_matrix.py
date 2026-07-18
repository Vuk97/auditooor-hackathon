"""Tests for ``tools/hackerman-audit-firm-coverage-matrix.py``.

Wave-1 hackerman capability lift (PR #726). The tool walks
``audit/corpus_tags/tags/audit_firm_public_reports/**/record.{yaml,json}``
and builds a per-firm x per-project coverage matrix used to classify
projects by cross-firm-coverage (3+-firm anchors vs 1-firm-only).

Cases (>=8):

1.  Tags-dir without the ``audit_firm_public_reports`` subtree -> empty
    matrix, render_human survives.
2.  Single subdir record -> one project, one firm, count=1.
3.  Project audited by 3 different firms -> bucketed into 3plus_firm,
    distinct_firms=3.
4.  Project audited by 2 firms -> bucketed into 2_firm.
5.  Project audited by 1 firm only -> bucketed into 1_firm.
6.  Project-name extraction from ``attacker_action_sequence`` regex
    works; normalisation strips leading date tokens, trailing
    ``securityreview`` / ``Final Audit Report`` / ``Audit`` suffixes.
7.  Project-name fallback to ``required_preconditions`` (Inferred
    project name X) when action sentence is missing.
8.  Project-name fallback to ``record_id`` slug parse when both action
    sentence and preconditions are missing; firm prefix is stripped.
9.  Case-insensitive project merging: ``Ethena`` and ``ethena`` merge
    to one project keyed by lowercase; display form is first-seen
    casing.
10. ``record.yaml`` wins over ``record.json`` in the same dir.
11. Records OUTSIDE ``audit_firm_public_reports`` are ignored.
12. JSON envelope schema is
    ``auditooor.hackerman_audit_firm_coverage_matrix.v1``.
13. CLI default human render exit-code 0 on a populated synthetic
    corpus.
14. CLI ``--json`` emits valid JSON envelope on stdout.
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
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-audit-firm-coverage-matrix.py"


def _load_tool() -> Any:
    name = "_hackerman_audit_firm_coverage_matrix_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


_SUBTREE = "audit_firm_public_reports"


def _write_record(
    tags_dir: Path,
    firm: str,
    slug: str,
    *,
    project_name: str | None = None,
    inferred_project: str | None = None,
    fmt: str = "json",
    in_subtree: bool = True,
    yaml_wins: bool = False,
    project_name_yaml: str | None = None,
) -> Path:
    """Create a record under ``audit_firm_public_reports/<firm>__<slug>-<hash>/``.

    ``in_subtree=False`` writes the record under a sibling subtree to
    verify the tool ignores it.

    ``yaml_wins=True`` writes BOTH ``record.json`` and ``record.yaml``;
    the yaml uses ``project_name_yaml`` so the test can verify
    precedence.
    """
    rec_hash = f"{abs(hash(slug)):x}"[:12]
    subtree = _SUBTREE if in_subtree else "other_subtree"
    rec_dir = tags_dir / subtree / f"{firm}__{slug}-{rec_hash}"
    rec_dir.mkdir(parents=True, exist_ok=True)
    record_id = f"audit-firm:{firm}:{slug}:{rec_hash}"

    def _obj(name: str | None) -> dict[str, Any]:
        obj: dict[str, Any] = {
            "schema_version": "auditooor.hackerman_record.v1",
            "record_id": record_id,
        }
        if name is not None:
            obj["attacker_action_sequence"] = (
                "Audit-firm public report indexed for the Hackerman "
                f"corpus. Report published in unknown-date covering "
                f"project '{name}'. PDF/markdown content not parsed "
                "at this stage; ..."
            )
        if inferred_project is not None:
            obj["required_preconditions"] = [
                f"Inferred project name {inferred_project}",
            ]
        return obj

    json_path = rec_dir / "record.json"
    yaml_path = rec_dir / "record.yaml"

    if yaml_wins:
        # Write both; YAML should win.
        json_path.write_text(json.dumps(_obj(project_name)), encoding="utf-8")
        yaml_obj = _obj(project_name_yaml)
        try:
            import yaml  # type: ignore[import-not-found]
            yaml_path.write_text(
                yaml.safe_dump(yaml_obj, sort_keys=False),
                encoding="utf-8",
            )
        except Exception:  # noqa: BLE001
            # Fallback to a minimal YAML that the tool's fallback
            # parser handles (top-level scalars only).
            lines = [
                "schema_version: auditooor.hackerman_record.v1",
                f"record_id: {record_id}",
            ]
            if project_name_yaml is not None:
                action = (
                    "covering project '" + project_name_yaml + "'"
                )
                lines.append(
                    "attacker_action_sequence: '" + action + "'"
                )
            yaml_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return yaml_path

    if fmt == "yaml":
        try:
            import yaml  # type: ignore[import-not-found]
            yaml_path.write_text(
                yaml.safe_dump(_obj(project_name), sort_keys=False),
                encoding="utf-8",
            )
        except Exception:  # noqa: BLE001
            lines = [
                "schema_version: auditooor.hackerman_record.v1",
                f"record_id: {record_id}",
            ]
            if project_name is not None:
                action = "covering project '" + project_name + "'"
                lines.append(
                    "attacker_action_sequence: '" + action + "'"
                )
            yaml_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return yaml_path

    json_path.write_text(json.dumps(_obj(project_name)), encoding="utf-8")
    return json_path


class CoverageMatrixTests(unittest.TestCase):
    def test_01_empty_tags_dir_survives(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags = Path(td) / "tags"
            tags.mkdir()
            stats = tool.build_matrix(tags)
            self.assertEqual(stats["total_records"], 0)
            self.assertEqual(stats["total_projects"], 0)
            self.assertEqual(stats["total_firms"], 0)
            # human render should not raise.
            self.assertIn("total_records: 0", tool.render_human(stats))

    def test_02_single_subdir_record(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags = Path(td) / "tags"
            tags.mkdir()
            _write_record(
                tags,
                "trailofbits-publications",
                "looksrare",
                project_name="LooksRare",
            )
            stats = tool.build_matrix(tags)
            self.assertEqual(stats["total_records"], 1)
            self.assertEqual(stats["total_projects"], 1)
            self.assertEqual(stats["total_firms"], 1)
            self.assertEqual(
                stats["project_totals"].get("LooksRare"), 1
            )
            self.assertEqual(
                stats["project_firm_counts"].get("LooksRare"), 1
            )
            self.assertIn("LooksRare", stats["coverage_buckets"]["1_firm"])

    def test_03_three_firm_project_bucketed_high(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags = Path(td) / "tags"
            tags.mkdir()
            for firm, slug in [
                ("trailofbits-publications", "looksrare"),
                ("sherlock-reports", "looksrare-final"),
                ("spearbit-portfolio", "looksrare-review"),
            ]:
                _write_record(
                    tags, firm, slug, project_name="LooksRare"
                )
            stats = tool.build_matrix(tags)
            self.assertEqual(stats["total_records"], 3)
            self.assertEqual(stats["total_projects"], 1)
            self.assertEqual(
                stats["project_firm_counts"]["LooksRare"], 3
            )
            self.assertIn(
                "LooksRare", stats["coverage_buckets"]["3plus_firm"]
            )
            self.assertNotIn(
                "LooksRare", stats["coverage_buckets"]["2_firm"]
            )

    def test_04_two_firm_project_bucketed_medium(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags = Path(td) / "tags"
            tags.mkdir()
            _write_record(
                tags, "pashov-audits", "ethena-1",
                project_name="Ethena",
            )
            _write_record(
                tags, "zellic-publications", "ethena-zellic",
                project_name="Ethena",
            )
            stats = tool.build_matrix(tags)
            self.assertEqual(
                stats["project_firm_counts"]["Ethena"], 2
            )
            self.assertIn("Ethena", stats["coverage_buckets"]["2_firm"])
            self.assertNotIn(
                "Ethena", stats["coverage_buckets"]["3plus_firm"]
            )
            self.assertNotIn(
                "Ethena", stats["coverage_buckets"]["1_firm"]
            )

    def test_05_one_firm_only_bucketed_low(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags = Path(td) / "tags"
            tags.mkdir()
            _write_record(
                tags, "pashov-audits", "morpho-1",
                project_name="Morpho",
            )
            _write_record(
                tags, "pashov-audits", "morpho-2",
                project_name="Morpho",
            )
            stats = tool.build_matrix(tags)
            # Same firm twice => still 1 distinct firm.
            self.assertEqual(
                stats["project_firm_counts"]["Morpho"], 1
            )
            self.assertEqual(
                stats["project_totals"]["Morpho"], 2
            )
            self.assertIn(
                "Morpho", stats["coverage_buckets"]["1_firm"]
            )

    def test_06_project_name_normalisation(self) -> None:
        # Direct normalisation unit checks.
        self.assertEqual(
            tool._normalize_project_name("06 10 bunni .1"),
            "bunni .1".rstrip(" .,-_"),
        )
        # Two date-token leading: stripped.
        self.assertTrue(
            tool._normalize_project_name(
                "04 balancer balancerv2"
            )
            .lower()
            .startswith("balancer")
        )
        # Trailing securityreview tail.
        self.assertEqual(
            tool._normalize_project_name(
                "Aave V3 securityreview"
            ).lower(),
            "aave v3",
        )
        # Trailing Audit Report suffix.
        self.assertEqual(
            tool._normalize_project_name("Ethena Audit Report"),
            "Ethena",
        )
        # Empty / whitespace -> empty.
        self.assertEqual(tool._normalize_project_name("   "), "")

    def test_07_project_name_falls_back_to_preconditions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags = Path(td) / "tags"
            tags.mkdir()
            # No action sentence; only an inferred-project precondition.
            _write_record(
                tags, "zellic-publications", "myproj",
                project_name=None,
                inferred_project="MyProj",
            )
            stats = tool.build_matrix(tags)
            self.assertEqual(stats["total_records"], 1)
            self.assertIn("MyProj", stats["project_totals"])

    def test_08_project_name_falls_back_to_slug(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags = Path(td) / "tags"
            tags.mkdir()
            # No action sentence, no preconditions -> slug fallback
            # via record_id parse.  Firm prefix stripped.
            _write_record(
                tags, "chainsecurity-audits",
                "chainsecurity_blockimmo",
                project_name=None,
            )
            stats = tool.build_matrix(tags)
            self.assertEqual(stats["total_records"], 1)
            # Slug ``chainsecurity_blockimmo`` -> firm prefix stripped
            # -> ``Blockimmo`` (title-cased).
            self.assertIn("Blockimmo", stats["project_totals"])

    def test_09_case_insensitive_project_merging(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags = Path(td) / "tags"
            tags.mkdir()
            _write_record(
                tags, "pashov-audits", "ethena-a",
                project_name="Ethena",
            )
            _write_record(
                tags, "zellic-publications", "ethena-b",
                project_name="ethena",
            )
            stats = tool.build_matrix(tags)
            # Should merge to one project (first-seen casing wins).
            self.assertEqual(stats["total_projects"], 1)
            keys = list(stats["project_totals"].keys())
            self.assertEqual(len(keys), 1)
            self.assertEqual(keys[0].lower(), "ethena")
            self.assertEqual(
                stats["project_firm_counts"][keys[0]], 2
            )

    def test_10_yaml_wins_over_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags = Path(td) / "tags"
            tags.mkdir()
            _write_record(
                tags, "pashov-audits", "double",
                project_name="FROM_JSON",
                yaml_wins=True,
                project_name_yaml="FROM_YAML",
            )
            stats = tool.build_matrix(tags)
            self.assertEqual(stats["total_records"], 1)
            self.assertIn("FROM_YAML", stats["project_totals"])
            self.assertNotIn("FROM_JSON", stats["project_totals"])

    def test_11_records_outside_subtree_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags = Path(td) / "tags"
            tags.mkdir()
            _write_record(
                tags, "trailofbits-publications", "real",
                project_name="Real",
            )
            _write_record(
                tags, "trailofbits-publications", "ignored",
                project_name="Ignored",
                in_subtree=False,
            )
            stats = tool.build_matrix(tags)
            self.assertEqual(stats["total_records"], 1)
            self.assertIn("Real", stats["project_totals"])
            self.assertNotIn("Ignored", stats["project_totals"])

    def test_12_json_envelope_schema(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags = Path(td) / "tags"
            tags.mkdir()
            _write_record(
                tags, "pashov-audits", "p",
                project_name="Proj",
            )
            stats = tool.build_matrix(tags)
            payload = json.loads(tool.render_json(stats))
            self.assertEqual(
                payload["schema"],
                "auditooor.hackerman_audit_firm_coverage_matrix.v1",
            )
            self.assertIn("matrix", payload)
            self.assertIn("coverage_buckets", payload)
            self.assertIn("top_projects", payload)

    def test_13_cli_default_human_render_rc_zero(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags = Path(td) / "tags"
            tags.mkdir()
            _write_record(
                tags, "pashov-audits", "p1",
                project_name="P1",
            )
            _write_record(
                tags, "zellic-publications", "p1z",
                project_name="P1",
            )
            res = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--tags-dir",
                    str(tags),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("Hackerman audit-firm coverage matrix", res.stdout)
            self.assertIn("P1", res.stdout)

    def test_14_cli_json_emits_valid_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags = Path(td) / "tags"
            tags.mkdir()
            _write_record(
                tags, "trailofbits-publications", "looksrare",
                project_name="LooksRare",
            )
            _write_record(
                tags, "sherlock-reports", "lr2",
                project_name="LooksRare",
            )
            _write_record(
                tags, "spearbit-portfolio", "lr3",
                project_name="LooksRare",
            )
            res = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--tags-dir",
                    str(tags),
                    "--json",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            payload = json.loads(res.stdout)
            self.assertEqual(
                payload["schema"],
                "auditooor.hackerman_audit_firm_coverage_matrix.v1",
            )
            self.assertEqual(payload["total_records"], 3)
            self.assertIn("LooksRare", payload["matrix"])
            self.assertEqual(
                payload["project_firm_counts"]["LooksRare"], 3
            )


if __name__ == "__main__":
    unittest.main()
