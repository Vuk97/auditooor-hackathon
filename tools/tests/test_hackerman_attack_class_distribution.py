"""Tests for ``tools/hackerman-attack-class-distribution.py``.

Cases (>=10):

1. empty tags-dir -> total_records=0, no subtrees / classes / cells
2. single subdir record -> one subtree, one class, one cell
3. multi-subtree records share a class -> matrix wires both cells
4. dense mode caps columns to top-20 by total count
5. full mode emits every class
6. orphan detection: single-subtree class flagged
7. concentration detection: >=80% in one subtree (multi-subtree) flagged
8. deterministic ordering: classes sorted by (-total, name)
9. flat dsl_pattern tag with attack_classes_to_try contributes to
   ``_flat_dsl_pattern`` bucket
10. flat solodit-spec tag with single attack_class contributes to
    ``_flat_solodit_spec`` bucket
11. JSON envelope schema is ``auditooor.hackerman_attack_class_distribution.v1``
12. human table renders without crashing on empty corpus
13. record without ``attack_class`` is bucketed under
    ``<missing-attack-class>`` but does NOT appear in orphan/concentrated
    panels (sentinel filtering)
14. CLI ``--mode dense`` exit-code 0 on a populated synthetic corpus
15. record.yaml wins over record.json in the same dir (precedence)
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
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-attack-class-distribution.py"


def _load_tool() -> Any:
    name = "_hackerman_attack_class_distribution_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


def _write_subdir_record(
    tags_dir: Path,
    subtree: str,
    record_id: str,
    attack_class: str | None,
    *,
    fmt: str = "yaml",
) -> Path:
    rec_dir = tags_dir / subtree / record_id
    rec_dir.mkdir(parents=True, exist_ok=True)
    if fmt == "yaml":
        body = (
            "schema_version: auditooor.hackerman_record.v1\n"
            f"record_id: {record_id}\n"
            "target_repo: synthetic/test\n"
        )
        if attack_class is not None:
            body += f"attack_class: {attack_class}\n"
        path = rec_dir / "record.yaml"
        path.write_text(body, encoding="utf-8")
        return path
    else:
        obj: dict[str, Any] = {
            "schema_version": "auditooor.hackerman_record.v1",
            "record_id": record_id,
            "target_repo": "synthetic/test",
        }
        if attack_class is not None:
            obj["attack_class"] = attack_class
        path = rec_dir / "record.json"
        path.write_text(json.dumps(obj), encoding="utf-8")
        return path


def _write_flat_dsl_pattern(
    tags_dir: Path, slug: str, attack_classes: list[str]
) -> Path:
    body_lines = [
        f"verdict_id: \"dsl_pattern/{slug}\"",
        "target_repo: \"unknown/dsl-synthetic\"",
        "language: solidity",
        "attack_classes_to_try:",
    ]
    for ac in attack_classes:
        body_lines.append(f"- \"{ac}\"")
    path = tags_dir / f"dsl_pattern_{slug}.yaml"
    path.write_text("\n".join(body_lines) + "\n", encoding="utf-8")
    return path


def _write_flat_solodit_spec(tags_dir: Path, rid: str, attack_class: str) -> Path:
    body = (
        "schema_version: auditooor.hackerman_record.v1\n"
        f"record_id: solodit-spec:{rid}\n"
        "target_repo: synthetic/solodit\n"
        f"attack_class: {attack_class}\n"
    )
    path = tags_dir / f"solodit-spec:{rid}-{rid}.yaml"
    path.write_text(body, encoding="utf-8")
    return path


class TestAttackClassDistribution(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tags_dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # 1
    def test_empty_tags_dir(self) -> None:
        dist = tool.build_distribution(self.tags_dir)
        self.assertEqual(dist["total_records"], 0)
        self.assertEqual(dist["subtrees"], [])
        self.assertEqual(dist["classes"], [])
        self.assertEqual(dist["matrix"], {})

    # 2
    def test_single_subdir_record(self) -> None:
        _write_subdir_record(self.tags_dir, "lending", "r1", "reentrancy")
        dist = tool.build_distribution(self.tags_dir)
        self.assertEqual(dist["total_records"], 1)
        self.assertEqual(dist["subtrees"], ["lending"])
        self.assertEqual(dist["classes"], ["reentrancy"])
        self.assertEqual(dist["matrix"], {"lending": {"reentrancy": 1}})

    # 3
    def test_multi_subtree_shared_class(self) -> None:
        _write_subdir_record(self.tags_dir, "lending", "r1", "reentrancy")
        _write_subdir_record(self.tags_dir, "dex", "r2", "reentrancy")
        _write_subdir_record(self.tags_dir, "dex", "r3", "oracle")
        dist = tool.build_distribution(self.tags_dir)
        self.assertEqual(dist["total_records"], 3)
        self.assertEqual(sorted(dist["subtrees"]), ["dex", "lending"])
        # 'reentrancy' has 2, 'oracle' has 1 -> order by -total, then name
        self.assertEqual(dist["classes"], ["reentrancy", "oracle"])
        self.assertEqual(dist["matrix"]["dex"]["reentrancy"], 1)
        self.assertEqual(dist["matrix"]["dex"]["oracle"], 1)
        self.assertEqual(dist["matrix"]["lending"]["reentrancy"], 1)

    # 4
    def test_dense_mode_caps_top_20(self) -> None:
        # 25 distinct classes, one record each
        for i in range(25):
            _write_subdir_record(
                self.tags_dir, "lending", f"r{i}", f"class-{i:02d}"
            )
        dist = tool.build_distribution(self.tags_dir)
        cols = tool.select_columns(dist, "dense")
        self.assertEqual(len(cols), 20)
        full = tool.select_columns(dist, "full")
        self.assertEqual(len(full), 25)

    # 5
    def test_full_mode_emits_all(self) -> None:
        for i in range(7):
            _write_subdir_record(
                self.tags_dir, "dex", f"r{i}", f"class-{i:02d}"
            )
        dist = tool.build_distribution(self.tags_dir)
        full = tool.select_columns(dist, "full")
        self.assertEqual(len(full), 7)

    # 6
    def test_orphan_detection(self) -> None:
        _write_subdir_record(self.tags_dir, "lending", "r1", "reentrancy")
        _write_subdir_record(self.tags_dir, "lending", "r2", "reentrancy")
        _write_subdir_record(self.tags_dir, "dex", "r3", "oracle")
        _write_subdir_record(self.tags_dir, "lending", "r4", "oracle")
        dist = tool.build_distribution(self.tags_dir)
        orphans = tool.orphan_classes(dist)
        # 'reentrancy' is only in lending -> orphan
        names = [o["attack_class"] for o in orphans]
        self.assertIn("reentrancy", names)
        # 'oracle' lives in both dex + lending -> not orphan
        self.assertNotIn("oracle", names)

    # 7
    def test_concentration_detection(self) -> None:
        # 9 records of 'oracle' in lending, 1 in dex -> 90% concentrated
        for i in range(9):
            _write_subdir_record(self.tags_dir, "lending", f"l{i}", "oracle")
        _write_subdir_record(self.tags_dir, "dex", "d0", "oracle")
        # 'reentrancy' lives only in dex -> orphan, NOT concentrated
        _write_subdir_record(self.tags_dir, "dex", "d1", "reentrancy")
        dist = tool.build_distribution(self.tags_dir)
        conc = tool.concentrated_classes(dist)
        names = [r["attack_class"] for r in conc]
        self.assertIn("oracle", names)
        # Orphans excluded from concentration panel
        self.assertNotIn("reentrancy", names)
        row = next(r for r in conc if r["attack_class"] == "oracle")
        self.assertEqual(row["top_subtree"], "lending")
        self.assertGreaterEqual(row["top_subtree_pct"], 80.0)

    # 8
    def test_deterministic_class_ordering(self) -> None:
        _write_subdir_record(self.tags_dir, "lending", "r1", "zz")
        _write_subdir_record(self.tags_dir, "lending", "r2", "aa")
        _write_subdir_record(self.tags_dir, "lending", "r3", "aa")
        _write_subdir_record(self.tags_dir, "lending", "r4", "mm")
        _write_subdir_record(self.tags_dir, "lending", "r5", "mm")
        dist = tool.build_distribution(self.tags_dir)
        # aa=2 mm=2 zz=1 -> sort by (-total, name): aa, mm, zz
        self.assertEqual(dist["classes"], ["aa", "mm", "zz"])

    # 9
    def test_flat_dsl_pattern_bucket(self) -> None:
        _write_flat_dsl_pattern(
            self.tags_dir,
            "minting-unrestricted",
            ["admin-bypass", "access-control-missing-modifier"],
        )
        dist = tool.build_distribution(self.tags_dir)
        self.assertIn("_flat_dsl_pattern", dist["subtrees"])
        self.assertEqual(dist["total_records"], 1)
        cells = dist["matrix"]["_flat_dsl_pattern"]
        self.assertEqual(cells.get("admin-bypass"), 1)
        self.assertEqual(cells.get("access-control-missing-modifier"), 1)

    # 10
    def test_flat_solodit_spec_bucket(self) -> None:
        _write_flat_solodit_spec(self.tags_dir, "13467", "state-accounting-drift")
        dist = tool.build_distribution(self.tags_dir)
        self.assertIn("_flat_solodit_spec", dist["subtrees"])
        self.assertEqual(
            dist["matrix"]["_flat_solodit_spec"]["state-accounting-drift"], 1
        )

    # 11
    def test_json_envelope_schema(self) -> None:
        _write_subdir_record(self.tags_dir, "lending", "r1", "reentrancy")
        dist = tool.build_distribution(self.tags_dir)
        out = tool.render_json(dist, "dense")
        payload = json.loads(out)
        self.assertEqual(
            payload["schema"], "auditooor.hackerman_attack_class_distribution.v1"
        )
        self.assertEqual(payload["mode"], "dense")
        self.assertIn("matrix", payload)
        self.assertIn("orphan_classes", payload)
        self.assertIn("concentrated_classes", payload)
        self.assertIn("top_classes_per_subtree", payload)

    # 12
    def test_human_table_on_empty(self) -> None:
        dist = tool.build_distribution(self.tags_dir)
        # Should not crash.
        out = tool.render_human(dist, "dense")
        self.assertIn("total_records: 0", out)
        self.assertIn("Matrix", out)

    # 13
    def test_missing_attack_class_sentinel_excluded(self) -> None:
        _write_subdir_record(self.tags_dir, "lending", "r1", None)
        _write_subdir_record(self.tags_dir, "lending", "r2", None)
        dist = tool.build_distribution(self.tags_dir)
        self.assertIn(tool.MISSING_AC, dist["classes"])
        # Sentinel is excluded from orphan + concentrated panels.
        orphans = tool.orphan_classes(dist)
        self.assertNotIn(tool.MISSING_AC, [o["attack_class"] for o in orphans])
        conc = tool.concentrated_classes(dist)
        self.assertNotIn(tool.MISSING_AC, [r["attack_class"] for r in conc])

    # 13b
    def test_unknown_placeholder_class_segregated(self) -> None:
        # N unrouted ``unknown-attack`` placeholder records, plus real
        # classes: 'reentrancy' in one subtree, 'oracle' in two subtrees.
        n = 5
        for i in range(n):
            _write_subdir_record(
                self.tags_dir, "lending", f"u{i}", "unknown-attack"
            )
        _write_subdir_record(self.tags_dir, "lending", "r1", "reentrancy")
        _write_subdir_record(self.tags_dir, "dex", "o1", "oracle")
        _write_subdir_record(self.tags_dir, "lending", "o2", "oracle")
        dist = tool.build_distribution(self.tags_dir)

        # (a) placeholder absent from dense + full presentation columns
        self.assertNotIn(
            "unknown-attack", tool.select_columns(dist, "dense")
        )
        self.assertNotIn(
            "unknown-attack", tool.select_columns(dist, "full")
        )
        # real classes still present in the presentation columns
        self.assertIn("reentrancy", tool.select_columns(dist, "full"))
        self.assertIn("oracle", tool.select_columns(dist, "full"))

        # (b) not flagged as an orphan despite living in a single subtree
        orphans = [o["attack_class"] for o in tool.orphan_classes(dist)]
        self.assertNotIn("unknown-attack", orphans)

        # (c) not flagged as concentrated
        conc = [r["attack_class"] for r in tool.concentrated_classes(dist)]
        self.assertNotIn("unknown-attack", conc)

        # (d) render_json segregated panel names it + counts its records
        payload = json.loads(tool.render_json(dist, "dense"))
        seg = payload["segregated_placeholders"]
        self.assertEqual(seg["total_records"], n)
        self.assertIn("unknown-attack", seg["classes"])

        # (e) raw provenance preserved in class_totals
        self.assertEqual(dist["class_totals"]["unknown-attack"], n)

    # 14
    def test_cli_runs_clean(self) -> None:
        _write_subdir_record(self.tags_dir, "lending", "r1", "reentrancy")
        _write_subdir_record(self.tags_dir, "dex", "r2", "oracle")
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL_PATH),
                "--tags-dir",
                str(self.tags_dir),
                "--mode",
                "dense",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Matrix", proc.stdout)

        proc2 = subprocess.run(
            [
                sys.executable,
                str(TOOL_PATH),
                "--tags-dir",
                str(self.tags_dir),
                "--mode",
                "full",
                "--json",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc2.returncode, 0, proc2.stderr)
        payload = json.loads(proc2.stdout)
        self.assertEqual(
            payload["schema"],
            "auditooor.hackerman_attack_class_distribution.v1",
        )
        self.assertEqual(payload["mode"], "full")

    # 15
    def test_yaml_wins_over_json_in_same_dir(self) -> None:
        # write json first, then yaml -- yaml should be the one walked.
        _write_subdir_record(
            self.tags_dir, "lending", "r1", "json-class", fmt="json"
        )
        _write_subdir_record(
            self.tags_dir, "lending", "r1", "yaml-class", fmt="yaml"
        )
        dist = tool.build_distribution(self.tags_dir)
        self.assertEqual(dist["total_records"], 1)
        self.assertIn("yaml-class", dist["classes"])
        self.assertNotIn("json-class", dist["classes"])


if __name__ == "__main__":
    unittest.main()
