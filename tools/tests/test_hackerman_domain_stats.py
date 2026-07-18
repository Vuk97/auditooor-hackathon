"""Tests for ``tools/hackerman-domain-stats.py``.

Cases (>=8):

1. empty tags-dir -> total_records=0, no domains
2. single subdir record -> one domain, one record
3. multi-domain multi-tier records aggregate cleanly across all roll-ups
4. record without ``target_domain`` is bucketed under ``<missing-target-domain>``
5. record without ``record_tier`` is bucketed under ``<missing-record-tier>``
6. deterministic ordering: domains sorted by (-count, name)
7. flat dsl_pattern tag contributes to ``_flat_dsl_pattern`` bucket
8. flat solodit-spec tag contributes to ``_flat_solodit_spec`` bucket
9. JSON envelope schema is ``auditooor.hackerman_domain_stats.v1``
10. human render works on empty corpus + populated corpus
11. record.yaml wins over record.json in the same dir (precedence)
12. CLI ``--json`` exit-code 0 on a populated synthetic corpus
13. ``--out-json`` writes the envelope to disk and matches stdout payload
14. top_domains payload respects ``--top-n`` ranking and is deterministic
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
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-domain-stats.py"


def _load_tool() -> Any:
    name = "_hackerman_domain_stats_test_mod"
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
    *,
    target_domain: str | None = None,
    record_tier: str | None = None,
    fmt: str = "yaml",
) -> Path:
    rec_dir = tags_dir / subtree / record_id
    rec_dir.mkdir(parents=True, exist_ok=True)
    if fmt == "yaml":
        lines = [
            "schema_version: auditooor.hackerman_record.v1",
            f"record_id: {record_id}",
            "target_repo: synthetic/test",
        ]
        if target_domain is not None:
            lines.append(f"target_domain: {target_domain}")
        if record_tier is not None:
            lines.append(f"record_tier: {record_tier}")
        path = rec_dir / "record.yaml"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path
    obj: dict[str, Any] = {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": record_id,
        "target_repo": "synthetic/test",
    }
    if target_domain is not None:
        obj["target_domain"] = target_domain
    if record_tier is not None:
        obj["record_tier"] = record_tier
    path = rec_dir / "record.json"
    path.write_text(json.dumps(obj), encoding="utf-8")
    return path


def _write_flat_dsl_pattern(
    tags_dir: Path,
    slug: str,
    target_domain: str | None,
    record_tier: str | None = None,
) -> Path:
    body_lines = [
        f"verdict_id: \"dsl_pattern/{slug}\"",
        "target_repo: \"unknown/dsl-synthetic\"",
        "language: solidity",
    ]
    if target_domain is not None:
        body_lines.append(f"target_domain: {target_domain}")
    if record_tier is not None:
        body_lines.append(f"record_tier: {record_tier}")
    path = tags_dir / f"dsl_pattern_{slug}.yaml"
    path.write_text("\n".join(body_lines) + "\n", encoding="utf-8")
    return path


def _write_flat_solodit_spec(
    tags_dir: Path,
    rid: str,
    target_domain: str | None,
) -> Path:
    lines = [
        "schema_version: auditooor.hackerman_record.v1",
        f"record_id: solodit-spec:{rid}",
        "target_repo: synthetic/solodit",
    ]
    if target_domain is not None:
        lines.append(f"target_domain: {target_domain}")
    path = tags_dir / f"solodit-spec:{rid}-{rid}.yaml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


class TestHackermanDomainStats(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tags_dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # 1
    def test_empty_tags_dir(self) -> None:
        stats = tool.build_stats(self.tags_dir)
        self.assertEqual(stats["total_records"], 0)
        self.assertEqual(stats["domains"], [])
        self.assertEqual(stats["domain_totals"], {})
        self.assertEqual(stats["domain_by_tier"], {})
        self.assertEqual(stats["domain_by_subtree"], {})
        self.assertEqual(stats["tier_totals"], {})
        self.assertEqual(stats["subtree_totals"], {})

    # 2
    def test_single_subdir_record(self) -> None:
        _write_subdir_record(
            self.tags_dir,
            "lending",
            "r1",
            target_domain="lending",
            record_tier="T1",
        )
        stats = tool.build_stats(self.tags_dir)
        self.assertEqual(stats["total_records"], 1)
        self.assertEqual(stats["domains"], ["lending"])
        self.assertEqual(stats["domain_totals"], {"lending": 1})
        self.assertEqual(stats["domain_by_tier"]["lending"], {"T1": 1})
        self.assertEqual(stats["domain_by_subtree"]["lending"], {"lending": 1})
        self.assertEqual(stats["tier_totals"], {"T1": 1})
        self.assertEqual(stats["subtree_totals"], {"lending": 1})

    # 3
    def test_multi_domain_multi_tier_aggregation(self) -> None:
        _write_subdir_record(
            self.tags_dir, "lending", "r1",
            target_domain="lending", record_tier="T1",
        )
        _write_subdir_record(
            self.tags_dir, "lending", "r2",
            target_domain="lending", record_tier="T2",
        )
        _write_subdir_record(
            self.tags_dir, "dex", "r3",
            target_domain="dex", record_tier="T1",
        )
        _write_subdir_record(
            self.tags_dir, "vault_subdir", "r4",
            target_domain="vault", record_tier="T1",
        )
        stats = tool.build_stats(self.tags_dir)
        self.assertEqual(stats["total_records"], 4)
        # lending=2, dex=1, vault=1 -> sort by (-total, name): lending, dex, vault
        self.assertEqual(stats["domains"], ["lending", "dex", "vault"])
        self.assertEqual(stats["domain_totals"]["lending"], 2)
        self.assertEqual(stats["domain_by_tier"]["lending"], {"T1": 1, "T2": 1})
        self.assertEqual(stats["domain_by_subtree"]["dex"], {"dex": 1})
        self.assertEqual(stats["domain_by_subtree"]["vault"], {"vault_subdir": 1})
        self.assertEqual(stats["tier_totals"], {"T1": 3, "T2": 1})

    # 4
    def test_missing_target_domain_sentinel(self) -> None:
        _write_subdir_record(self.tags_dir, "lending", "r1", record_tier="T1")
        stats = tool.build_stats(self.tags_dir)
        self.assertEqual(stats["total_records"], 1)
        self.assertIn(tool.MISSING_DOMAIN, stats["domains"])
        self.assertEqual(stats["domain_totals"][tool.MISSING_DOMAIN], 1)

    # 5
    def test_missing_record_tier_sentinel(self) -> None:
        _write_subdir_record(
            self.tags_dir, "lending", "r1", target_domain="lending"
        )
        stats = tool.build_stats(self.tags_dir)
        self.assertIn(tool.MISSING_TIER, stats["tier_totals"])
        self.assertEqual(stats["tier_totals"][tool.MISSING_TIER], 1)
        self.assertEqual(
            stats["domain_by_tier"]["lending"], {tool.MISSING_TIER: 1}
        )

    # 6
    def test_deterministic_domain_ordering(self) -> None:
        # zz=1, aa=2, mm=2 -> aa, mm, zz
        _write_subdir_record(
            self.tags_dir, "s", "r1", target_domain="zz", record_tier="T1"
        )
        _write_subdir_record(
            self.tags_dir, "s", "r2", target_domain="aa", record_tier="T1"
        )
        _write_subdir_record(
            self.tags_dir, "s", "r3", target_domain="aa", record_tier="T1"
        )
        _write_subdir_record(
            self.tags_dir, "s", "r4", target_domain="mm", record_tier="T1"
        )
        _write_subdir_record(
            self.tags_dir, "s", "r5", target_domain="mm", record_tier="T1"
        )
        stats = tool.build_stats(self.tags_dir)
        self.assertEqual(stats["domains"], ["aa", "mm", "zz"])

    # 7
    def test_flat_dsl_pattern_bucket(self) -> None:
        _write_flat_dsl_pattern(
            self.tags_dir, "minting-unrestricted", target_domain="stablecoin"
        )
        stats = tool.build_stats(self.tags_dir)
        self.assertEqual(stats["total_records"], 1)
        self.assertIn("_flat_dsl_pattern", stats["subtree_totals"])
        self.assertEqual(stats["subtree_totals"]["_flat_dsl_pattern"], 1)
        self.assertEqual(
            stats["domain_by_subtree"]["stablecoin"],
            {"_flat_dsl_pattern": 1},
        )

    # 8
    def test_flat_solodit_spec_bucket(self) -> None:
        _write_flat_solodit_spec(self.tags_dir, "13467", target_domain="dex")
        stats = tool.build_stats(self.tags_dir)
        self.assertIn("_flat_solodit_spec", stats["subtree_totals"])
        self.assertEqual(
            stats["domain_by_subtree"]["dex"], {"_flat_solodit_spec": 1}
        )

    # 9
    def test_json_envelope_schema(self) -> None:
        _write_subdir_record(
            self.tags_dir, "lending", "r1",
            target_domain="lending", record_tier="T1",
        )
        stats = tool.build_stats(self.tags_dir)
        out = tool.render_json(stats)
        payload = json.loads(out)
        self.assertEqual(payload["schema"], "auditooor.hackerman_domain_stats.v1")
        self.assertIn("domain_totals", payload)
        self.assertIn("domain_by_tier", payload)
        self.assertIn("domain_by_subtree", payload)
        self.assertIn("top_domains", payload)
        self.assertIn("tier_totals", payload)
        self.assertIn("subtree_totals", payload)

    # 10
    def test_human_render(self) -> None:
        # empty
        stats_empty = tool.build_stats(self.tags_dir)
        out_empty = tool.render_human(stats_empty)
        self.assertIn("total_records: 0", out_empty)
        self.assertIn("Domains by record count", out_empty)
        # populated
        _write_subdir_record(
            self.tags_dir, "lending", "r1",
            target_domain="lending", record_tier="T1",
        )
        stats = tool.build_stats(self.tags_dir)
        out = tool.render_human(stats)
        self.assertIn("lending", out)
        self.assertIn("total_records: 1", out)

    # 11
    def test_yaml_wins_over_json_in_same_dir(self) -> None:
        _write_subdir_record(
            self.tags_dir, "lending", "r1",
            target_domain="json-domain", fmt="json",
        )
        _write_subdir_record(
            self.tags_dir, "lending", "r1",
            target_domain="yaml-domain", fmt="yaml",
        )
        stats = tool.build_stats(self.tags_dir)
        self.assertEqual(stats["total_records"], 1)
        self.assertIn("yaml-domain", stats["domains"])
        self.assertNotIn("json-domain", stats["domains"])

    # 12
    def test_cli_runs_clean(self) -> None:
        _write_subdir_record(
            self.tags_dir, "lending", "r1",
            target_domain="lending", record_tier="T1",
        )
        _write_subdir_record(
            self.tags_dir, "dex", "r2",
            target_domain="dex", record_tier="T2",
        )
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL_PATH),
                "--tags-dir",
                str(self.tags_dir),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("target_domain", proc.stdout)
        proc2 = subprocess.run(
            [
                sys.executable,
                str(TOOL_PATH),
                "--tags-dir",
                str(self.tags_dir),
                "--json",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc2.returncode, 0, proc2.stderr)
        payload = json.loads(proc2.stdout)
        self.assertEqual(
            payload["schema"], "auditooor.hackerman_domain_stats.v1"
        )
        self.assertEqual(payload["total_records"], 2)

    # 13
    def test_out_json_written_to_disk(self) -> None:
        _write_subdir_record(
            self.tags_dir, "lending", "r1",
            target_domain="lending", record_tier="T1",
        )
        out_path = self.tags_dir / "envelope.json"
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL_PATH),
                "--tags-dir",
                str(self.tags_dir),
                "--json",
                "--out-json",
                str(out_path),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(out_path.exists())
        stdout_payload = json.loads(proc.stdout)
        disk_payload = json.loads(out_path.read_text(encoding="utf-8"))
        self.assertEqual(stdout_payload["schema"], disk_payload["schema"])
        self.assertEqual(
            stdout_payload["domain_totals"], disk_payload["domain_totals"]
        )

    # 14
    def test_top_domains_ranking(self) -> None:
        for i in range(5):
            _write_subdir_record(
                self.tags_dir, "s", f"a{i}",
                target_domain="alpha", record_tier="T1",
            )
        for i in range(3):
            _write_subdir_record(
                self.tags_dir, "s", f"b{i}",
                target_domain="beta", record_tier="T1",
            )
        _write_subdir_record(
            self.tags_dir, "s", "g1",
            target_domain="gamma", record_tier="T1",
        )
        stats = tool.build_stats(self.tags_dir)
        top2 = tool.top_domains(stats, 2)
        self.assertEqual(
            top2,
            [
                {"target_domain": "alpha", "count": 5},
                {"target_domain": "beta", "count": 3},
            ],
        )
        top_all = tool.top_domains(stats, 25)
        self.assertEqual(len(top_all), 3)
        self.assertEqual(top_all[2]["target_domain"], "gamma")


if __name__ == "__main__":
    unittest.main()
