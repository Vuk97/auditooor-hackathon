"""Tests for ``tools/hackerman-target-repo-stats.py``.

Wave-1 hackerman capability lift (PR #726). The tool walks
``audit/corpus_tags/tags/**/record.{yaml,json}`` plus flat
``audit/corpus_tags/tags/*.yaml`` files and emits per-target_repo
distribution stats (totals, top-50, tier-1/2/3 breakdown, subtree
breakdown).

Cases (>=8):

1.  empty tags-dir -> total_records=0, no repos, render_human survives.
2.  single subdir record -> one repo with count=1, correct subtree
    and verification_tier extracted from function_shape.shape_tags.
3.  multi-record aggregation across multiple repos, ranked by count.
4.  ``<missing-target-repo>`` sentinel when target_repo is missing.
5.  ``<missing-tier>`` sentinel when no verification_tier shape_tag is
    parseable; canonical normalisation of tier-1 / tier-2 / tier-3
    subtypes (e.g. tier-1-ghsa-rest-api collapses to tier-1).
6.  record.yaml wins over record.json in the same dir (precedence).
7.  flat solodit-spec / dsl_pattern / prior-audit / corpus-mined / seed
    / other tags bucket into ``_flat_*`` subtrees by filename prefix.
8.  JSON envelope schema is ``auditooor.hackerman_target_repo_stats.v1``
    and carries ``top_repos`` + per-repo tier-1/2/3 cells.
9.  ``top_repos(top_n=N)`` honours the limit and ranks by (-count, name).
10. tier extracted from ``required_preconditions`` fallback when
    function_shape.shape_tags is empty.
11. CLI default human render exit-code 0 on a populated synthetic corpus.
12. CLI ``--json`` emits valid JSON envelope on stdout.
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
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-target-repo-stats.py"


def _load_tool() -> Any:
    name = "_hackerman_target_repo_stats_test_mod"
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
    target_repo: str | None = "synthetic/test",
    verification_tier_tag: str | None = None,
    extra_shape_tags: list[str] | None = None,
    precondition_tier_tag: str | None = None,
    fmt: str = "yaml",
) -> Path:
    rec_dir = tags_dir / subtree / record_id
    rec_dir.mkdir(parents=True, exist_ok=True)
    if fmt == "yaml":
        lines = [
            "schema_version: auditooor.hackerman_record.v1",
            f"record_id: {record_id}",
        ]
        if target_repo is not None:
            lines.append(f"target_repo: {target_repo}")
        # function_shape with optional verification_tier shape_tag.
        shape_tags = list(extra_shape_tags or [])
        if verification_tier_tag is not None:
            shape_tags.append(verification_tier_tag)
        if shape_tags:
            lines.append("function_shape:")
            lines.append("  raw_signature: synthetic-shape")
            lines.append("  shape_tags:")
            for t in shape_tags:
                lines.append(f"    - {t}")
        if precondition_tier_tag is not None:
            lines.append("required_preconditions:")
            lines.append(f"  - {precondition_tier_tag}")
        path = rec_dir / "record.yaml"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path
    obj: dict[str, Any] = {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": record_id,
    }
    if target_repo is not None:
        obj["target_repo"] = target_repo
    shape_tags = list(extra_shape_tags or [])
    if verification_tier_tag is not None:
        shape_tags.append(verification_tier_tag)
    if shape_tags:
        obj["function_shape"] = {
            "raw_signature": "synthetic-shape",
            "shape_tags": shape_tags,
        }
    if precondition_tier_tag is not None:
        obj["required_preconditions"] = [precondition_tier_tag]
    path = rec_dir / "record.json"
    path.write_text(json.dumps(obj), encoding="utf-8")
    return path


def _write_flat(
    tags_dir: Path,
    filename: str,
    *,
    target_repo: str | None,
    verification_tier_tag: str | None = None,
) -> Path:
    lines = ["schema_version: auditooor.hackerman_record.v1"]
    if target_repo is not None:
        lines.append(f"target_repo: {target_repo}")
    if verification_tier_tag is not None:
        lines.append("function_shape:")
        lines.append("  raw_signature: synthetic-shape")
        lines.append("  shape_tags:")
        lines.append(f"    - {verification_tier_tag}")
    path = tags_dir / filename
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


class HackermanTargetRepoStatsTests(unittest.TestCase):
    def test_01_empty_tags_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 0)
            self.assertEqual(stats["repos"], [])
            self.assertEqual(stats["repo_totals"], {})
            # render_human must not crash on empty corpus
            human = tool.render_human(stats)
            self.assertIn("total_records: 0", human)
            self.assertIn("target_repo distribution", human)

    def test_02_single_subdir_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags,
                "lending_protocols",
                "rec_a",
                target_repo="liquity/dev",
                verification_tier_tag=(
                    "verification_tier:tier-1-verified-realtime-api"
                ),
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 1)
            self.assertEqual(stats["repos"], ["liquity/dev"])
            self.assertEqual(stats["repo_totals"]["liquity/dev"], 1)
            self.assertEqual(
                stats["repo_by_subtree"]["liquity/dev"]["lending_protocols"],
                1,
            )
            self.assertEqual(
                stats["repo_by_tier"]["liquity/dev"]["tier-1"], 1
            )
            self.assertEqual(stats["tier_totals"]["tier-1"], 1)

    def test_03_multi_record_aggregation_and_ranking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            # liquity/dev has 3, aave/v3 has 2, makerdao/dss has 1
            for i in range(3):
                _write_subdir_record(
                    tags, "lending_protocols", f"liq_{i}",
                    target_repo="liquity/dev",
                    verification_tier_tag=(
                        "verification_tier:tier-1-verified-realtime-api"
                    ),
                )
            for i in range(2):
                _write_subdir_record(
                    tags, "lending_protocols", f"aave_{i}",
                    target_repo="aave/v3",
                    verification_tier_tag=(
                        "verification_tier:tier-2-verified-public-archive"
                    ),
                )
            _write_subdir_record(
                tags, "lending_protocols", "dss_0",
                target_repo="makerdao/dss",
                verification_tier_tag=(
                    "verification_tier:tier-3-synthetic-taxonomy-anchored"
                ),
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 6)
            # ranking: liquity/dev (3) > aave/v3 (2) > makerdao/dss (1)
            self.assertEqual(
                stats["repos"],
                ["liquity/dev", "aave/v3", "makerdao/dss"],
            )
            self.assertEqual(stats["repo_totals"]["liquity/dev"], 3)
            self.assertEqual(stats["repo_totals"]["aave/v3"], 2)
            self.assertEqual(stats["repo_totals"]["makerdao/dss"], 1)
            # tier breakdown
            self.assertEqual(stats["tier_totals"]["tier-1"], 3)
            self.assertEqual(stats["tier_totals"]["tier-2"], 2)
            self.assertEqual(stats["tier_totals"]["tier-3"], 1)
            # canonical tier ordering in tier_totals keys
            tier_keys = list(stats["tier_totals"].keys())
            self.assertEqual(tier_keys[:3], ["tier-1", "tier-2", "tier-3"])

    def test_04_missing_target_repo_sentinel(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "no_repo",
                target_repo=None,
                verification_tier_tag=(
                    "verification_tier:tier-1-verified-realtime-api"
                ),
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 1)
            self.assertIn(tool.MISSING_REPO, stats["repo_totals"])
            self.assertEqual(stats["repo_totals"][tool.MISSING_REPO], 1)

    def test_05_tier_normalisation_and_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            # tier-1 subtype suffixes collapse to tier-1
            _write_subdir_record(
                tags, "lending_protocols", "r_t1_ghsa",
                target_repo="liquity/dev",
                verification_tier_tag=(
                    "verification_tier:tier-1-ghsa-rest-api"
                ),
            )
            _write_subdir_record(
                tags, "lending_protocols", "r_t1_live",
                target_repo="liquity/dev",
                verification_tier_tag=(
                    "verification_tier:tier-1-live-fetch"
                ),
            )
            # tier-2 subtype
            _write_subdir_record(
                tags, "lending_protocols", "r_t2",
                target_repo="liquity/dev",
                verification_tier_tag=(
                    "verification_tier:tier-2-verified-public-archive"
                ),
            )
            # tier-3 subtype
            _write_subdir_record(
                tags, "lending_protocols", "r_t3",
                target_repo="liquity/dev",
                verification_tier_tag=(
                    "verification_tier:tier-3-synthetic-taxonomy-anchored"
                ),
            )
            # no verification_tier shape_tag at all -> <missing-tier>
            _write_subdir_record(
                tags, "lending_protocols", "r_no_tier",
                target_repo="liquity/dev",
                verification_tier_tag=None,
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 5)
            self.assertEqual(stats["tier_totals"]["tier-1"], 2)
            self.assertEqual(stats["tier_totals"]["tier-2"], 1)
            self.assertEqual(stats["tier_totals"]["tier-3"], 1)
            self.assertEqual(stats["tier_totals"][tool.MISSING_TIER], 1)
            self.assertEqual(
                stats["repo_by_tier"]["liquity/dev"]["tier-1"], 2
            )

    def test_06_yaml_wins_over_json_in_same_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "rec_both",
                target_repo="liquity/dev",
                verification_tier_tag=(
                    "verification_tier:tier-1-verified-realtime-api"
                ),
                fmt="yaml",
            )
            _write_subdir_record(
                tags, "lending_protocols", "rec_both",
                target_repo="some/other-repo",
                verification_tier_tag=(
                    "verification_tier:tier-3-synthetic-taxonomy-anchored"
                ),
                fmt="json",
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 1)
            self.assertEqual(stats["repo_totals"].get("liquity/dev"), 1)
            self.assertNotIn("some/other-repo", stats["repo_totals"])

    def test_07_flat_prefix_buckets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_flat(
                tags, "solodit-spec:foo-1.yaml",
                target_repo="upstream-a/repo",
                verification_tier_tag=(
                    "verification_tier:tier-1-verified-realtime-api"
                ),
            )
            _write_flat(
                tags, "dsl_pattern_foo.yaml",
                target_repo="upstream-b/repo",
            )
            _write_flat(
                tags, "prior-audit-foo.yaml",
                target_repo="upstream-c/repo",
                verification_tier_tag=(
                    "verification_tier:tier-2-verified-public-archive"
                ),
            )
            _write_flat(
                tags, "corpus-mined-foo.yaml",
                target_repo="upstream-d/repo",
            )
            _write_flat(
                tags, "seed_foo.yaml",
                target_repo="upstream-e/repo",
            )
            _write_flat(
                tags, "miscellaneous_thing.yaml",
                target_repo="upstream-f/repo",
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 6)
            buckets = stats["subtree_totals"]
            self.assertEqual(buckets["_flat_solodit_spec"], 1)
            self.assertEqual(buckets["_flat_dsl_pattern"], 1)
            self.assertEqual(buckets["_flat_prior_audit"], 1)
            self.assertEqual(buckets["_flat_corpus_mined"], 1)
            self.assertEqual(buckets["_flat_seed"], 1)
            self.assertEqual(buckets["_flat_other"], 1)
            # spot check a subtree-cell
            self.assertEqual(
                stats["repo_by_subtree"]["upstream-a/repo"][
                    "_flat_solodit_spec"
                ],
                1,
            )

    def test_08_json_envelope_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "r1",
                target_repo="liquity/dev",
                verification_tier_tag=(
                    "verification_tier:tier-1-verified-realtime-api"
                ),
            )
            stats = tool.build_stats(tags)
            payload = json.loads(tool.render_json(stats))
            self.assertEqual(
                payload["schema"],
                "auditooor.hackerman_target_repo_stats.v1",
            )
            self.assertEqual(payload["total_records"], 1)
            self.assertIn("repo_totals", payload)
            self.assertIn("repo_by_tier", payload)
            self.assertIn("repo_by_subtree", payload)
            self.assertIn("top_repos", payload)
            # top_repos rows carry tier_1 / tier_2 / tier_3 cells
            tr0 = payload["top_repos"][0]
            self.assertEqual(tr0["target_repo"], "liquity/dev")
            self.assertEqual(tr0["count"], 1)
            self.assertEqual(tr0["tier_1"], 1)
            self.assertEqual(tr0["tier_2"], 0)
            self.assertEqual(tr0["tier_3"], 0)

    def test_09_top_repos_top_n_and_ranking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            # Insert 5 repos with descending counts; top_n=3 should drop
            # the last two.
            for repo, n in [
                ("repo-a/x", 5),
                ("repo-b/x", 4),
                ("repo-c/x", 3),
                ("repo-d/x", 2),
                ("repo-e/x", 1),
            ]:
                for i in range(n):
                    _write_subdir_record(
                        tags, "lending_protocols", f"{repo}_{i}".replace(
                            "/", "_"
                        ),
                        target_repo=repo,
                        verification_tier_tag=(
                            "verification_tier:tier-1-verified-realtime-api"
                        ),
                    )
            stats = tool.build_stats(tags)
            top3 = tool.top_repos(stats, 3)
            self.assertEqual(len(top3), 3)
            self.assertEqual(
                [r["target_repo"] for r in top3],
                ["repo-a/x", "repo-b/x", "repo-c/x"],
            )
            self.assertEqual(top3[0]["count"], 5)
            self.assertEqual(top3[2]["count"], 3)
            # Ensure top-N=50 default surfaces all 5 entries when corpus
            # smaller than the default limit.
            top50 = tool.top_repos(stats, 50)
            self.assertEqual(len(top50), 5)

    def test_10_tier_from_required_preconditions_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            # function_shape has no verification_tier; precondition has.
            _write_subdir_record(
                tags, "lending_protocols", "r_precond_tier",
                target_repo="liquity/dev",
                verification_tier_tag=None,
                precondition_tier_tag="verification_tier=tier-2-verified-public-archive",
            )
            stats = tool.build_stats(tags)
            self.assertEqual(stats["total_records"], 1)
            self.assertEqual(stats["tier_totals"]["tier-2"], 1)
            self.assertEqual(
                stats["repo_by_tier"]["liquity/dev"]["tier-2"], 1
            )

    def test_11_cli_human_exit_code_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "r1",
                target_repo="liquity/dev",
                verification_tier_tag=(
                    "verification_tier:tier-1-verified-realtime-api"
                ),
            )
            result = subprocess.run(
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
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertIn(
                "Hackerman target_repo distribution", result.stdout
            )
            self.assertIn("liquity/dev", result.stdout)

    def test_12_cli_json_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "r1",
                target_repo="liquity/dev",
                verification_tier_tag=(
                    "verification_tier:tier-1-verified-realtime-api"
                ),
            )
            result = subprocess.run(
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
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(
                payload["schema"],
                "auditooor.hackerman_target_repo_stats.v1",
            )
            self.assertEqual(payload["total_records"], 1)
            self.assertEqual(
                payload["top_repos"][0]["target_repo"], "liquity/dev"
            )
            self.assertEqual(payload["top_repos"][0]["tier_1"], 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
