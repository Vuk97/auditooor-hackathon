"""Tests for ``tools/hackerman-tier-history-snapshot.py`` (PR #726 Wave-1).

Covers >=8 cases per PR #726 spec:

1. ``build_tier_distribution`` walks the three record shapes and returns
   deterministic tier counts in canonical TIER_ORDER.
2. ``snapshot_filename_for`` converts an ISO timestamp to a filesystem-safe
   slug (``:`` -> ``-``).
3. ``_resolve_generated_at`` accepts both ISO and slug input and normalises
   to ISO.
4. ``take_snapshot`` writes a versioned snapshot file under the configured
   out-dir and returns ``skipped=False``.
5. ``take_snapshot`` is idempotent: a second call with the same
   ``--generated-at`` returns ``skipped=True`` and does NOT overwrite the
   file (mtime / contents unchanged).
6. Manifest grows with each distinct snapshot; entries are sorted by
   ``generated_at`` asc; duplicate filenames dedup.
7. Manifest entries contain the four required fields (filename,
   generated_at, total_records, tier_counts) for growth-tracking.
8. ``list_snapshots`` returns newest-first and respects ``limit``.
9. CLI ``--json`` mode emits a parse-friendly verdict with ``verdict`` and
   ``tier_counts`` keys.
10. CLI ``--list`` mode prints the manifest in human-readable form and
    exits 0 even when no snapshots exist.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-tier-history-snapshot.py"


def _load_tool() -> Any:
    name = "_hackerman_tier_history_snapshot_test_mod"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


SAMPLE_RECORD_BASE = {
    "schema_version": "auditooor.hackerman_record.v1",
    "attack_class": "ghsa-class-a",
    "target_repo": "acme/lending",
    "target_domain": "lending",
    "function_shape": {
        "shape_tags": ["verification_tier:tier-1-ghsa-rest-api"],
    },
}


def _write_record_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_flat_yaml(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for k, v in payload.items():
        if k == "function_shape":
            lines.append("function_shape:")
            lines.append("  shape_tags:")
            for tag in v.get("shape_tags", []):
                lines.append(f"    - {tag}")
        else:
            lines.append(f"{k}: {v}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _build_synthetic_tree(root: Path) -> Path:
    """Build a small synthetic corpus tree:
    - 2 record.json under lending_protocols/ (tier-1, tier-1)
    - 1 record.json under dex_fix_history/ (tier-2)
    - 1 flat .yaml under lending_protocols/ (tier-3)
    - 1 flat .yaml under lending_protocols/ with NO tier tag (no-tier)
    Total = 5 records; tiers: tier-1=2, tier-2=1, tier-3=1, no-tier=1.
    """
    tags_dir = root / "audit" / "corpus_tags" / "tags"
    tags_dir.mkdir(parents=True, exist_ok=True)
    rec1 = dict(SAMPLE_RECORD_BASE)
    rec1["function_shape"] = {"shape_tags": ["verification_tier:tier-1-ghsa-rest-api"]}
    _write_record_json(tags_dir / "lending_protocols" / "acme-1" / "record.json", rec1)
    rec2 = dict(SAMPLE_RECORD_BASE)
    rec2["function_shape"] = {"shape_tags": ["verification_tier:tier-1-ghsa-rest-api"]}
    _write_record_json(tags_dir / "lending_protocols" / "acme-2" / "record.json", rec2)
    rec3 = dict(SAMPLE_RECORD_BASE)
    rec3["function_shape"] = {"shape_tags": ["verification_tier:tier-2-osv"]}
    _write_record_json(tags_dir / "dex_fix_history" / "acme-dex-1" / "record.json", rec3)
    _write_flat_yaml(
        tags_dir / "lending_protocols" / "flat_one.yaml",
        {
            "schema_version": "auditooor.hackerman_record.v1",
            "attack_class": "ghsa-class-c",
            "target_repo": "acme/flat",
            "target_domain": "lending",
            "function_shape": {"shape_tags": ["verification_tier:tier-3-cve"]},
        },
    )
    _write_flat_yaml(
        tags_dir / "lending_protocols" / "flat_two.yaml",
        {
            "schema_version": "auditooor.hackerman_record.v1",
            "attack_class": "ghsa-class-d",
            "target_repo": "acme/flat2",
            "target_domain": "lending",
            # No verification_tier shape_tag -> bucketed under no-tier.
            "function_shape": {"shape_tags": ["other:something-else"]},
        },
    )
    return tags_dir


class TestBuildTierDistribution(unittest.TestCase):
    def test_walks_three_shapes_and_counts_tiers_canonically(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            stats = tool.build_tier_distribution(tags_dir)
            self.assertEqual(stats["total_records"], 5)
            self.assertEqual(stats["total_hackerman_v1_records"], 5)
            self.assertEqual(
                stats["tier_counts"],
                {"tier-1": 2, "tier-2": 1, "tier-3": 1, "no-tier": 1},
            )
            # Canonical TIER_ORDER preserved in insertion order.
            self.assertEqual(
                list(stats["tier_counts"].keys()),
                ["tier-1", "tier-2", "tier-3", "no-tier"],
            )
            self.assertEqual(stats["shape_counts"].get("record.json"), 3)
            self.assertEqual(stats["shape_counts"].get("flat.yaml"), 2)


class TestSnapshotFilenameFor(unittest.TestCase):
    def test_iso_to_slug_converts_colons_to_hyphens(self) -> None:
        self.assertEqual(
            tool.snapshot_filename_for("2026-05-16T22:00:00Z"),
            "2026-05-16T22-00-00Z.json",
        )

    def test_iso_to_slug_preserves_zero_padding(self) -> None:
        self.assertEqual(
            tool.snapshot_filename_for("2026-01-02T03:04:05Z"),
            "2026-01-02T03-04-05Z.json",
        )


class TestResolveGeneratedAt(unittest.TestCase):
    def test_accepts_iso_form(self) -> None:
        self.assertEqual(
            tool._resolve_generated_at("2026-05-16T22:00:00Z"),
            "2026-05-16T22:00:00Z",
        )

    def test_accepts_slug_form_and_normalises(self) -> None:
        self.assertEqual(
            tool._resolve_generated_at("2026-05-16T22-00-00Z"),
            "2026-05-16T22:00:00Z",
        )

    def test_rejects_garbage(self) -> None:
        with self.assertRaises(ValueError):
            tool._resolve_generated_at("not-a-timestamp")


class TestTakeSnapshotWritesFile(unittest.TestCase):
    def test_writes_versioned_snapshot_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            out_dir = Path(td) / "snapshots"
            verdict = tool.take_snapshot(
                tags_dir, out_dir, generated_at="2026-05-16T22:00:00Z"
            )
            self.assertFalse(verdict["skipped"])
            self.assertEqual(verdict["filename"], "2026-05-16T22-00-00Z.json")
            snap_path = Path(verdict["path"])
            self.assertTrue(snap_path.exists())
            payload = json.loads(snap_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], tool.SCHEMA)
            self.assertEqual(payload["generated_at"], "2026-05-16T22:00:00Z")
            self.assertEqual(payload["stats"]["total_records"], 5)
            self.assertEqual(payload["stats"]["tier_counts"]["tier-1"], 2)
            self.assertEqual(verdict["snapshot_count_after"], 1)


class TestTakeSnapshotIdempotency(unittest.TestCase):
    def test_same_second_invocation_skips_and_does_not_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            out_dir = Path(td) / "snapshots"
            v1 = tool.take_snapshot(
                tags_dir, out_dir, generated_at="2026-05-16T22:00:00Z"
            )
            self.assertFalse(v1["skipped"])
            snap_path = Path(v1["path"])
            mtime1 = snap_path.stat().st_mtime_ns
            contents1 = snap_path.read_bytes()

            # Mutate the corpus before second call to prove the file does NOT
            # get overwritten (idempotency means "same second = no-op").
            _write_record_json(
                tags_dir / "lending_protocols" / "acme-3" / "record.json",
                {
                    **SAMPLE_RECORD_BASE,
                    "function_shape": {
                        "shape_tags": ["verification_tier:tier-1-ghsa-rest-api"]
                    },
                },
            )
            # Sleep just enough so st_mtime would change if rewritten (best-
            # effort - the bytes-equal assertion below is the real proof).
            time.sleep(0.01)
            v2 = tool.take_snapshot(
                tags_dir, out_dir, generated_at="2026-05-16T22:00:00Z"
            )
            self.assertTrue(v2["skipped"])
            self.assertEqual(snap_path.read_bytes(), contents1)
            # mtime should be unchanged when skipped (Python's read_text does
            # not modify it; we never opened for write).
            self.assertEqual(snap_path.stat().st_mtime_ns, mtime1)
            # snapshot_count_after stays at 1 (manifest dedup by filename).
            self.assertEqual(v2["snapshot_count_after"], 1)


class TestManifestGrowthAndOrdering(unittest.TestCase):
    def test_manifest_grows_and_sorts_by_generated_at(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            out_dir = Path(td) / "snapshots"
            tool.take_snapshot(tags_dir, out_dir, generated_at="2026-05-16T22:00:00Z")
            tool.take_snapshot(tags_dir, out_dir, generated_at="2026-05-17T22:00:00Z")
            v3 = tool.take_snapshot(
                tags_dir, out_dir, generated_at="2026-05-15T22:00:00Z"
            )
            self.assertEqual(v3["snapshot_count_after"], 3)
            manifest_path = out_dir / tool.MANIFEST_NAME
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema"], tool.MANIFEST_SCHEMA)
            generated_ats = [s["generated_at"] for s in manifest["snapshots"]]
            self.assertEqual(
                generated_ats,
                ["2026-05-15T22:00:00Z", "2026-05-16T22:00:00Z", "2026-05-17T22:00:00Z"],
            )

    def test_manifest_entry_has_required_growth_fields(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            out_dir = Path(td) / "snapshots"
            tool.take_snapshot(tags_dir, out_dir, generated_at="2026-05-16T22:00:00Z")
            manifest = json.loads((out_dir / tool.MANIFEST_NAME).read_text(encoding="utf-8"))
            entry = manifest["snapshots"][0]
            for required in ("filename", "generated_at", "total_records", "tier_counts"):
                self.assertIn(required, entry, f"manifest entry missing {required}")
            self.assertEqual(entry["total_records"], 5)
            self.assertEqual(entry["tier_counts"]["tier-1"], 2)


class TestListSnapshots(unittest.TestCase):
    def test_returns_newest_first_and_respects_limit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            out_dir = Path(td) / "snapshots"
            for ts in (
                "2026-05-10T22:00:00Z",
                "2026-05-11T22:00:00Z",
                "2026-05-12T22:00:00Z",
                "2026-05-13T22:00:00Z",
            ):
                tool.take_snapshot(tags_dir, out_dir, generated_at=ts)
            top2 = tool.list_snapshots(out_dir, limit=2)
            self.assertEqual(len(top2), 2)
            self.assertEqual(top2[0]["generated_at"], "2026-05-13T22:00:00Z")
            self.assertEqual(top2[1]["generated_at"], "2026-05-12T22:00:00Z")


class TestCliJsonMode(unittest.TestCase):
    def test_cli_json_mode_emits_verdict_and_tier_counts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            out_dir = Path(td) / "snapshots"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--tags-dir",
                    str(tags_dir),
                    "--out-dir",
                    str(out_dir),
                    "--generated-at",
                    "2026-05-16T22:00:00Z",
                    "--json",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            data = json.loads(proc.stdout)
            self.assertEqual(data["verdict"], "ok")
            self.assertEqual(data["total_records"], 5)
            self.assertEqual(data["tier_counts"]["tier-1"], 2)
            self.assertEqual(data["snapshot_count_after"], 1)


class TestCliListMode(unittest.TestCase):
    def test_cli_list_mode_handles_empty_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td) / "snapshots"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--out-dir",
                    str(out_dir),
                    "--list",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            self.assertIn("no snapshots yet", proc.stdout)

    def test_cli_list_mode_shows_recent_entries(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            out_dir = Path(td) / "snapshots"
            tool.take_snapshot(tags_dir, out_dir, generated_at="2026-05-16T22:00:00Z")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--out-dir",
                    str(out_dir),
                    "--list",
                    "--limit",
                    "5",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            self.assertIn("2026-05-16T22:00:00Z", proc.stdout)
            self.assertIn("tier-1=2", proc.stdout)


if __name__ == "__main__":
    unittest.main()
