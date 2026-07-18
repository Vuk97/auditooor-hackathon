"""Tests for ``tools/hackerman-baseline-freeze.py`` (PR #726 Wave-1).

Covers >=8 cases per PR #726 spec:

1. ``compute_baseline`` walks the three record shapes and returns
   deterministic ``corpus_sha256`` + ``total_records`` + ``tier_distribution``
   + ``shape_counts`` + ``subtree_record_counts``.
2. SHA is deterministic across two independent invocations on the same tree.
3. SHA flips when a record's content changes (a single byte edit).
4. SHA flips when a record's relpath changes (rename of same content).
5. ``freeze_baseline`` writes the freeze JSON to ``--out-path`` with the
   canonical schema + ordered tier_distribution + per-subtree counts.
6. ``verify_baseline`` returns ``match=True`` when the corpus is unchanged
   between freeze + verify.
7. ``verify_baseline`` returns ``match=False`` after a record content edit;
   surfaces expected vs observed SHA.
8. ``verify_baseline`` returns ``match=False`` with ``error`` key when the
   freeze file does not exist.
9. CLI ``--json`` mode emits a parse-friendly verdict with ``verdict`` and
   ``corpus_sha256`` keys.
10. CLI ``--check`` mode exits 0 on match and 1 on mismatch.
11. ``default_out_path`` resolves to ``<out-dir>/<baseline-label>.json``.
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
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-baseline-freeze.py"


def _load_tool() -> Any:
    name = "_hackerman_baseline_freeze_test_mod"
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
    Subtrees: lending_protocols=4, dex_fix_history=1.
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
            "function_shape": {"shape_tags": ["other:something-else"]},
        },
    )
    return tags_dir


class TestComputeBaselineWalksThreeShapes(unittest.TestCase):
    def test_returns_sha_and_stats(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            core = tool.compute_baseline(tags_dir)
            self.assertEqual(core["input_count"], 5)
            self.assertEqual(len(core["corpus_sha256"]), 64)
            # SHA is 64 hex chars.
            int(core["corpus_sha256"], 16)
            stats = core["stats"]
            self.assertEqual(stats["total_records"], 5)
            self.assertEqual(
                stats["tier_distribution"],
                {"tier-1": 2, "tier-2": 1, "tier-3": 1, "no-tier": 1},
            )
            self.assertEqual(
                list(stats["tier_distribution"].keys()),
                ["tier-1", "tier-2", "tier-3", "no-tier"],
            )
            self.assertEqual(stats["shape_counts"].get("record.json"), 3)
            self.assertEqual(stats["shape_counts"].get("flat.yaml"), 2)
            self.assertEqual(stats["subtree_record_counts"]["lending_protocols"], 4)
            self.assertEqual(stats["subtree_record_counts"]["dex_fix_history"], 1)


class TestShaDeterministic(unittest.TestCase):
    def test_sha_stable_across_two_invocations(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            sha_a = tool.compute_baseline(tags_dir)["corpus_sha256"]
            sha_b = tool.compute_baseline(tags_dir)["corpus_sha256"]
            self.assertEqual(sha_a, sha_b)


class TestShaFlipsOnContentChange(unittest.TestCase):
    def test_byte_edit_changes_sha(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            sha_before = tool.compute_baseline(tags_dir)["corpus_sha256"]
            # Mutate a single record's content (append whitespace).
            target = tags_dir / "lending_protocols" / "acme-1" / "record.json"
            target.write_text(target.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            sha_after = tool.compute_baseline(tags_dir)["corpus_sha256"]
            self.assertNotEqual(sha_before, sha_after)


class TestShaFlipsOnPathChange(unittest.TestCase):
    def test_rename_changes_sha(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            sha_before = tool.compute_baseline(tags_dir)["corpus_sha256"]
            # Rename one of the subtree dirs (same content, different relpath).
            src = tags_dir / "lending_protocols" / "acme-1"
            dst = tags_dir / "lending_protocols" / "acme-1-renamed"
            src.rename(dst)
            sha_after = tool.compute_baseline(tags_dir)["corpus_sha256"]
            self.assertNotEqual(sha_before, sha_after)


class TestFreezeBaselineWritesFile(unittest.TestCase):
    def test_writes_freeze_with_schema_and_tier_distribution(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            out_path = Path(td) / "freeze.json"
            payload = tool.freeze_baseline(
                tags_dir,
                out_path,
                baseline_label="test-label",
                generated_at="2026-05-16T00:00:00Z",
            )
            self.assertTrue(out_path.exists())
            disk = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(disk["schema"], tool.SCHEMA)
            self.assertEqual(disk["baseline_label"], "test-label")
            self.assertEqual(disk["generated_at"], "2026-05-16T00:00:00Z")
            self.assertEqual(disk["stats"]["total_records"], 5)
            self.assertEqual(disk["corpus_sha256"], payload["corpus_sha256"])
            # tier_distribution order preserved.
            self.assertEqual(
                list(disk["stats"]["tier_distribution"].keys()),
                ["tier-1", "tier-2", "tier-3", "no-tier"],
            )
            # subtree counts present.
            self.assertIn("lending_protocols", disk["stats"]["subtree_record_counts"])


class TestVerifyBaselineMatch(unittest.TestCase):
    def test_match_when_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            out_path = Path(td) / "freeze.json"
            tool.freeze_baseline(
                tags_dir,
                out_path,
                baseline_label="test",
                generated_at="2026-05-16T00:00:00Z",
            )
            verdict = tool.verify_baseline(tags_dir, out_path)
            self.assertTrue(verdict["match"])
            self.assertEqual(verdict["expected_sha"], verdict["observed_sha"])
            self.assertEqual(verdict["expected_total"], verdict["observed_total"])


class TestVerifyBaselineMismatch(unittest.TestCase):
    def test_mismatch_after_content_edit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            out_path = Path(td) / "freeze.json"
            tool.freeze_baseline(
                tags_dir,
                out_path,
                baseline_label="test",
                generated_at="2026-05-16T00:00:00Z",
            )
            # Mutate corpus.
            target = tags_dir / "dex_fix_history" / "acme-dex-1" / "record.json"
            target.write_text(target.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            verdict = tool.verify_baseline(tags_dir, out_path)
            self.assertFalse(verdict["match"])
            self.assertNotEqual(verdict["expected_sha"], verdict["observed_sha"])
            self.assertNotIn("error", verdict)


class TestVerifyBaselineMissingFile(unittest.TestCase):
    def test_returns_error_when_freeze_absent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            verdict = tool.verify_baseline(tags_dir, Path(td) / "nope.json")
            self.assertFalse(verdict["match"])
            self.assertIn("error", verdict)
            self.assertIn("freeze file not found", verdict["error"])


class TestCliJsonMode(unittest.TestCase):
    def test_json_verdict_has_sha_and_total(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            out_dir = Path(td) / "out"
            res = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--tags-dir",
                    str(tags_dir),
                    "--out-dir",
                    str(out_dir),
                    "--baseline-label",
                    "cli-test",
                    "--generated-at",
                    "2026-05-16T00:00:00Z",
                    "--json",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            data = json.loads(res.stdout)
            self.assertEqual(data["verdict"], "ok")
            self.assertEqual(data["total_records"], 5)
            self.assertEqual(len(data["corpus_sha256"]), 64)
            self.assertEqual(data["baseline_label"], "cli-test")
            # File exists at expected path.
            self.assertTrue((out_dir / "cli-test.json").exists())


class TestCliCheckMode(unittest.TestCase):
    def test_check_exits_zero_on_match_and_one_on_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = _build_synthetic_tree(Path(td))
            out_dir = Path(td) / "out"
            # Freeze.
            res_freeze = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--tags-dir",
                    str(tags_dir),
                    "--out-dir",
                    str(out_dir),
                    "--baseline-label",
                    "check-test",
                    "--generated-at",
                    "2026-05-16T00:00:00Z",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res_freeze.returncode, 0, res_freeze.stderr)
            # Check (match).
            res_match = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--tags-dir",
                    str(tags_dir),
                    "--out-dir",
                    str(out_dir),
                    "--baseline-label",
                    "check-test",
                    "--check",
                    "--json",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res_match.returncode, 0, res_match.stderr)
            self.assertEqual(json.loads(res_match.stdout)["verdict"], "match")
            # Mutate corpus, re-check (mismatch).
            (tags_dir / "lending_protocols" / "acme-1" / "record.json").write_text(
                json.dumps({"schema_version": "auditooor.hackerman_record.v1", "x": 1})
                + "\n",
                encoding="utf-8",
            )
            res_mismatch = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--tags-dir",
                    str(tags_dir),
                    "--out-dir",
                    str(out_dir),
                    "--baseline-label",
                    "check-test",
                    "--check",
                    "--json",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res_mismatch.returncode, 1)
            self.assertEqual(
                json.loads(res_mismatch.stdout)["verdict"], "mismatch"
            )


class TestDefaultOutPath(unittest.TestCase):
    def test_default_out_path_combines_dir_and_label(self) -> None:
        p = tool.default_out_path(Path("/tmp/freeze"), "2026-05-16-wave1-final")
        self.assertEqual(p, Path("/tmp/freeze/2026-05-16-wave1-final.json"))


if __name__ == "__main__":
    unittest.main()
