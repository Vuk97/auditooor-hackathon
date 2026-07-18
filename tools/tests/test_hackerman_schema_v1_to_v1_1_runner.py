"""Tests for tools/hackerman-schema-v1-to-v1.1-runner.py (Wave-2 W2.1).

Covers >=10 cases:

  1. Dry-run mode (default) does NOT mutate any file on disk.
  2. Apply mode (subtree-scoped) DOES mutate the v1 records in-place.
  3. Migrated JSON file passes the v1.1 schema validator post-mutation.
  4. Migrated YAML file passes the v1.1 schema validator post-mutation.
  5. Atomic-write leaves no orphan ``.tmp`` files in the parent directory.
  6. Idempotency: re-running over an already-migrated subtree reports
     ``already_v11`` for every previously-migrated record and zero new
     migrations.
  7. ``--apply`` without ``--subtree`` is refused (exit 2); ``--ready-for-full``
     with ``--subtree`` is refused.
  8. Unparseable JSON file is reported as ``unparseable`` and the runner
     exits with code 1.
  9. Non-v1 records (e.g. legacy verdict-tag YAML, v1.1 records) are
     classified correctly and never written.
 10. ``render_report`` is deterministic for a fixed ``generated_at`` and
     contains the headline counts + per-subtree breakdown table.
 11. ``--limit`` stops after N candidate files.
 12. ``--no-validate-after`` disables post-mutation validation and the
     summary reports ``validate_after=False``.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict

_HERE = Path(__file__).resolve()
_REPO = _HERE.parents[2]
_RUNNER_PATH = _REPO / "tools" / "hackerman-schema-v1-to-v1.1-runner.py"
_MIGRATOR_PATH = _REPO / "tools" / "hackerman-schema-v1-to-v1.1-migrator.py"


def _load_runner() -> Any:
    name = "_hackerman_schema_v1_to_v1_1_runner_test_mod"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, str(_RUNNER_PATH))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


R = _load_runner()


def _base_v1_record() -> Dict[str, Any]:
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": "audit:example:test-001",
        "source_audit_ref": "cantina:example-2025:1.2.3",
        "target_domain": "lending",
        "target_language": "solidity",
        "target_repo": "example/example",
        "target_component": "src/Pool.sol::deposit",
        "function_shape": {
            "raw_signature": "function deposit(uint256 amount)",
            "shape_tags": [
                "state-mutating",
                "verification_tier:tier-2-verified-public-archive",
            ],
        },
        "bug_class": "missing-access-control",
        "attack_class": "unauth-state-write",
        "attacker_role": "unprivileged",
        "attacker_action_sequence": "Call deposit. See CVE-2024-12345 and GHSA-aaaa-bbbb-cccc.",
        "required_preconditions": [
            "Pool deployed and not paused.",
            "Reference advisory at https://example.com/advisory",
        ],
        "impact_class": "theft",
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": ">=$1M",
        "fix_pattern": "Add onlyOwner modifier.",
        "fix_anti_pattern_avoided": "Public state writer.",
        "severity_at_finding": "high",
        "year": 2025,
        "cross_language_analogues": [],
        "related_records": [],
    }


@contextlib.contextmanager
def _temp_tags_dir():
    """Yield a (tags_dir, subtree_dir) pair populated with one JSON + one
    YAML v1 record under a pilot subtree."""
    with tempfile.TemporaryDirectory() as td:
        tags = Path(td) / "tags"
        sub = tags / "pilot_subtree"
        sub.mkdir(parents=True)
        rec = _base_v1_record()
        json_path = sub / "rec01.json"
        json_path.write_text(
            json.dumps(rec, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        try:
            import yaml  # type: ignore

            yaml_path = sub / "rec02.yaml"
            yaml_path.write_text(
                yaml.safe_dump(rec, sort_keys=False, default_flow_style=False),
                encoding="utf-8",
            )
        except ImportError:
            yaml_path = None  # type: ignore[assignment]
        yield tags, sub, json_path, yaml_path


class TestDryRunNoMutation(unittest.TestCase):
    def test_default_is_dry_run_no_writes(self) -> None:
        with _temp_tags_dir() as (tags, sub, json_path, yaml_path):
            before = json_path.read_bytes()
            summary = R.run(tags, subtree="pilot_subtree", apply=False)
            after = json_path.read_bytes()
            self.assertEqual(before, after)
            self.assertEqual(summary["apply"], False)
            self.assertGreaterEqual(summary["totals"].get("migrated", 0), 1)


class TestApplyMutates(unittest.TestCase):
    def test_apply_writes_v11(self) -> None:
        with _temp_tags_dir() as (tags, sub, json_path, yaml_path):
            summary = R.run(
                tags, subtree="pilot_subtree", apply=True, validate_after=True
            )
            self.assertEqual(summary["totals"].get("write_failed", 0), 0)
            self.assertEqual(
                summary["totals"].get("validation_failed_after", 0), 0
            )
            self.assertGreaterEqual(
                summary["totals"].get("migrated", 0), 1
            )
            with json_path.open("r", encoding="utf-8") as fh:
                doc = json.load(fh)
            self.assertEqual(
                doc["schema_version"], "auditooor.hackerman_record.v1.1"
            )
            self.assertEqual(
                doc["verification_tier"], "tier-2-verified-public-archive"
            )
            self.assertEqual(doc["cve_id"], "CVE-2024-12345")
            self.assertEqual(doc["ghsa_id"], "GHSA-aaaa-bbbb-cccc")
            self.assertEqual(doc["record_source_url"], "https://example.com/advisory")


class TestYamlRoundTrip(unittest.TestCase):
    def test_yaml_migrates_and_validates(self) -> None:
        try:
            import yaml  # type: ignore # noqa: F401
        except ImportError:
            self.skipTest("PyYAML not available")
        with _temp_tags_dir() as (tags, sub, json_path, yaml_path):
            if yaml_path is None:
                self.skipTest("yaml fixture not created")
            summary = R.run(
                tags,
                subtree="pilot_subtree",
                apply=True,
                validate_after=True,
            )
            self.assertEqual(
                summary["totals"].get("validation_failed_after", 0), 0
            )
            import yaml  # type: ignore

            with yaml_path.open("r", encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
            self.assertEqual(
                doc["schema_version"], "auditooor.hackerman_record.v1.1"
            )
            self.assertEqual(
                doc["verification_tier"], "tier-2-verified-public-archive"
            )


class TestAtomicWriteNoOrphans(unittest.TestCase):
    def test_no_tmp_files_after_apply(self) -> None:
        with _temp_tags_dir() as (tags, sub, json_path, yaml_path):
            R.run(tags, subtree="pilot_subtree", apply=True)
            orphans = [p.name for p in sub.iterdir() if p.suffix == ".tmp"]
            self.assertEqual(orphans, [])


class TestIdempotent(unittest.TestCase):
    def test_second_run_reports_already_v11(self) -> None:
        with _temp_tags_dir() as (tags, sub, json_path, yaml_path):
            R.run(tags, subtree="pilot_subtree", apply=True)
            summary2 = R.run(tags, subtree="pilot_subtree", apply=True)
            # After the first apply, no record remains v1; runner sees v1.1.
            self.assertEqual(summary2["totals"].get("migrated", 0), 0)
            self.assertGreaterEqual(
                summary2["totals"].get("already_v11", 0), 1
            )


class TestCliApplyRequiresSubtree(unittest.TestCase):
    def test_apply_without_subtree_refused(self) -> None:
        with _temp_tags_dir() as (tags, sub, json_path, yaml_path):
            res = subprocess.run(
                [
                    sys.executable,
                    str(_RUNNER_PATH),
                    "--tags-dir",
                    str(tags),
                    "--apply",
                    "--quiet",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 2)
            self.assertIn("--apply requires --subtree", res.stderr)

    def test_ready_for_full_with_subtree_refused(self) -> None:
        with _temp_tags_dir() as (tags, sub, json_path, yaml_path):
            res = subprocess.run(
                [
                    sys.executable,
                    str(_RUNNER_PATH),
                    "--tags-dir",
                    str(tags),
                    "--subtree",
                    "pilot_subtree",
                    "--ready-for-full",
                    "--quiet",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 2)
            self.assertIn("--ready-for-full", res.stderr)


class TestUnparseable(unittest.TestCase):
    def test_unparseable_json_reported(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags = Path(td) / "tags"
            sub = tags / "bad"
            sub.mkdir(parents=True)
            (sub / "broken.json").write_text("not json {{{", encoding="utf-8")
            summary = R.run(tags, subtree="bad", apply=False)
            self.assertEqual(
                summary["totals"].get("unparseable", 0), 1
            )


class TestNonV1Classification(unittest.TestCase):
    def test_already_v11_and_not_v1(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags = Path(td) / "tags"
            sub = tags / "mixed"
            sub.mkdir(parents=True)
            v11 = _base_v1_record()
            v11["schema_version"] = "auditooor.hackerman_record.v1.1"
            (sub / "rec_v11.json").write_text(
                json.dumps(v11, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            (sub / "rec_other.json").write_text(
                json.dumps({"schema_version": "something.else.v9"}) + "\n",
                encoding="utf-8",
            )
            before_v11 = (sub / "rec_v11.json").read_bytes()
            before_other = (sub / "rec_other.json").read_bytes()
            summary = R.run(tags, subtree="mixed", apply=True)
            self.assertEqual(summary["totals"].get("already_v11", 0), 1)
            self.assertEqual(summary["totals"].get("not_v1", 0), 1)
            self.assertEqual(summary["totals"].get("migrated", 0), 0)
            # No writes for already_v11 / not_v1.
            self.assertEqual(
                (sub / "rec_v11.json").read_bytes(), before_v11
            )
            self.assertEqual(
                (sub / "rec_other.json").read_bytes(), before_other
            )


class TestRenderReportDeterministic(unittest.TestCase):
    def test_render_report_stable(self) -> None:
        summary = {
            "tags_dir": "audit/corpus_tags/tags",
            "subtree": "pilot",
            "scope": "pilot",
            "apply": True,
            "validate_after": True,
            "scan_root": "audit/corpus_tags/tags/pilot",
            "totals": {k: 0 for k in R._OUTCOMES},
            "totals_overall": 3,
            "per_subtree": {"pilot": {k: 0 for k in R._OUTCOMES}},
            "errors": [],
        }
        summary["totals"]["migrated"] = 3
        summary["per_subtree"]["pilot"]["migrated"] = 3
        rep1 = R.render_report(
            summary, generated_at="2026-05-16T00:00:00Z"
        )
        rep2 = R.render_report(
            summary, generated_at="2026-05-16T00:00:00Z"
        )
        self.assertEqual(rep1, rep2)
        self.assertIn(
            "Hackerman schema v1 -> v1.1 migration: runner report", rep1
        )
        self.assertIn("| `migrated` | 3 |", rep1)
        self.assertIn("Per-subtree breakdown", rep1)


class TestLimit(unittest.TestCase):
    def test_limit_stops_processing(self) -> None:
        with _temp_tags_dir() as (tags, sub, json_path, yaml_path):
            summary = R.run(tags, subtree="pilot_subtree", apply=False, limit=1)
            self.assertEqual(summary["totals_overall"], 1)


class TestNoValidateAfter(unittest.TestCase):
    def test_validate_after_disabled(self) -> None:
        with _temp_tags_dir() as (tags, sub, json_path, yaml_path):
            summary = R.run(
                tags,
                subtree="pilot_subtree",
                apply=True,
                validate_after=False,
            )
            self.assertEqual(summary["validate_after"], False)
            self.assertEqual(
                summary["totals"].get("validation_failed_after", 0), 0
            )


class TestCliDryRunDefault(unittest.TestCase):
    def test_cli_default_is_dry_run(self) -> None:
        with _temp_tags_dir() as (tags, sub, json_path, yaml_path):
            before = json_path.read_bytes()
            res = subprocess.run(
                [
                    sys.executable,
                    str(_RUNNER_PATH),
                    "--tags-dir",
                    str(tags),
                    "--subtree",
                    "pilot_subtree",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            self.assertEqual(json_path.read_bytes(), before)
            payload = json.loads(res.stdout)
            self.assertEqual(payload["apply"], False)


class TestCliExitCodeHarmonization(unittest.TestCase):
    """Wave-2 PR-A capability-gap #2: runner exit codes must agree with
    ``tools/wave2-w21-post-migration-validator.py``.

    Convention:

      * exit 0 - PASS (clean run, including dry-runs with nothing to do)
      * exit 1 - FAIL (records found, post-migration validation failed)
      * exit 2 - ERROR (missing scan_root, unparseable input, CLI conflict,
        write failure)

    Before this fix the runner returned exit 0 on missing scan_root which
    silently masked a tool-misinvocation; orchestration scripts that
    branched on exit code could not distinguish "clean" from
    "operator-pointed-at-the-wrong-dir".
    """

    def test_missing_scan_root_exits_2(self) -> None:
        # Synthetic fixture: a nonexistent tags-dir path. Marker for
        # real-source-only discipline lives in the path basename.
        with tempfile.TemporaryDirectory() as td:
            bogus = Path(td) / "synthetic_fixture_nonexistent_tags_dir"
            self.assertFalse(bogus.exists())
            res = subprocess.run(
                [
                    sys.executable,
                    str(_RUNNER_PATH),
                    "--tags-dir",
                    str(bogus),
                    "--dry-run",
                    "--quiet",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                res.returncode,
                2,
                msg=(
                    "missing scan_root must return exit 2 (tool error); "
                    f"got rc={res.returncode}\nstdout={res.stdout}\n"
                    f"stderr={res.stderr}"
                ),
            )

    def test_missing_subtree_under_valid_tags_dir_exits_2(self) -> None:
        # Synthetic fixture: tags-dir exists but the requested subtree does
        # not — resolved scan_root (tags_dir/subtree) is missing.
        with _temp_tags_dir() as (tags, sub, json_path, yaml_path):
            res = subprocess.run(
                [
                    sys.executable,
                    str(_RUNNER_PATH),
                    "--tags-dir",
                    str(tags),
                    "--subtree",
                    "synthetic_fixture_no_such_subtree",
                    "--dry-run",
                    "--quiet",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 2)

    def test_clean_dry_run_exits_0(self) -> None:
        # Synthetic fixture: well-formed v1 record under a real subtree.
        with _temp_tags_dir() as (tags, sub, json_path, yaml_path):
            res = subprocess.run(
                [
                    sys.executable,
                    str(_RUNNER_PATH),
                    "--tags-dir",
                    str(tags),
                    "--subtree",
                    "pilot_subtree",
                    "--dry-run",
                    "--quiet",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0)

    def test_unparseable_record_exits_2(self) -> None:
        # Synthetic fixture: deliberately malformed JSON. Treated as
        # tool/input error (exit 2) under the harmonized convention --
        # malformed-on-disk is a structural problem, not a verdict on
        # content correctness.
        with tempfile.TemporaryDirectory() as td:
            tags = Path(td) / "tags"
            sub = tags / "synthetic_fixture_bad"
            sub.mkdir(parents=True)
            (sub / "broken.json").write_text("not json {{{", encoding="utf-8")
            res = subprocess.run(
                [
                    sys.executable,
                    str(_RUNNER_PATH),
                    "--tags-dir",
                    str(tags),
                    "--subtree",
                    "synthetic_fixture_bad",
                    "--dry-run",
                    "--quiet",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                res.returncode,
                2,
                msg=(
                    "unparseable input must surface as exit 2 (tool/input "
                    f"error). got rc={res.returncode}\nstderr={res.stderr}"
                ),
            )


if __name__ == "__main__":
    unittest.main()
