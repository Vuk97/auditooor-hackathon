"""Tests for tools/solodit-delta-runner.py (I2 Solodit delta runner).

All tests are offline-safe: no network calls, no SOLODIT_API_KEY required.
Synthetic fixture records are used throughout.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


SDR = _load_module("_solodit_delta_runner", REPO_ROOT / "tools" / "solodit-delta-runner.py")
SRD = _load_module("_srd", REPO_ROOT / "tools" / "solodit-rest-direct.py")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mk_cursor(last_id: int, updated_at: str = "2026-05-20T23:41:35.317461+00:00") -> dict:
    return {
        "last_id": last_id,
        "updated_at": updated_at,
        "run_date": updated_at[:10],
        "tool": "solodit-rest-direct",
        "tool_version": "wave3-1.0.0",
    }


def _mk_fixture_finding(fid: int, severity: str = "HIGH") -> dict:
    return {
        "id": fid,
        "severity": severity,
        "title": f"Reentrancy in vault.withdraw ({fid})",
        "description": "Attacker re-enters withdraw and drains balances.",
        "url": f"https://solodit.cyfrin.io/issues/sample-{fid}",
        "language": "Solidity",
        "function": "withdraw(uint256 amount)",
        "category": "reentrancy",
        "year": 2025,
    }


def _write_fixture(path: Path, findings: list, total_pages: int = 1) -> None:
    payload = [{"findings": findings, "metadata": {"totalPages": total_pages, "pageSize": len(findings)}}]
    path.write_text(json.dumps(payload), encoding="utf-8")


# ---------------------------------------------------------------------------
# Case 1: Offline staleness-only report (no network, no key)
# ---------------------------------------------------------------------------

class TestStalenessOnly(unittest.TestCase):
    def test_staleness_report_stale(self):
        """Cursor age > TTL -> staleness report shows is_stale=True, awaiting_network_run=True."""
        # last updated 2026-05-20; today is much later
        state = _mk_cursor(65823, "2026-05-20T23:41:35.317461+00:00")
        report = SDR.staleness_report(state)
        self.assertEqual(report["last_cursor_id"], 65823)
        self.assertTrue(report["is_stale"])
        self.assertTrue(report["awaiting_network_run"])
        self.assertIn("solodit-rest-direct.py", report["next_action"])

    def test_staleness_report_missing_cursor(self):
        """Missing updated_at -> is_stale=True, age_days=None."""
        state = {"last_id": 0}
        report = SDR.staleness_report(state)
        self.assertTrue(report["is_stale"])
        self.assertIsNone(report["age_days"])

    def test_load_cursor_missing_file(self):
        """Missing cursor file -> returns defaults with last_id=0."""
        state = SDR._load_cursor(Path("/nonexistent/cursor.json"))
        self.assertEqual(state["last_id"], 0)
        self.assertIsNone(state["updated_at"])

    def test_staleness_only_cli_emits_json(self):
        """--staleness-only --json-only prints a JSON report to stdout."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cursor_file = Path(tmpdir) / "cursor.json"
            cursor_file.write_text(json.dumps(_mk_cursor(65823)), encoding="utf-8")
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc = SDR.main([
                    "--cursor-file", str(cursor_file),
                    "--staleness-only",
                    "--json-only",
                ])
            self.assertEqual(rc, 0)
            out = json.loads(buf.getvalue())
            self.assertEqual(out["schema"], SDR.REPORT_SCHEMA)
            self.assertIn("staleness", out)
            self.assertEqual(out["mode"], "staleness_only")
            self.assertEqual(out["delta"], None)


# ---------------------------------------------------------------------------
# Case 2: Dry-run with injected fixture
# ---------------------------------------------------------------------------

class TestDryRunDelta(unittest.TestCase):
    def test_dry_run_new_records(self):
        """Dry-run with 3 findings past cursor -> cursor moves, upstream written=3.

        Note: SRD's ingest_from_injected_fixture marks records with
        synthetic_fixture=True, so they are classified as rejected by the
        quality gate (by design - synthetic fixtures must not reach corpus).
        The cursor movement and upstream_result.written=3 confirm the delta
        was correctly computed; the quality gate correctly rejects synthetics.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            fixture = Path(tmpdir) / "fixture.json"
            _write_fixture(fixture, [_mk_fixture_finding(fid) for fid in [70001, 70002, 70003]])
            cursor_file = Path(tmpdir) / "cursor.json"
            cursor_file.write_text(json.dumps(_mk_cursor(65823)), encoding="utf-8")
            out_dir = Path(tmpdir) / "out"

            result = SDR.run_delta(
                cursor_id=65823,
                out_dir=out_dir,
                dry_run=True,
                inject_json=fixture,
                json_only=False,
                max_pages=5,
                page_size=100,
                language_filter=None,
                srd_mod=SRD,
            )
            self.assertEqual(result["verdict"], "POSITIVE-DRY-RUN")
            # upstream_result.written shows 3 records processed before quality gate
            self.assertEqual(result["upstream_result"]["written"], 3)
            # quality gate rejects all 3 (synthetic_fixture=True)
            self.assertEqual(result["rejected_breakdown"]["quality_gate"], 3)
            self.assertEqual(result["unchanged_count"], 0)
            # cursor correctly moved to the highest id seen
            self.assertTrue(result["cursor_movement"]["moved"])
            self.assertEqual(result["cursor_movement"]["prior"], 65823)
            self.assertEqual(result["cursor_movement"]["new"], 70003)

    def test_dry_run_new_records_json_only(self):
        """Dry-run json_only=True: no YAML quality scan; upstream written=3, new_count=3."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fixture = Path(tmpdir) / "fixture.json"
            _write_fixture(fixture, [_mk_fixture_finding(fid) for fid in [70001, 70002, 70003]])
            out_dir = Path(tmpdir) / "out"

            result = SDR.run_delta(
                cursor_id=65823,
                out_dir=out_dir,
                dry_run=True,
                inject_json=fixture,
                json_only=True,   # no YAML written; quality gate not applied
                max_pages=5,
                page_size=100,
                language_filter=None,
                srd_mod=SRD,
            )
            self.assertEqual(result["verdict"], "POSITIVE-DRY-RUN")
            self.assertEqual(result["new_count"], 3)
            self.assertEqual(result["unchanged_count"], 0)
            self.assertTrue(result["cursor_movement"]["moved"])
            self.assertEqual(result["cursor_movement"]["new"], 70003)

    def test_dry_run_already_seen_findings(self):
        """Findings with id <= cursor -> new_count=0, unchanged_count=3."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fixture = Path(tmpdir) / "fixture.json"
            _write_fixture(fixture, [_mk_fixture_finding(fid) for fid in [60000, 61000, 62000]])
            cursor_file = Path(tmpdir) / "cursor.json"
            cursor_file.write_text(json.dumps(_mk_cursor(65823)), encoding="utf-8")
            out_dir = Path(tmpdir) / "out"

            result = SDR.run_delta(
                cursor_id=65823,
                out_dir=out_dir,
                dry_run=True,
                inject_json=fixture,
                json_only=False,
                max_pages=5,
                page_size=100,
                language_filter=None,
                srd_mod=SRD,
            )
            # All three have id < cursor_id=65823 -> skipped
            self.assertEqual(result["new_count"], 0)
            self.assertEqual(result["unchanged_count"], 3)
            self.assertFalse(result["cursor_movement"]["moved"])

    def test_dry_run_no_fixture_returns_negative(self):
        """--dry-run without --inject-json -> NEGATIVE verdict."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = SDR.run_delta(
                cursor_id=0,
                out_dir=Path(tmpdir) / "out",
                dry_run=True,
                inject_json=None,
                json_only=True,
                max_pages=5,
                page_size=100,
                language_filter=None,
                srd_mod=SRD,
            )
            self.assertEqual(result["verdict"], "NEGATIVE")
            self.assertIn("--inject-json", result["reason"])

    def test_dry_run_missing_fixture_returns_negative(self):
        """--dry-run with non-existent fixture path -> NEGATIVE verdict."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = SDR.run_delta(
                cursor_id=0,
                out_dir=Path(tmpdir) / "out",
                dry_run=True,
                inject_json=Path("/nonexistent/fixture.json"),
                json_only=True,
                max_pages=5,
                page_size=100,
                language_filter=None,
                srd_mod=SRD,
            )
            self.assertEqual(result["verdict"], "NEGATIVE")


# ---------------------------------------------------------------------------
# Case 3: No-key offline mode
# ---------------------------------------------------------------------------

class TestNoKeyOffline(unittest.TestCase):
    def test_no_api_key_returns_negative_no_key(self):
        """No SOLODIT_API_KEY -> verdict=NEGATIVE-NO-KEY, network_performed=False."""
        env_without_key = {k: v for k, v in os.environ.items() if k != "SOLODIT_API_KEY"}
        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch.dict(os.environ, env_without_key, clear=True):
                result = SDR.run_delta(
                    cursor_id=65823,
                    out_dir=Path(tmpdir) / "out",
                    dry_run=False,
                    inject_json=None,
                    json_only=True,
                    max_pages=5,
                    page_size=100,
                    language_filter=None,
                    srd_mod=SRD,
                )
            self.assertEqual(result["verdict"], "NEGATIVE-NO-KEY")
            self.assertFalse(result.get("network_performed", True))
            self.assertEqual(result["new_count"], 0)
            self.assertEqual(result["changed_count"], 0)
            self.assertFalse(result["cursor_movement"]["moved"])


# ---------------------------------------------------------------------------
# Case 4: Quality gate
# ---------------------------------------------------------------------------

class TestQualityGate(unittest.TestCase):
    def test_accepted_record(self):
        """Record with all required fields -> 'accepted'."""
        record = {
            "record_source_url": "https://solodit.cyfrin.io/issues/sample-1",
            "verification_tier": "tier-2-verified-public-archive",
            "severity_at_finding": "high",
            "attack_class": "reentrancy",
        }
        self.assertEqual(SDR._quality_verdict(record), "accepted")

    def test_rejected_missing_attack_class(self):
        """Missing attack_class -> rejected-missing-attack_class."""
        record = {
            "record_source_url": "https://solodit.cyfrin.io/issues/sample-2",
            "verification_tier": "tier-2-verified-public-archive",
            "severity_at_finding": "high",
        }
        verdict = SDR._quality_verdict(record)
        self.assertIn("rejected", verdict)

    def test_rejected_wrong_tier(self):
        """Wrong verification_tier -> rejected-wrong-tier."""
        record = {
            "record_source_url": "https://solodit.cyfrin.io/issues/sample-3",
            "verification_tier": "tier-1-verified-realtime-api",  # wrong for Solodit
            "severity_at_finding": "high",
            "attack_class": "reentrancy",
        }
        verdict = SDR._quality_verdict(record)
        self.assertIn("wrong-tier", verdict)

    def test_rejected_synthetic_fixture(self):
        """Synthetic fixture record -> rejected."""
        record = {
            "record_source_url": "https://solodit.cyfrin.io/issues/sample-4",
            "verification_tier": "tier-2-verified-public-archive",
            "severity_at_finding": "high",
            "attack_class": "reentrancy",
            "record_extensions": {"synthetic_fixture": True},
        }
        self.assertEqual(SDR._quality_verdict(record), "rejected-synthetic-fixture")


# ---------------------------------------------------------------------------
# Case 5: Build report shape
# ---------------------------------------------------------------------------

class TestBuildReport(unittest.TestCase):
    def test_report_schema_and_required_keys(self):
        """build_report returns all required schema keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cursor_file = Path(tmpdir) / "cursor.json"
            cursor_file.write_text(json.dumps(_mk_cursor(65823)), encoding="utf-8")
            stale = SDR.staleness_report(_mk_cursor(65823))
            delta = {
                "verdict": "NEGATIVE-NO-KEY",
                "new_count": 0,
                "changed_count": 0,
                "unchanged_count": 0,
                "rejected_count": 0,
                "cursor_movement": {"prior": 65823, "new": 65823, "moved": False},
                "source_links": [],
            }
            report = SDR.build_report(
                delta=delta,
                staleness=stale,
                out_dir=Path(tmpdir) / "out",
                cursor_file=cursor_file,
                language_filter=None,
            )
            self.assertEqual(report["schema"], SDR.REPORT_SCHEMA)
            self.assertIn("staleness", report)
            self.assertIn("delta", report)
            self.assertIn("sidecar_refresh_status", report)
            self.assertIn("generated_at", report)
            self.assertIn("source", report)
            self.assertEqual(report["source"], "https://solodit.cyfrin.io/api/v1/solodit/findings")

    def test_report_sidecar_refresh_false_when_no_writes(self):
        """sidecar_refresh_status.sidecar_refreshed=False when written=0."""
        with tempfile.TemporaryDirectory() as tmpdir:
            delta = {
                "new_count": 0,
                "cursor_movement": {"prior": 0, "new": 0, "moved": False},
            }
            report = SDR.build_report(
                delta=delta,
                staleness={"is_stale": True},
                out_dir=Path(tmpdir) / "out",
                cursor_file=Path(tmpdir) / "cursor.json",
                language_filter=None,
            )
            self.assertFalse(report["sidecar_refresh_status"]["sidecar_refreshed"])


# ---------------------------------------------------------------------------
# Case 6: CLI round-trip with fixture
# ---------------------------------------------------------------------------

class TestCLI(unittest.TestCase):
    def test_cli_dry_run_emits_json_report(self):
        """CLI --dry-run --inject-json --json-only -> valid JSON report on stdout."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fixture = Path(tmpdir) / "fixture.json"
            _write_fixture(fixture, [_mk_fixture_finding(fid) for fid in [70100, 70101]])
            cursor_file = Path(tmpdir) / "cursor.json"
            cursor_file.write_text(json.dumps(_mk_cursor(65823)), encoding="utf-8")

            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc = SDR.main([
                    "--cursor-file", str(cursor_file),
                    "--dry-run",
                    "--inject-json", str(fixture),
                    "--json-only",
                ])
            self.assertEqual(rc, 0)
            out = json.loads(buf.getvalue())
            self.assertEqual(out["schema"], SDR.REPORT_SCHEMA)
            self.assertEqual(out["delta"]["new_count"], 2)
            self.assertTrue(out["delta"]["cursor_movement"]["moved"])

    def test_cli_no_key_dry_run_offline_report(self):
        """CLI with no SOLODIT_API_KEY and no --inject-json -> NEGATIVE-NO-KEY delta."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cursor_file = Path(tmpdir) / "cursor.json"
            cursor_file.write_text(json.dumps(_mk_cursor(65823)), encoding="utf-8")

            env_no_key = {k: v for k, v in os.environ.items() if k != "SOLODIT_API_KEY"}
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf), mock.patch.dict(os.environ, env_no_key, clear=True):
                rc = SDR.main([
                    "--cursor-file", str(cursor_file),
                    "--json-only",
                ])
            self.assertEqual(rc, 0)
            out = json.loads(buf.getvalue())
            self.assertEqual(out["delta"]["verdict"], "NEGATIVE-NO-KEY")

    def test_cli_report_out_writes_file(self):
        """--report-out writes JSON to the specified file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cursor_file = Path(tmpdir) / "cursor.json"
            cursor_file.write_text(json.dumps(_mk_cursor(65823)), encoding="utf-8")
            report_path = Path(tmpdir) / "report.json"

            buf = io.StringIO()
            env_no_key = {k: v for k, v in os.environ.items() if k != "SOLODIT_API_KEY"}
            with mock.patch("sys.stdout", buf), mock.patch.dict(os.environ, env_no_key, clear=True):
                rc = SDR.main([
                    "--cursor-file", str(cursor_file),
                    "--json-only",
                    "--report-out", str(report_path),
                ])
            self.assertEqual(rc, 0)
            self.assertTrue(report_path.exists())
            report = json.loads(report_path.read_text())
            self.assertEqual(report["schema"], SDR.REPORT_SCHEMA)

    def test_cli_staleness_only_no_network(self):
        """--staleness-only never touches the network regardless of SOLODIT_API_KEY."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cursor_file = Path(tmpdir) / "cursor.json"
            cursor_file.write_text(json.dumps(_mk_cursor(65823)), encoding="utf-8")

            network_called = []

            def _fake_urlopen(*args, **kwargs):
                network_called.append(True)
                raise AssertionError("network was called in staleness-only mode")

            buf = io.StringIO()
            import urllib.request
            with mock.patch("sys.stdout", buf), mock.patch.object(urllib.request, "urlopen", _fake_urlopen):
                rc = SDR.main([
                    "--cursor-file", str(cursor_file),
                    "--staleness-only",
                    "--json-only",
                ])
            self.assertEqual(rc, 0)
            self.assertEqual(network_called, [], "no network call must be made in staleness-only mode")

    def test_cursor_age_days_computation(self):
        """_cursor_age_days returns a non-negative integer for a dated cursor."""
        state = _mk_cursor(65823, "2026-05-20T23:41:35.317461+00:00")
        age = SDR._cursor_age_days(state)
        self.assertIsInstance(age, int)
        self.assertGreaterEqual(age, 0)

    def test_cursor_age_days_none_for_missing(self):
        """_cursor_age_days returns None when updated_at is absent."""
        age = SDR._cursor_age_days({"last_id": 0})
        self.assertIsNone(age)


# r36-rebuttal: bugfix-inventory-claude-20260610
# ---------------------------------------------------------------------------
# Case 7: Quality gate with pre-existing files (false-green guard)
# ---------------------------------------------------------------------------

class TestQualityGateFalseGreenGuard(unittest.TestCase):
    """Guard against the false-green bug where glob()[:written] iterates
    pre-existing clean files instead of newly-written synthetic ones.

    Setup: out_dir has 5 old clean YAML files (backdated mtime) PLUS 3 new
    synthetic files written by run_delta (fixture records all get
    synthetic_fixture=True from build_v11_record).

    Before the fix: glob()[:3] returns 3 old clean files (APFS inode order),
    reports rejected_count=0 and new_count=3 - a false green.

    After the fix (mtime-sorted tail): iterates the 3 newest files (synthetic),
    reports rejected_count=3, new_count=0 - honest rejection.
    """

    def _write_old_clean_yaml(self, path: Path, index: int) -> None:
        """Write a clean YAML file that looks like a real corpus record."""
        path.write_text(
            f"record_source_url: https://solodit.cyfrin.io/issues/old-{index}\n"
            f"verification_tier: tier-2-verified-public-archive\n"
            f"severity_at_finding: high\n"
            f"attack_class: reentrancy\n",
            encoding="utf-8",
        )
        # Backdate mtime to 1 hour ago so newly-written files are clearly newer.
        old_time = __import__("time").time() - 3600
        __import__("os").utime(path, (old_time, old_time))

    def test_false_green_guard_pre_existing_files(self):
        """Quality gate must scan the N newest files, not the first N in glob order.

        With 5 pre-existing clean files + 3 newly-written synthetic files,
        the gate must report rejected_count>=3 and new_count==0.
        Before the fix (glob()[:3]), the gate returned rejected_count=0 / new_count=3.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "out"
            out_dir.mkdir()

            # Plant 5 old clean YAML files with backdated mtime.
            for i in range(5):
                self._write_old_clean_yaml(out_dir / f"old_{i:04d}.yaml", i)

            # Fixture with 3 new findings past cursor (ids > 65823).
            fixture = Path(tmpdir) / "fixture.json"
            _write_fixture(fixture, [_mk_fixture_finding(fid) for fid in [70010, 70011, 70012]])

            result = SDR.run_delta(
                cursor_id=65823,
                out_dir=out_dir,
                dry_run=True,
                inject_json=fixture,
                json_only=False,  # YAML files must be written for the gate to run
                max_pages=5,
                page_size=100,
                language_filter=None,
                srd_mod=SRD,
            )

            # The 3 newly-written fixture records all carry synthetic_fixture=True,
            # so the quality gate must reject all 3 and produce new_count=0.
            self.assertEqual(
                result["rejected_breakdown"]["quality_gate"], 3,
                "quality gate must detect all 3 synthetic fixture records; "
                f"got {result['rejected_breakdown']['quality_gate']} "
                f"(full result: {result})",
            )
            self.assertEqual(
                result["new_count"], 0,
                "new_count must be 0 after quality gate rejects all synthetic records; "
                f"got {result['new_count']}",
            )
            # Upstream confirms 3 records were processed (written count is correct).
            self.assertEqual(result["upstream_result"]["written"], 3)
            # Cursor still moved - the upstream ingest saw the new ids.
            self.assertTrue(result["cursor_movement"]["moved"])

    def test_false_green_guard_only_new_files_no_pre_existing(self):
        """Baseline: with no pre-existing files the gate also works correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "out"
            # out_dir does not exist yet; run_delta creates it.

            fixture = Path(tmpdir) / "fixture.json"
            _write_fixture(fixture, [_mk_fixture_finding(fid) for fid in [70020, 70021, 70022]])

            result = SDR.run_delta(
                cursor_id=65823,
                out_dir=out_dir,
                dry_run=True,
                inject_json=fixture,
                json_only=False,
                max_pages=5,
                page_size=100,
                language_filter=None,
                srd_mod=SRD,
            )
            self.assertEqual(result["rejected_breakdown"]["quality_gate"], 3)
            self.assertEqual(result["new_count"], 0)


if __name__ == "__main__":
    unittest.main()
