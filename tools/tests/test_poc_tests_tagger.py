#!/usr/bin/env python3
"""Regression coverage for tools/poc-tests-tagger.py.

Covers:
- Auto-classification across all 5 submission status dirs
  (filed / paste_ready / staging / _killed / _oos_rejected).
- Slug normalization (underscore vs dash, workspace prefix strip,
  severity suffix strip).
- Sentinel JSON shape conformance to auditooor.poc_status.v1.
- gc-dropped dry-run vs --confirm; mtime filter respect.
- Refusal to clobber existing .poc-status without --force.
- Explicit --status / --slug operator tag mode.
- Empirical hyperbridge-style fixture mirroring the 14 PoC dirs the
  capability-gap-7 brief enumerates.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "poc-tests-tagger.py"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _make_workspace(tmpdir: Path) -> Path:
    """Build a fake audit workspace with poc-tests/ + submissions/ dirs."""
    (tmpdir / "poc-tests").mkdir()
    for status in (
        "filed",
        "paste_ready",
        "ready",
        "packaged",
        "staging",
        "held",
        "_killed",
        "_oos_rejected",
        "superseded",
    ):
        (tmpdir / "submissions" / status).mkdir(parents=True)
    return tmpdir


def _add_poc(workspace: Path, slug: str) -> Path:
    p = workspace / "poc-tests" / slug
    p.mkdir()
    (p / "main.go").write_text("// poc body")
    return p


def _add_submission(workspace: Path, status: str, slug: str) -> Path:
    p = workspace / "submissions" / status / slug
    p.mkdir(parents=True)
    (p / f"{slug}.md").write_text("# draft")
    return p


def _read_sentinel(poc_dir: Path) -> dict:
    return json.loads((poc_dir / ".poc-status").read_text())


class AutoClassifyTests(unittest.TestCase):
    def test_filed_submission_maps_to_filed_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            _add_poc(ws, "arbitrum_orbit_unconfirmed_node")
            _add_submission(
                ws, "filed", "hb-arbitrum-orbit-unconfirmed-node-HIGH"
            )
            proc = _run("--workspace", str(ws), "--auto-classify", "--json")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["total"], 1)
            rec = payload["results"][0]
            self.assertEqual(rec["status"], "filed-evidence")
            self.assertIn(
                "submissions/filed/hb-arbitrum-orbit-unconfirmed-node-HIGH",
                rec["cross_reference"],
            )

    def test_killed_submission_maps_to_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            _add_poc(ws, "call_decompressor_size_cap_bypass")
            _add_submission(
                ws,
                "_killed",
                "hb-call-decompressor-size-cap-bypass-KILLED-dupe-SRL-6.10",
            )
            proc = _run("--workspace", str(ws), "--auto-classify", "--json")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            rec = json.loads(proc.stdout)["results"][0]
            self.assertEqual(rec["status"], "dropped")

    def test_oos_rejected_maps_to_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            _add_poc(ws, "scope_misalignment_finding")
            _add_submission(
                ws, "_oos_rejected", "hb-scope-misalignment-finding-OOS"
            )
            proc = _run("--workspace", str(ws), "--auto-classify", "--json")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            rec = json.loads(proc.stdout)["results"][0]
            self.assertEqual(rec["status"], "dropped")

    def test_paste_ready_submission_maps_to_filed_evidence_inflight(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            _add_poc(ws, "pallet_relayer_u256_truncation")
            _add_submission(ws, "paste_ready", "pallet-relayer-u256-truncation")
            proc = _run("--workspace", str(ws), "--auto-classify", "--json")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            rec = json.loads(proc.stdout)["results"][0]
            self.assertEqual(rec["status"], "filed-evidence")

    def test_staging_submission_maps_to_engineering_record(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            _add_poc(ws, "bandwidth_fot_over_credit")
            _add_submission(ws, "staging", "bandwidth-fot-over-credit")
            proc = _run("--workspace", str(ws), "--auto-classify", "--json")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            rec = json.loads(proc.stdout)["results"][0]
            self.assertEqual(rec["status"], "engineering-record")

    def test_no_submission_match_falls_back_to_engineering_record(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            _add_poc(ws, "legacy_scratch_harness_no_filing")
            proc = _run("--workspace", str(ws), "--auto-classify", "--json")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            rec = json.loads(proc.stdout)["results"][0]
            self.assertEqual(rec["status"], "engineering-record")
            self.assertIsNone(rec["cross_reference"])


class SlugNormalizationTests(unittest.TestCase):
    def test_underscore_vs_dash_match(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            _add_poc(ws, "foo_bar_baz_underscored")
            _add_submission(ws, "filed", "hb-foo-bar-baz-underscored-HIGH")
            proc = _run("--workspace", str(ws), "--auto-classify", "--json")
            rec = json.loads(proc.stdout)["results"][0]
            self.assertEqual(rec["status"], "filed-evidence")

    def test_workspace_prefix_strip(self) -> None:
        # PoC dir has no hb- prefix; submission folder has hb- prefix.
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            _add_poc(ws, "optimism_l2oracle_unfinalized_output")
            _add_submission(
                ws, "filed", "hb-optimism-l2oracle-unfinalized-output-HIGH"
            )
            proc = _run("--workspace", str(ws), "--auto-classify", "--json")
            rec = json.loads(proc.stdout)["results"][0]
            self.assertEqual(rec["status"], "filed-evidence")

    def test_killed_with_descriptive_suffix(self) -> None:
        # Suffix like KILLED-no-rubric-row should not block matching.
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            _add_poc(ws, "pharos_validator_set_decoder")
            _add_submission(
                ws,
                "_killed",
                "hb-pharos-validator-set-decoder-unbounded-alloc-KILLED-no-rubric-row",
            )
            proc = _run("--workspace", str(ws), "--auto-classify", "--json")
            rec = json.loads(proc.stdout)["results"][0]
            self.assertEqual(rec["status"], "dropped")


class SentinelShapeTests(unittest.TestCase):
    def test_sentinel_json_conforms_to_schema(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            poc = _add_poc(ws, "vwap_int256_overflow")
            _add_submission(ws, "staging", "vwap-int256-overflow")
            proc = _run("--workspace", str(ws), "--auto-classify")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            sentinel = _read_sentinel(poc)
            self.assertEqual(sentinel["schema"], "auditooor.poc_status.v1")
            self.assertEqual(sentinel["status"], "engineering-record")
            self.assertEqual(sentinel["finding_slug"], "vwap_int256_overflow")
            self.assertEqual(sentinel["classification_mode"], "auto")
            # ISO-8601 UTC; ends with Z.
            self.assertTrue(sentinel["classified_at"].endswith("Z"))
            self.assertIn("tool_version", sentinel)

    def test_explicit_tag_mode_sets_classification_mode(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            poc = _add_poc(ws, "univ3_univ4_wrapper_refund")
            proc = _run(
                "--workspace",
                str(ws),
                "--status",
                "superseded",
                "--slug",
                "univ3_univ4_wrapper_refund",
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            sentinel = _read_sentinel(poc)
            self.assertEqual(sentinel["status"], "superseded")
            self.assertEqual(sentinel["classification_mode"], "explicit")
            self.assertIsNone(sentinel["cross_reference"])


class ClobberRefusalTests(unittest.TestCase):
    def test_refuse_to_clobber_existing_sentinel(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            poc = _add_poc(ws, "fuzz_pallet_bandwidth")
            (poc / ".poc-status").write_text(json.dumps({"status": "old"}))
            proc = _run(
                "--workspace",
                str(ws),
                "--status",
                "engineering-record",
                "--slug",
                "fuzz_pallet_bandwidth",
            )
            self.assertEqual(proc.returncode, 2, proc.stderr)
            # Sentinel must remain untouched.
            self.assertEqual(
                json.loads((poc / ".poc-status").read_text())["status"],
                "old",
            )

    def test_force_overwrites_existing_sentinel(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            poc = _add_poc(ws, "fuzz_scale_codec")
            (poc / ".poc-status").write_text(json.dumps({"status": "old"}))
            proc = _run(
                "--workspace",
                str(ws),
                "--status",
                "engineering-record",
                "--slug",
                "fuzz_scale_codec",
                "--force",
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(
                _read_sentinel(poc)["status"], "engineering-record"
            )

    def test_auto_classify_skips_existing_sentinels(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            poc = _add_poc(ws, "eip1153_transient_auth")
            (poc / ".poc-status").write_text(json.dumps({"status": "keep"}))
            proc = _run(
                "--workspace", str(ws), "--auto-classify", "--json"
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            rec = json.loads(proc.stdout)["results"][0]
            self.assertFalse(rec["written"])
            self.assertEqual(rec["message"], "exists")
            # File contents preserved.
            self.assertEqual(
                json.loads((poc / ".poc-status").read_text())["status"],
                "keep",
            )


class GcDroppedTests(unittest.TestCase):
    def test_dry_run_does_not_remove(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            poc = _add_poc(ws, "kill_me_dropped")
            sentinel = poc / ".poc-status"
            sentinel.write_text(json.dumps({"status": "dropped"}))
            # Backdate the sentinel mtime by 60 days.
            old_ts = time.time() - 60 * 86400
            os.utime(sentinel, (old_ts, old_ts))
            proc = _run(
                "--workspace",
                str(ws),
                "--gc-dropped",
                "--older-than",
                "30d",
                "--json",
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["mode"], "DRY-RUN")
            self.assertEqual(len(payload["to_remove"]), 1)
            # PoC dir is still present.
            self.assertTrue(poc.exists())

    def test_confirm_removes_eligible_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            poc = _add_poc(ws, "really_kill_me")
            sentinel = poc / ".poc-status"
            sentinel.write_text(json.dumps({"status": "dropped"}))
            old_ts = time.time() - 60 * 86400
            os.utime(sentinel, (old_ts, old_ts))
            proc = _run(
                "--workspace",
                str(ws),
                "--gc-dropped",
                "--older-than",
                "30d",
                "--confirm",
                "--json",
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["mode"], "REMOVE")
            self.assertEqual(len(payload["to_remove"]), 1)
            self.assertFalse(poc.exists())

    def test_recent_dropped_dir_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            poc = _add_poc(ws, "recently_dropped")
            (poc / ".poc-status").write_text(json.dumps({"status": "dropped"}))
            # Default mtime is now; should be filtered out by 30d TTL.
            proc = _run(
                "--workspace",
                str(ws),
                "--gc-dropped",
                "--older-than",
                "30d",
                "--json",
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(len(payload["to_remove"]), 0)
            self.assertEqual(len(payload["skipped"]), 1)
            self.assertTrue(poc.exists())

    def test_filed_dir_is_not_eligible_for_gc(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            poc = _add_poc(ws, "filed_keep_me")
            sentinel = poc / ".poc-status"
            sentinel.write_text(json.dumps({"status": "filed-evidence"}))
            old_ts = time.time() - 90 * 86400
            os.utime(sentinel, (old_ts, old_ts))
            proc = _run(
                "--workspace",
                str(ws),
                "--gc-dropped",
                "--older-than",
                "30d",
                "--confirm",
                "--json",
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(len(payload["to_remove"]), 0)
            self.assertTrue(poc.exists())

    def test_unsentineled_dir_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            poc = _add_poc(ws, "no_sentinel_yet")
            proc = _run(
                "--workspace",
                str(ws),
                "--gc-dropped",
                "--older-than",
                "30d",
                "--json",
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(len(payload["to_remove"]), 0)
            # 1 skipped (no sentinel).
            self.assertEqual(len(payload["skipped"]), 1)
            self.assertTrue(poc.exists())


class HyperbridgeAnchorTests(unittest.TestCase):
    """Anchor test mirroring the 14 PoC dirs the brief enumerates for
    /Users/wolf/audits/hyperbridge/poc-tests/.

    Build a synthetic mini-workspace that matches the production
    structure and assert all 14 classify correctly.
    """

    POC_DIRS = (
        "arbitrum_orbit_unconfirmed_node",
        "bandwidth-fot-over-credit",
        "eip1153-transient-auth",
        "fuzz-ethereum-trie",
        "fuzz-intents-transient-auth",
        "fuzz-pallet-bandwidth",
        "fuzz-scale-codec",
        "fuzz-vwap-oracle",
        "fuzz_triedb_codec",
        "optimism_l2oracle_unfinalized_output",
        "pallet-relayer-u256-truncation",
        "storage-slot-mismatch",
        "univ3_univ4_wrapper_refund",
        "vwap-int256-overflow",
    )
    SUBMISSIONS = (
        # (status, folder name)
        ("filed", "hb-arbitrum-orbit-unconfirmed-node-HIGH"),
        ("filed", "hb-optimism-l2oracle-unfinalized-output-HIGH"),
        ("filed", "hb-univ3-univ4-wrapper-refund-deployer-MEDIUM"),
        ("_killed", "hb-call-decompressor-size-cap-bypass-KILLED-dupe-SRL-6.10"),
        ("_killed", "hb-hft-superapprove-unrestricted-KILLED"),
        (
            "_killed",
            "hb-pharos-validator-set-decoder-unbounded-alloc-KILLED-no-rubric-row",
        ),
        ("paste_ready", "pallet-relayer-u256-truncation"),
        ("staging", "bandwidth-fot-over-credit"),
        ("staging", "vwap-int256-overflow"),
    )

    def test_all_fourteen_classify(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            for slug in self.POC_DIRS:
                _add_poc(ws, slug)
            for status, name in self.SUBMISSIONS:
                _add_submission(ws, status, name)
            proc = _run(
                "--workspace", str(ws), "--auto-classify", "--json"
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["total"], 14)
            by_slug = {r["slug"]: r for r in payload["results"]}
            # Expected classifications.
            expected = {
                "arbitrum_orbit_unconfirmed_node": "filed-evidence",
                "optimism_l2oracle_unfinalized_output": "filed-evidence",
                "univ3_univ4_wrapper_refund": "filed-evidence",
                "pallet-relayer-u256-truncation": "filed-evidence",
                "bandwidth-fot-over-credit": "engineering-record",
                "vwap-int256-overflow": "engineering-record",
                # Killed PoCs without matching submission folder names
                # (the killed submission slugs don't directly map to
                # those PoC dir names) still default to engineering-record.
                "eip1153-transient-auth": "engineering-record",
                "fuzz-ethereum-trie": "engineering-record",
                "fuzz-intents-transient-auth": "engineering-record",
                "fuzz-pallet-bandwidth": "engineering-record",
                "fuzz-scale-codec": "engineering-record",
                "fuzz-vwap-oracle": "engineering-record",
                "fuzz_triedb_codec": "engineering-record",
                "storage-slot-mismatch": "engineering-record",
            }
            for slug, want in expected.items():
                self.assertEqual(
                    by_slug[slug]["status"],
                    want,
                    f"slug {slug}: want {want} got {by_slug[slug]['status']}",
                )


class CliErrorTests(unittest.TestCase):
    def test_missing_workspace_errors(self) -> None:
        proc = _run(
            "--workspace",
            "/tmp/nonexistent-workspace-xyzzy",
            "--auto-classify",
        )
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn("workspace not found", proc.stderr)

    def test_missing_poc_tests_dir_errors(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            # No poc-tests/ subdir.
            (Path(td) / "submissions").mkdir()
            proc = _run("--workspace", td, "--auto-classify")
            self.assertEqual(proc.returncode, 1, proc.stderr)
            self.assertIn("poc-tests/ not found", proc.stderr)

    def test_status_without_slug_errors(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            proc = _run(
                "--workspace",
                str(ws),
                "--status",
                "superseded",
            )
            self.assertEqual(proc.returncode, 1, proc.stderr)
            self.assertIn("--slug", proc.stderr)

    def test_invalid_duration_errors(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            proc = _run(
                "--workspace",
                str(ws),
                "--gc-dropped",
                "--older-than",
                "fortnight",
            )
            self.assertEqual(proc.returncode, 1, proc.stderr)
            self.assertIn("invalid duration", proc.stderr)


if __name__ == "__main__":
    unittest.main()
