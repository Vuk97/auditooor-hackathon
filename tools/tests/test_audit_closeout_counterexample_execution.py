#!/usr/bin/env python3
"""Tests for the ``counterexample-execution`` close-out row (P0-1 burn-down).

Background
----------
The deep-counterexample queue collects symbolic/fuzz traces, but a queued
trace is *not* proof. Until a replay is wired and a
``poc_execution/**/execution_manifest.json`` is recorded, the trace is
"advisory until replayed". This test module locks down the close-out gate
that warns (and, with ``REQUIRE_REPLAY_EXECUTED=1`` / ``--require-replay-
executed``, fails) when deep counterexample records lack matching execution
manifests.

The cases below mirror the burn-down acceptance grid:

  - empty queue                    -> PASS
  - 1 record, no manifest          -> WARN (advisory)
  - 1 record, manifest present     -> PASS
  - strict env + missing manifest  -> FAIL (rc != 0)
  - 5 records, 3 executed, 2 not   -> WARN with concrete counts

All tests are stdlib-only and hermetic via ``tempfile.TemporaryDirectory``.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "audit-closeout-check.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "audit_closeout_check", TOOL_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["audit_closeout_check"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


def _write_record(
    ws: Path,
    name: str,
    *,
    target_function: str = "Vault.withdraw",
    engine: str = "halmos",
    forge_path: str = "",
) -> Path:
    """Write a minimal but schema-valid deep_counterexample.v1 record."""
    record_dir = ws / "deep_counterexamples"
    record_dir.mkdir(parents=True, exist_ok=True)
    record_path = record_dir / f"{name}.deep_counterexample.v1.json"
    payload = {
        "schema_version": "auditooor.deep_counterexample.v1",
        "engine": engine,
        "target_function": target_function,
        "expected_invariant": "shares decrease",
        "observed_violation": "shares unchanged",
        "promotes_to_poc_work": True,
    }
    if forge_path:
        payload["generated_forge_test_path"] = forge_path
    record_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    return record_path


def _write_manifest(
    ws: Path,
    candidate_id: str,
    *,
    final_result: str = "disproved",
    impact_assertion: str = "not_demonstrated",
    brief_path: str = "",
) -> Path:
    out = ws / "poc_execution" / candidate_id / "execution_manifest.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "auditooor.poc_execution_manifest.v1",
        "candidate_id": candidate_id,
        "brief_path": brief_path,
        "final_result": final_result,
        "impact_assertion": impact_assertion,
    }
    out.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    return out


class EmptyQueueTest(unittest.TestCase):
    """No deep_counterexample.v1 records present -> PASS."""

    def test_empty_queue_passes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-cxq-") as tmp:
            ws = Path(tmp)
            row = MOD.check_counterexample_execution(
                ws, require_replay_executed=False
            )
            self.assertEqual(row.status, MOD.PASS, f"reason={row.reason!r}")
            self.assertEqual(row.detail["record_count"], 0)
            self.assertEqual(row.detail["unreplayed_count"], 0)
            self.assertEqual(row.detail["status_value"], "queue-empty")
            self.assertIn("queue is empty", row.reason)

    def test_empty_queue_passes_under_strict(self) -> None:
        """Strict mode must still PASS when the queue is empty — strict only
        promotes a real backlog of unreplayed records, not absence of work.
        """
        with tempfile.TemporaryDirectory(prefix="aco-cxq-") as tmp:
            ws = Path(tmp)
            row = MOD.check_counterexample_execution(
                ws, require_replay_executed=True
            )
            self.assertEqual(row.status, MOD.PASS, f"reason={row.reason!r}")


class SingleRecordWithoutManifestTest(unittest.TestCase):
    """1 counterexample, no execution manifest -> WARN (advisory)."""

    def test_warns_by_default(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-cxq-") as tmp:
            ws = Path(tmp)
            _write_record(ws, "halmos-vault")
            row = MOD.check_counterexample_execution(
                ws, require_replay_executed=False
            )
            self.assertEqual(row.status, MOD.WARN, f"reason={row.reason!r}")
            self.assertEqual(row.detail["record_count"], 1)
            self.assertEqual(row.detail["executed_count"], 0)
            self.assertEqual(row.detail["unreplayed_count"], 1)
            self.assertEqual(
                row.detail["status_value"],
                MOD.REPLAY_NOT_EXECUTED_STATUS,
            )
            self.assertIn("advisory until replayed", row.reason)
            self.assertIn("executed=0", row.reason)
            self.assertIn("unreplayed=1", row.reason)
            # Sample path of the unreplayed record is surfaced as an artifact
            # so the operator can jump straight to the queue file.
            self.assertEqual(len(row.artifacts), 1)


class SingleRecordWithManifestTest(unittest.TestCase):
    """1 counterexample, matching execution manifest -> PASS."""

    def test_record_id_match_passes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-cxq-") as tmp:
            ws = Path(tmp)
            _write_record(ws, "halmos-vault")
            # candidate_id matches the record_id, which is the suffix-stripped
            # filename.
            _write_manifest(ws, "halmos-vault")
            row = MOD.check_counterexample_execution(
                ws, require_replay_executed=False
            )
            self.assertEqual(row.status, MOD.PASS, f"reason={row.reason!r}")
            self.assertEqual(row.detail["record_count"], 1)
            self.assertEqual(row.detail["executed_count"], 1)
            self.assertEqual(row.detail["unreplayed_count"], 0)
            self.assertEqual(row.detail["status_value"], "all-replayed")
            self.assertIn("replay coverage complete", row.reason)

    def test_target_function_slug_match_passes(self) -> None:
        """Manifest matched on slug(target_function) -> PASS.

        The queue tool also matches on the slug of ``target_function``; this
        check must agree so a manifest written under e.g.
        ``poc_execution/vault.withdraw/`` finds its record.
        """
        with tempfile.TemporaryDirectory(prefix="aco-cxq-") as tmp:
            ws = Path(tmp)
            _write_record(ws, "halmos-novel-trace", target_function="Vault.withdraw")
            _write_manifest(ws, "vault.withdraw")
            row = MOD.check_counterexample_execution(
                ws, require_replay_executed=False
            )
            self.assertEqual(row.status, MOD.PASS, f"reason={row.reason!r}")


class StrictModePromotesToFailTest(unittest.TestCase):
    """REQUIRE_REPLAY_EXECUTED=1 / --require-replay-executed -> FAIL."""

    def test_strict_promotes_warn_to_fail(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-cxq-") as tmp:
            ws = Path(tmp)
            _write_record(ws, "halmos-vault")
            row = MOD.check_counterexample_execution(
                ws, require_replay_executed=True
            )
            self.assertEqual(row.status, MOD.FAIL, f"reason={row.reason!r}")
            self.assertIn("--require-replay-executed", row.reason)
            self.assertIn(MOD.REQUIRE_REPLAY_EXECUTED_ENV, row.reason)
            self.assertEqual(row.detail["unreplayed_count"], 1)
            self.assertTrue(row.detail["require_replay_executed"])

    def test_strict_via_env_var_returns_nonzero_rc(self) -> None:
        """End-to-end: env-var REQUIRE_REPLAY_EXECUTED=1 -> rc != 0."""
        with tempfile.TemporaryDirectory(prefix="aco-cxq-") as tmp:
            ws = Path(tmp)
            _write_record(ws, "halmos-vault")
            saved_env = os.environ.get(MOD.REQUIRE_REPLAY_EXECUTED_ENV)
            try:
                os.environ[MOD.REQUIRE_REPLAY_EXECUTED_ENV] = "1"
                buf = io.StringIO()
                err = io.StringIO()
                with redirect_stdout(buf), redirect_stderr(err):
                    rc = MOD.main(["--workspace", str(ws)])
                self.assertNotEqual(
                    rc, 0,
                    f"expected non-zero rc; got rc={rc}\nout={buf.getvalue()}\n"
                    f"err={err.getvalue()}",
                )
                self.assertIn("counterexample-execution", buf.getvalue())
            finally:
                if saved_env is None:
                    os.environ.pop(MOD.REQUIRE_REPLAY_EXECUTED_ENV, None)
                else:
                    os.environ[MOD.REQUIRE_REPLAY_EXECUTED_ENV] = saved_env

    def test_strict_via_cli_flag_returns_nonzero_rc(self) -> None:
        """End-to-end: --require-replay-executed -> rc != 0."""
        with tempfile.TemporaryDirectory(prefix="aco-cxq-") as tmp:
            ws = Path(tmp)
            _write_record(ws, "halmos-vault")
            buf = io.StringIO()
            err = io.StringIO()
            with redirect_stdout(buf), redirect_stderr(err):
                rc = MOD.main(
                    ["--workspace", str(ws), "--require-replay-executed"]
                )
            self.assertNotEqual(
                rc, 0,
                f"expected non-zero rc; got rc={rc}\nout={buf.getvalue()}",
            )

    def test_default_warn_does_not_fail_run(self) -> None:
        """Without strict: WARN row, but run rc=0 (no FAIL row)."""
        with tempfile.TemporaryDirectory(prefix="aco-cxq-") as tmp:
            ws = Path(tmp)
            _write_record(ws, "halmos-vault")
            # Make sure no other check FAILs by scaffolding the bare minimum
            # pieces needed for canonical-audit to be at least WARN/PASS,
            # hypothesis check WARN (neither file), etc. We only assert that
            # counterexample-execution itself does not promote to FAIL.
            row = MOD.check_counterexample_execution(
                ws, require_replay_executed=False
            )
            self.assertEqual(row.status, MOD.WARN)
            self.assertNotIn("--require-replay-executed", row.reason.split("(pass")[0])


class MixedQueueCountsTest(unittest.TestCase):
    """5 counterexamples, 3 executed, 2 not -> WARN with concrete counts."""

    def test_partial_execution_warns_with_counts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-cxq-") as tmp:
            ws = Path(tmp)
            executed_ids = ["cx-001", "cx-002", "cx-003"]
            unreplayed_ids = ["cx-004", "cx-005"]
            for record_id in executed_ids:
                _write_record(ws, record_id, target_function=f"M.{record_id}")
                _write_manifest(ws, record_id)
            for record_id in unreplayed_ids:
                _write_record(ws, record_id, target_function=f"M.{record_id}")

            row = MOD.check_counterexample_execution(
                ws, require_replay_executed=False
            )
            self.assertEqual(row.status, MOD.WARN, f"reason={row.reason!r}")
            self.assertEqual(row.detail["record_count"], 5)
            self.assertEqual(row.detail["executed_count"], 3)
            self.assertEqual(row.detail["unreplayed_count"], 2)
            self.assertIn("2/5", row.reason)
            self.assertIn("executed=3", row.reason)
            self.assertIn("unreplayed=2", row.reason)
            executed_record_ids = {
                r["record_id"] for r in row.detail["executed_records"]
            }
            unreplayed_record_ids = {
                r["record_id"] for r in row.detail["unreplayed_records"]
            }
            self.assertEqual(executed_record_ids, set(executed_ids))
            self.assertEqual(unreplayed_record_ids, set(unreplayed_ids))

    def test_partial_execution_fails_under_strict(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-cxq-") as tmp:
            ws = Path(tmp)
            for record_id in ("cx-001", "cx-002", "cx-003"):
                _write_record(ws, record_id, target_function=f"M.{record_id}")
                _write_manifest(ws, record_id)
            for record_id in ("cx-004", "cx-005"):
                _write_record(ws, record_id, target_function=f"M.{record_id}")

            row = MOD.check_counterexample_execution(
                ws, require_replay_executed=True
            )
            self.assertEqual(row.status, MOD.FAIL, f"reason={row.reason!r}")
            self.assertEqual(row.detail["unreplayed_count"], 2)


class HumanTableShowsRowTest(unittest.TestCase):
    """The human-readable closeout table includes the new row."""

    def test_human_format_includes_counterexample_execution_row(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-cxq-") as tmp:
            ws = Path(tmp)
            _write_record(ws, "halmos-vault")
            buf = io.StringIO()
            with redirect_stdout(buf):
                MOD.main(["--workspace", str(ws)])
            out = buf.getvalue()
            self.assertIn("counterexample-execution", out)
            self.assertIn("[WARN]", out)


class WriteManifestRecordsRowTest(unittest.TestCase):
    """``--write-manifest`` includes the new row in the audit_closeout
    manifest, and the require_replay_executed flag flows through.
    """

    def test_manifest_records_strict_flag_and_row(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-cxq-") as tmp:
            ws = Path(tmp)
            _write_record(ws, "halmos-vault")
            buf = io.StringIO()
            with redirect_stdout(buf):
                MOD.main([
                    "--workspace", str(ws),
                    "--write-manifest",
                    "--require-replay-executed",
                ])
            doc = json.loads(
                (ws / ".audit_logs" / "audit_closeout_manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertTrue(doc["require_replay_executed"])
            checks = {c["check"]: c for c in doc["checks"]}
            self.assertIn("counterexample-execution", checks)
            row = checks["counterexample-execution"]
            self.assertEqual(row["status"], MOD.FAIL)
            self.assertEqual(row["detail"]["unreplayed_count"], 1)


if __name__ == "__main__":
    unittest.main()
