"""Tests for tools/wave2-a-close-readiness.py.

Synthetic fixtures only.  No corpus material is created here; the test
exercises each of the six Wave-2-A close criteria via fake workspaces
and via the ``--skip-criteria`` testing knob.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, Iterable
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "wave2-a-close-readiness.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "wave2_a_close_readiness", str(TOOL_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


READINESS = _load_module()


def _make_fake_workspace(
    tmp: Path,
    *,
    validator_payload: Dict[str, Any] | None = None,
    record_quality_rows: Iterable[Dict[str, Any]] | None = None,
    tag_records: Iterable[tuple[str, str]] | None = None,
    redirect_manifest: Dict[str, Any] | None = None,
    presubmit_text: str | None = None,
) -> Path:
    """Synthesize a workspace with just enough surface for each criterion.

    The ``wave2-w21-post-migration-validator.py`` is replaced with a
    Python stub that simply prints the JSON payload we supply.
    """
    ws = tmp / "ws"
    (ws / "tools").mkdir(parents=True)
    (ws / "audit" / "corpus_tags" / "derived").mkdir(parents=True)
    (ws / "audit" / "corpus_tags" / "tags" / "_deprecated").mkdir(parents=True)

    # Stub validator that emits the requested payload.
    if validator_payload is None:
        validator_payload = {
            "overall_status": "PASS",
            "v1_record_count": 0,
            "v1_1_record_count": 100,
        }
    stub = ws / "tools" / "wave2-w21-post-migration-validator.py"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        f"print(json.dumps({json.dumps(validator_payload)}))\n"
    )
    stub.chmod(0o755)

    # record_quality.jsonl
    rq = ws / "audit" / "corpus_tags" / "derived" / "record_quality.jsonl"
    rows = list(record_quality_rows or [])
    with rq.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")

    # tags/*.yaml records
    records = list(tag_records or [])
    for stem, body in records:
        (ws / "audit" / "corpus_tags" / "tags" / stem).write_text(body)

    # REDIRECT_MANIFEST.json
    if redirect_manifest is None:
        redirect_manifest = {
            "schema_version": "auditooor.hackerman_redirect_manifest.v1",
            "wave2_w26_execution_ledger": {"wave_id": "W2.6"},
            "verdict_artefacts": [
                {
                    "record_id": "verdict_tag:ASA-2024-0012-stub",
                    "marker_field": "verdict_artefact",
                    "marker_value": True,
                    "reason": "stub fixture marking ASA-2024-0012",
                }
            ],
        }
    (ws / "audit" / "corpus_tags" / "tags" / "_deprecated" / "REDIRECT_MANIFEST.json").write_text(
        json.dumps(redirect_manifest)
    )

    # pre-submit-check.sh
    if presubmit_text is None:
        presubmit_text = (
            "#!/usr/bin/env bash\n"
            "# Check #73: R38-BUG-CLASS-SHIFT wiring\n"
            "# Check #74: R39-ATTACK-CLASS-ORPHAN wiring\n"
            "echo R38-BUG-CLASS-SHIFT R39-ATTACK-CLASS-ORPHAN\n"
        )
    (ws / "tools" / "pre-submit-check.sh").write_text(presubmit_text)

    return ws


def _all_pass_records(n: int = 5) -> list[tuple[str, str]]:
    """Generate n tier-2 records each with verification_tier set."""
    return [
        (
            f"rec-{i}.yaml",
            (
                "schema_version: auditooor.hackerman_record.v1.1\n"
                f"record_id: rec-{i}\n"
                "verification_tier: tier-2-verified-public-archive\n"
            ),
        )
        for i in range(n)
    ]


def _high_quality_record_quality(n: int = 2000) -> list[Dict[str, Any]]:
    return [
        {
            "record_id": f"rec-{i}",
            "record_quality_score": 4.0,
        }
        for i in range(n)
    ]


class TestAllCriteriaPass(unittest.TestCase):
    """Synthesize a workspace where every criterion passes."""

    def test_all_pass_yields_ready_to_merge(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_fake_workspace(
                Path(tmp),
                tag_records=_all_pass_records(n=2000),
                record_quality_rows=_high_quality_record_quality(n=2000),
            )
            # Make criterion 6 PASS via test_modules_override pointing at a
            # trivial unittest-discoverable module path is awkward; we
            # instead patch the function.
            with mock.patch.object(
                READINESS,
                "check_criterion_5_hackerman_pre_merge",
                return_value={
                    "name": READINESS.CRITERION_NAMES[4],
                    "status": "PASS",
                    "detail": "stubbed PASS",
                    "evidence_ref": "stub",
                },
            ), mock.patch.object(
                READINESS,
                "check_criterion_6_test_suites",
                return_value={
                    "name": READINESS.CRITERION_NAMES[5],
                    "status": "PASS",
                    "detail": "stubbed PASS",
                    "evidence_ref": "stub",
                },
            ):
                payload = READINESS.evaluate(ws)
        self.assertEqual(payload["overall_status"], "READY_TO_MERGE")
        self.assertEqual(payload["failures"], [])


class TestCriterion1Failure(unittest.TestCase):
    """Validator emits v1_record_count > 0 -> criterion 1 FAIL."""

    def test_v1_records_remaining_blocks_close(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_fake_workspace(
                Path(tmp),
                validator_payload={
                    "overall_status": "FAIL",
                    "v1_record_count": 41100,
                    "v1_1_record_count": 0,
                },
                tag_records=_all_pass_records(n=2000),
                record_quality_rows=_high_quality_record_quality(n=2000),
            )
            with mock.patch.object(
                READINESS,
                "check_criterion_5_hackerman_pre_merge",
                return_value={
                    "name": READINESS.CRITERION_NAMES[4],
                    "status": "PASS",
                    "detail": "stub",
                    "evidence_ref": "stub",
                },
            ), mock.patch.object(
                READINESS,
                "check_criterion_6_test_suites",
                return_value={
                    "name": READINESS.CRITERION_NAMES[5],
                    "status": "PASS",
                    "detail": "stub",
                    "evidence_ref": "stub",
                },
            ):
                payload = READINESS.evaluate(ws)
        self.assertEqual(payload["overall_status"], "BLOCKED")
        self.assertIn(
            "schema_v1_1_migration_complete", payload["failures"]
        )


class TestCriterion3Failure(unittest.TestCase):
    """REDIRECT_MANIFEST missing wave2_w26_execution_ledger block."""

    def test_missing_w26_block_blocks_close(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_fake_workspace(
                Path(tmp),
                redirect_manifest={
                    "schema_version": "auditooor.hackerman_redirect_manifest.v1",
                    # no wave2_w26_execution_ledger
                    "verdict_artefacts": [],
                },
                tag_records=_all_pass_records(n=2000),
                record_quality_rows=_high_quality_record_quality(n=2000),
            )
            with mock.patch.object(
                READINESS,
                "check_criterion_5_hackerman_pre_merge",
                return_value={
                    "name": READINESS.CRITERION_NAMES[4],
                    "status": "PASS",
                    "detail": "stub",
                    "evidence_ref": "stub",
                },
            ), mock.patch.object(
                READINESS,
                "check_criterion_6_test_suites",
                return_value={
                    "name": READINESS.CRITERION_NAMES[5],
                    "status": "PASS",
                    "detail": "stub",
                    "evidence_ref": "stub",
                },
            ):
                payload = READINESS.evaluate(ws)
        self.assertEqual(payload["overall_status"], "BLOCKED")
        self.assertIn(
            "cosmos_sdk_dedup_residual_resolved", payload["failures"]
        )


class TestCriterion4Failure(unittest.TestCase):
    """pre-submit-check.sh missing Check #73 string."""

    def test_missing_check_73_blocks_close(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_fake_workspace(
                Path(tmp),
                presubmit_text=(
                    "#!/usr/bin/env bash\n"
                    "# Only Check 74: R39-ATTACK-CLASS-ORPHAN wired\n"
                    "echo R39-ATTACK-CLASS-ORPHAN\n"
                ),
                tag_records=_all_pass_records(n=2000),
                record_quality_rows=_high_quality_record_quality(n=2000),
            )
            with mock.patch.object(
                READINESS,
                "check_criterion_5_hackerman_pre_merge",
                return_value={
                    "name": READINESS.CRITERION_NAMES[4],
                    "status": "PASS",
                    "detail": "stub",
                    "evidence_ref": "stub",
                },
            ), mock.patch.object(
                READINESS,
                "check_criterion_6_test_suites",
                return_value={
                    "name": READINESS.CRITERION_NAMES[5],
                    "status": "PASS",
                    "detail": "stub",
                    "evidence_ref": "stub",
                },
            ):
                payload = READINESS.evaluate(ws)
        self.assertEqual(payload["overall_status"], "BLOCKED")
        self.assertIn(
            "r38_r39_wired_into_pre_submit_check", payload["failures"]
        )


class TestCriterion6Failure(unittest.TestCase):
    """Synthetic test failure injected by patching the test runner."""

    def test_unittest_failure_blocks_close(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_fake_workspace(
                Path(tmp),
                tag_records=_all_pass_records(n=2000),
                record_quality_rows=_high_quality_record_quality(n=2000),
            )

            def _failing_run(*args, **kwargs):
                # Simulate `subprocess.run` returning non-zero for the test
                # suite invocation.
                class R:
                    returncode = 1
                    stdout = ""
                    stderr = "FAILED (errors=1)\n"

                return R()

            with mock.patch.object(
                READINESS,
                "check_criterion_5_hackerman_pre_merge",
                return_value={
                    "name": READINESS.CRITERION_NAMES[4],
                    "status": "PASS",
                    "detail": "stub",
                    "evidence_ref": "stub",
                },
            ), mock.patch.object(
                READINESS.subprocess, "run", side_effect=_failing_run
            ):
                # criterion 1 will also call subprocess.run; we need to
                # narrow the patch.  Re-do without the global subprocess
                # patch by routing through --skip-criteria for #1..#5 and
                # only exercising criterion 6 here.
                payload = READINESS.evaluate(
                    ws,
                    skip_criteria={
                        READINESS.CRITERION_NAMES[0],
                        READINESS.CRITERION_NAMES[1],
                        READINESS.CRITERION_NAMES[2],
                        READINESS.CRITERION_NAMES[3],
                        READINESS.CRITERION_NAMES[4],
                    },
                )
        self.assertEqual(payload["overall_status"], "BLOCKED")
        self.assertIn("wave2_a_test_suites_pass", payload["failures"])


class TestStrictExitCode(unittest.TestCase):
    """--strict returns 1 on BLOCKED/PARTIAL, 0 on READY_TO_MERGE."""

    def test_strict_exits_zero_on_ready(self):
        with mock.patch.object(
            READINESS,
            "evaluate",
            return_value={
                "schema": READINESS.SCHEMA,
                "branch": "x",
                "head_sha": "x",
                "pr_url": READINESS.PR_URL,
                "overall_status": "READY_TO_MERGE",
                "criteria": [],
                "failures": [],
                "passes": [],
                "skipped": [],
            },
        ):
            rc = READINESS.main(["--json", "--strict"])
        self.assertEqual(rc, 0)

    def test_strict_exits_one_on_blocked(self):
        with mock.patch.object(
            READINESS,
            "evaluate",
            return_value={
                "schema": READINESS.SCHEMA,
                "branch": "x",
                "head_sha": "x",
                "pr_url": READINESS.PR_URL,
                "overall_status": "BLOCKED",
                "criteria": [],
                "failures": ["schema_v1_1_migration_complete"],
                "passes": [],
                "skipped": [],
            },
        ):
            rc = READINESS.main(["--json", "--strict"])
        self.assertEqual(rc, 1)

    def test_strict_exits_one_on_partial(self):
        with mock.patch.object(
            READINESS,
            "evaluate",
            return_value={
                "schema": READINESS.SCHEMA,
                "branch": "x",
                "head_sha": "x",
                "pr_url": READINESS.PR_URL,
                "overall_status": "PARTIAL",
                "criteria": [],
                "failures": [],
                "passes": [],
                "skipped": ["hackerman_pre_merge_pass"],
            },
        ):
            rc = READINESS.main(["--json", "--strict"])
        self.assertEqual(rc, 1)


class TestCriterion5PreMergeCache(unittest.TestCase):
    """Pre-merge cache read paths (Wave-2 PR-A PR #728).

    Four cases:

      1. cache-found-PASS-via-cache: cache file exists with
         overall_status=PASS -> criterion 5 PASS.
      2. cache-found-FAIL-via-cache: cache file exists with
         overall_status=FAIL -> criterion 5 FAIL.
      3. cache-missing-graceful-SKIP: no cache file anywhere, no
         --run-pre-merge -> criterion 5 SKIPPED with diagnostic.
      4. cache-and-run-flag-prefers-run: cache file exists AND
         --run-pre-merge is true -> the live invocation path is used,
         cache is ignored.

    All cache payloads are tagged ``synthetic_fixture: true`` per
    Wave-2 PR-A test discipline.
    """

    def _write_cache(self, path: Path, overall_status: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload: Dict[str, Any] = {
            "schema": "auditooor.hackerman_pre_merge.v1",
            "synthetic_fixture": True,
            "timestamp": "2026-05-16T12:00:00Z",
            "generated_at": "2026-05-16T12:00:00Z",
            "overall": overall_status,
            "overall_status": overall_status,
            "exit_code": 0 if overall_status == "PASS" else 1,
            "runtime_seconds": 1234.56,
            "sub_check_breakdown": [
                {
                    "step_id": "hackerman-all",
                    "label": "make hackerman-all",
                    "critical": True,
                    "verdict": "PASS" if overall_status == "PASS" else "FAIL",
                    "returncode": 0 if overall_status == "PASS" else 1,
                    "duration_s": 600.0,
                    "reason": "",
                },
            ],
            "steps": [],
        }
        path.write_text(json.dumps(payload, indent=2))

    def test_cache_found_pass_via_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            cache = tmp_path / ".auditooor" / "cache" / "pre_merge_result.json"
            self._write_cache(cache, "PASS")
            verdict = READINESS.check_criterion_5_hackerman_pre_merge(
                tmp_path,
                run_pre_merge=False,
                use_pre_merge_cache=Path(".auditooor/cache/pre_merge_result.json"),
            )
        self.assertEqual(verdict["status"], "PASS")
        self.assertIn("cache=", verdict["detail"])
        self.assertIn("verdict=PASS", verdict["detail"])
        # Evidence ref should point to the cache file we created.
        self.assertTrue(verdict["evidence_ref"].endswith("pre_merge_result.json"))

    def test_cache_found_fail_via_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            cache = tmp_path / ".auditooor" / "cache" / "pre_merge_result.json"
            self._write_cache(cache, "FAIL")
            verdict = READINESS.check_criterion_5_hackerman_pre_merge(
                tmp_path,
                run_pre_merge=False,
                use_pre_merge_cache=Path(".auditooor/cache/pre_merge_result.json"),
            )
        self.assertEqual(verdict["status"], "FAIL")
        self.assertIn("verdict='FAIL'", verdict["detail"])

    def test_cache_missing_graceful_skip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # No cache file written.  Also patch the /tmp/ scan to ensure
            # the legacy fallback returns no candidates regardless of the
            # host /tmp/ state (CI-friendly).
            with mock.patch.object(
                READINESS, "_find_latest_pre_merge_cache", return_value=None
            ):
                verdict = READINESS.check_criterion_5_hackerman_pre_merge(
                    tmp_path,
                    run_pre_merge=False,
                    use_pre_merge_cache=Path(
                        ".auditooor/cache/pre_merge_result.json"
                    ),
                )
        self.assertEqual(verdict["status"], "SKIPPED")
        self.assertIn("hackerman-pre-merge-cached", verdict["detail"])
        self.assertIn("--run-pre-merge", verdict["detail"])

    def test_cache_and_run_flag_prefers_run(self) -> None:
        """When both a cache exists AND --run-pre-merge is set, the live
        invocation path wins.  We assert by patching the live runner."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            cache = tmp_path / ".auditooor" / "cache" / "pre_merge_result.json"
            # Cache says PASS; the live runner stub will say FAIL.  If we
            # honour the run flag we should see FAIL (i.e. cache is
            # ignored).
            self._write_cache(cache, "PASS")

            sentinel = {
                "name": READINESS.CRITERION_NAMES[4],
                "status": "FAIL",
                "detail": "stub live runner FAIL sentinel",
                "evidence_ref": "make hackerman-pre-merge",
            }
            with mock.patch.object(
                READINESS, "_run_pre_merge_inline", return_value=sentinel
            ) as run_mock:
                verdict = READINESS.check_criterion_5_hackerman_pre_merge(
                    tmp_path,
                    run_pre_merge=True,
                    use_pre_merge_cache=Path(
                        ".auditooor/cache/pre_merge_result.json"
                    ),
                )
            run_mock.assert_called_once()
        self.assertEqual(verdict, sentinel)


class TestCriterion5VerdictKeyNormalisation(unittest.TestCase):
    """Cache reader must accept any of overall_status / overall_verdict /
    verdict / overall as the verdict field name (back-compat with older
    pre-merge JSON envelopes that wrote the verdict under different keys).
    """

    def test_overall_status_preferred(self) -> None:
        # Payload has both overall_status and overall; we should use
        # overall_status verbatim (priority order in PRE_MERGE_VERDICT_KEYS).
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            cache = tmp_path / "cache.json"
            cache.write_text(
                json.dumps(
                    {
                        "synthetic_fixture": True,
                        "overall_status": "PASS",
                        "overall": "FAIL",
                    }
                )
            )
            verdict = READINESS.check_criterion_5_hackerman_pre_merge(
                tmp_path,
                run_pre_merge=False,
                use_pre_merge_cache=cache,
            )
        self.assertEqual(verdict["status"], "PASS")

    def test_legacy_overall_field_accepted(self) -> None:
        # Legacy payload with only `overall` should still be readable.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            cache = tmp_path / "legacy.json"
            cache.write_text(
                json.dumps(
                    {
                        "synthetic_fixture": True,
                        "overall": "PASS",
                    }
                )
            )
            verdict = READINESS.check_criterion_5_hackerman_pre_merge(
                tmp_path,
                run_pre_merge=False,
                use_pre_merge_cache=cache,
            )
        self.assertEqual(verdict["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
