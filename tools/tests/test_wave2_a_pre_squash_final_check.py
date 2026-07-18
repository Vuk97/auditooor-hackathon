"""Unit tests for tools/wave2-a-pre-squash-final-check.py.

All fixtures are synthetic (marked ``synthetic_fixture: true`` in the
mock sub-check outputs we feed through ``_run_sub_check``).  We patch
``subprocess.run`` to return canned JSON envelopes for each sub-check so
the tests run offline + deterministically with no dependency on the
live corpus or the actual sub-check tools.
"""
from __future__ import annotations

import importlib.util
import io
import json
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL_PATH = ROOT / "tools" / "wave2-a-pre-squash-final-check.py"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(
        "wave2_a_pre_squash_final_check", TOOL_PATH
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Each canned envelope is keyed by sub-check name.  We attach
# ``synthetic_fixture: true`` to make provenance obvious.
def _all_pass_envelopes() -> dict:
    return {
        "wave2-a-close-readiness": {
            "schema": "auditooor.wave2_a_close_readiness.v1",
            "overall_status": "READY_TO_MERGE",
            "synthetic_fixture": True,
        },
        "wave2-w21-post-migration-validator": {
            "schema": "auditooor.wave2_w21_post_migration_validator.v1",
            "overall_status": "PASS",
            "synthetic_fixture": True,
        },
        "wave2-w25-tier3-promotion-verify": {
            "schema": "auditooor.wave2_w25_tier3_promotion_verify.v1",
            "overall_status": "PASS",
            "synthetic_fixture": True,
        },
        "wave2-w26-cosmos-dedup-verify": {
            "schema": "auditooor.wave2_w26_cosmos_dedup_verify.v1",
            "overall_status": "PASS",
            "synthetic_fixture": True,
        },
        "wave2-a-pre-merge-preflight": {
            "schema": "auditooor.wave2_a_pre_merge_preflight.v1",
            "overall_status": "READY",
            "synthetic_fixture": True,
        },
        "wave2-index-dual-form-audit": {
            "schema": "auditooor.wave2_index_dual_form_audit.v1",
            "overall_status": "PASS",
            "synthetic_fixture": True,
        },
        "wave2-rule-37-emit-time-tier-audit": {
            "schema": "auditooor.wave2_rule_37_emit_time_tier_audit.v1",
            "overall_status": "PASS",
            "synthetic_fixture": True,
        },
        "wave2-cve-ghsa-verification-sweep": {
            "schema": "auditooor.wave2_cve_ghsa_verification_sweep.v1",
            "overall_status": "PASS",
            "synthetic_fixture": True,
        },
    }


class _FakeCompleted:
    def __init__(self, stdout: str, returncode: int = 0, stderr: str = ""):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _make_subprocess_fake(envelopes_by_script_substring: dict):
    """Return a fake subprocess.run that dispatches by script-path substring.

    ``envelopes_by_script_substring`` is a dict of ``substring -> envelope_or_None``.
    If the value is ``None`` the fake simulates a tool that emitted empty
    stdout (parse error).  If the value is a dict, it is json.dumps'd.
    If the value is a string, it is returned verbatim.
    """

    def _fake(cmd, capture_output=True, text=True, timeout=None, **kwargs):
        # cmd[1] is the script path when invoked as
        # [python, tools/foo.py, --workspace, ..., --json]
        script_path = cmd[1] if len(cmd) > 1 else ""
        matched = None
        for substring, env in envelopes_by_script_substring.items():
            if substring in script_path:
                matched = env
                break
        if matched is None:
            return _FakeCompleted(
                stdout="",
                returncode=2,
                stderr="no fixture configured",
            )
        if isinstance(matched, dict):
            return _FakeCompleted(stdout=json.dumps(matched), returncode=0)
        if isinstance(matched, str):
            return _FakeCompleted(stdout=matched, returncode=0)
        # explicit None -> simulate empty stdout (parse error path)
        return _FakeCompleted(stdout="", returncode=0)

    return _fake


class PreSquashFinalCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_module()
        # Patch Path.exists for script files so the fake subprocess path is taken.
        self._exists_patcher = mock.patch.object(
            Path, "exists", autospec=True, return_value=True
        )
        self._exists_patcher.start()

    def tearDown(self) -> None:
        self._exists_patcher.stop()

    # --- Case 1: all-PASS synthetic fixtures ---
    def test_case_1_all_pass_yields_ready_to_squash_merge(self):
        envs = _all_pass_envelopes()
        fake = _make_subprocess_fake(
            {f"tools/{n}.py": e for n, e in envs.items()}
        )
        with mock.patch.object(self.mod.subprocess, "run", side_effect=fake):
            env = self.mod.run(
                workspace=Path("/tmp/synthetic_ws"),
                strict=False,
                parallel=False,
            )
        self.assertEqual(env["composite_status"], "READY_TO_SQUASH_MERGE")
        self.assertEqual(env["pass_count"], 8)
        self.assertEqual(env["fail_count"], 0)
        self.assertEqual(env["warning_count"], 0)
        self.assertEqual(env["error_count"], 0)
        self.assertEqual(env["documented_acceptable_warnings"], [])
        self.assertEqual(env["blocking_findings"], [])

    # --- Case 2: documented-acceptable WARNINGs only -> DEGRADED or READY ---
    def test_case_2_degraded_when_multiple_acceptable_warnings(self):
        envs = _all_pass_envelopes()
        envs["wave2-rule-37-emit-time-tier-audit"] = {
            "schema": "auditooor.wave2_rule_37_emit_time_tier_audit.v1",
            "overall_status": "FAIL",
            "synthetic_fixture": True,
            "summary": "1649 dsl_pattern_* records exempt",
        }
        envs["wave2-index-dual-form-audit"] = {
            "schema": "auditooor.wave2_index_dual_form_audit.v1",
            "overall_status": "WARNING",
            "synthetic_fixture": True,
            "summary": "6258 dual-form records",
        }
        fake = _make_subprocess_fake(
            {f"tools/{n}.py": e for n, e in envs.items()}
        )
        with mock.patch.object(self.mod.subprocess, "run", side_effect=fake):
            env = self.mod.run(
                workspace=Path("/tmp/synthetic_ws"),
                strict=False,
                parallel=False,
            )
        # Both non-PASS results match the documented-acceptable list.
        self.assertEqual(
            env["composite_status"],
            "DEGRADED",
            f"got {env['composite_status']!r}, "
            f"acceptable={len(env['documented_acceptable_warnings'])}, "
            f"blocking={len(env['blocking_findings'])}",
        )
        self.assertEqual(len(env["documented_acceptable_warnings"]), 2)
        self.assertEqual(env["blocking_findings"], [])
        # The doc commit SHA must be referenced for every acceptable entry.
        for entry in env["documented_acceptable_warnings"]:
            self.assertEqual(
                entry["doc_commit_sha"],
                self.mod.WAVE3_FOLLOWUP_DOC_COMMIT,
            )
            self.assertTrue(entry["doc_commit_sha"].startswith("69cebeb750"))

    # --- Case 3: post-migration validator FAIL -> BLOCKED ---
    def test_case_3_post_migration_fail_is_blocking(self):
        envs = _all_pass_envelopes()
        envs["wave2-w21-post-migration-validator"] = {
            "schema": "auditooor.wave2_w21_post_migration_validator.v1",
            "overall_status": "FAIL",
            "synthetic_fixture": True,
            "summary": "v1 residual records: 12",
        }
        fake = _make_subprocess_fake(
            {f"tools/{n}.py": e for n, e in envs.items()}
        )
        with mock.patch.object(self.mod.subprocess, "run", side_effect=fake):
            env = self.mod.run(
                workspace=Path("/tmp/synthetic_ws"),
                strict=False,
                parallel=False,
            )
        self.assertEqual(env["composite_status"], "BLOCKED")
        self.assertEqual(env["fail_count"], 1)
        self.assertEqual(len(env["blocking_findings"]), 1)
        self.assertEqual(
            env["blocking_findings"][0]["tool"],
            "wave2-w21-post-migration-validator",
        )

    # --- Case 4: pre-merge preflight BLOCKED is documented-acceptable; combine with another FAIL to confirm correct classification ---
    def test_case_4_pre_merge_preflight_blocked_is_acceptable(self):
        envs = _all_pass_envelopes()
        envs["wave2-a-pre-merge-preflight"] = {
            "schema": "auditooor.wave2_a_pre_merge_preflight.v1",
            "overall_status": "BLOCKED",
            "synthetic_fixture": True,
            "summary": "stale PR#726 fixture refs",
        }
        # Also inject a *genuine* blocker so we can see that
        # the preflight BLOCKED is filtered into acceptable while the
        # genuine blocker remains in blocking_findings.
        envs["wave2-w26-cosmos-dedup-verify"] = {
            "schema": "auditooor.wave2_w26_cosmos_dedup_verify.v1",
            "overall_status": "FAIL",
            "synthetic_fixture": True,
            "summary": "ASA-2024-0012 verdict-artefact missing",
        }
        fake = _make_subprocess_fake(
            {f"tools/{n}.py": e for n, e in envs.items()}
        )
        with mock.patch.object(self.mod.subprocess, "run", side_effect=fake):
            env = self.mod.run(
                workspace=Path("/tmp/synthetic_ws"),
                strict=False,
                parallel=False,
            )
        # composite is BLOCKED because of w26 FAIL.
        self.assertEqual(env["composite_status"], "BLOCKED")
        # pre-merge-preflight BLOCKED routed to acceptable warnings.
        acceptable_tools = {
            e["tool"] for e in env["documented_acceptable_warnings"]
        }
        self.assertIn("wave2-a-pre-merge-preflight", acceptable_tools)
        # w26 FAIL routed to blocking.
        blocking_tools = {e["tool"] for e in env["blocking_findings"]}
        self.assertIn("wave2-w26-cosmos-dedup-verify", blocking_tools)

    # --- Case 5: exit-code mapping via main(...) integration ---
    def test_case_5_strict_exit_code_mapping(self):
        # First: BLOCKED + strict -> exit 1
        envs = _all_pass_envelopes()
        envs["wave2-w21-post-migration-validator"] = {
            "overall_status": "FAIL",
            "synthetic_fixture": True,
        }
        fake = _make_subprocess_fake(
            {f"tools/{n}.py": e for n, e in envs.items()}
        )
        with mock.patch.object(self.mod.subprocess, "run", side_effect=fake):
            with mock.patch.object(sys, "stdout", new_callable=io.StringIO):
                rc_blocked = self.mod.main(
                    [
                        "--workspace",
                        "/tmp/synthetic_ws",
                        "--json",
                        "--strict",
                        "--no-parallel",
                    ]
                )
        self.assertEqual(rc_blocked, 1)

        # Second: all-PASS + strict -> exit 0
        envs = _all_pass_envelopes()
        fake = _make_subprocess_fake(
            {f"tools/{n}.py": e for n, e in envs.items()}
        )
        with mock.patch.object(self.mod.subprocess, "run", side_effect=fake):
            with mock.patch.object(sys, "stdout", new_callable=io.StringIO):
                rc_ready = self.mod.main(
                    [
                        "--workspace",
                        "/tmp/synthetic_ws",
                        "--json",
                        "--strict",
                        "--no-parallel",
                    ]
                )
        self.assertEqual(rc_ready, 0)

        # Third: DEGRADED + strict -> exit 0 (DEGRADED is squash-acceptable).
        envs = _all_pass_envelopes()
        envs["wave2-rule-37-emit-time-tier-audit"] = {
            "overall_status": "FAIL",
            "synthetic_fixture": True,
            "summary": "1649 dsl_pattern_* records exempt",
        }
        envs["wave2-index-dual-form-audit"] = {
            "overall_status": "WARNING",
            "synthetic_fixture": True,
            "summary": "6258 dual-form records",
        }
        fake = _make_subprocess_fake(
            {f"tools/{n}.py": e for n, e in envs.items()}
        )
        with mock.patch.object(self.mod.subprocess, "run", side_effect=fake):
            with mock.patch.object(sys, "stdout", new_callable=io.StringIO):
                rc_degraded = self.mod.main(
                    [
                        "--workspace",
                        "/tmp/synthetic_ws",
                        "--json",
                        "--strict",
                        "--no-parallel",
                    ]
                )
        self.assertEqual(rc_degraded, 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
