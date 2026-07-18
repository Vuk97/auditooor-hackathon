import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = ROOT / "Makefile"
AUDIT_DEEP_MANIFEST = ROOT / "tools" / "audit-deep-manifest.py"


def _audit_run_full_body() -> str:
    text = MAKEFILE.read_text(encoding="utf-8")
    start = text.index("audit-run-full:")
    end = text.index("\ncvl-spec-risk-scan:", start)
    return text[start:end]


class AuditRunFullMakefileGateTest(unittest.TestCase):
    def test_audit_run_full_dry_run_hides_recursive_make_and_token_issue(self) -> None:
        text = MAKEFILE.read_text(encoding="utf-8")
        body = _audit_run_full_body()
        safe_make = "$${AUDIT_RUN_FULL_MAKE:-make} --no-print-directory"

        self.assertIn("_AUDIT_RUN_FULL_JUST_PRINT =", text)
        self.assertIn(
            "_AUDIT_RUN_FULL_RUN_ID := $(if $(_AUDIT_RUN_FULL_JUST_PRINT),auditrun-dry-run,",
            text,
        )
        self.assertIn("audit-run-full: export AUDIT_RUN_FULL_MAKE := $(MAKE)", body)
        self.assertIn(
            "audit-run-full: export ENFORCE_AUTONOMOUS_PROOF_CONVERSION := "
            "$(AUDIT_RUN_FULL_ENFORCE_AUTONOMOUS_PROOF_CONVERSION)",
            body,
        )
        self.assertIn(
            "audit-run-full: export AUDITOOOR_MCP_SESSION_TOKEN := "
            "$(if $(_AUDIT_RUN_FULL_JUST_PRINT),$(AUDITOOOR_MCP_SESSION_TOKEN),",
            body,
        )
        self.assertIn("tools/auditooor_mcp_token.py issue", body)
        self.assertNotIn("$(MAKE) --no-print-directory", body)
        self.assertEqual(body.count(safe_make), 13)
        for target in (
            "prior-disclosure-index",
            "hunt-full",
            "novel-chain-hunt",
            "corpus-driven-hunt",
            "coverage-to-hunt-seed",
            "exploit-queue-source-mine",
            "hunt-coverage-gate",
            "chain-synth",
            "exploit-conversion-loop",
            "prove-top-leads",
            "cvl-spec-risk-scan",
            "audit-complete",
            "production-pipeline-check",
        ):
            self.assertIn(f"{safe_make} {target}", body)

    def test_audit_run_full_proof_conversion_is_advisory_by_default(self) -> None:
        text = MAKEFILE.read_text(encoding="utf-8")
        body = _audit_run_full_body()

        self.assertIn("AUDIT_RUN_FULL_ENFORCE_AUTONOMOUS_PROOF_CONVERSION ?= 0", text)
        self.assertIn(
            "[AUDIT_RUN_FULL_ENFORCE_AUTONOMOUS_PROOF_CONVERSION=0|1]",
            body,
        )
        self.assertIn(
            '"enforce_autonomous_proof_conversion":"%s"',
            body,
        )
        self.assertIn(
            "proof conversion is advisory unless audit-run-full proof enforcement is set to 1",
            body,
        )

    def test_synthetic_dry_run_hides_fallback_recursive_make(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_dry_run_make_") as tmp:
            tmp_path = Path(tmp)
            makefile = tmp_path / "Makefile"
            marker = tmp_path / "marker.txt"
            makefile.write_text(
                """
THIS_MAKEFILE := $(abspath $(lastword $(MAKEFILE_LIST)))
ifeq ($(CHILD),1)
_ := $(shell printf 'child-submake\\n' >> "$(MARKER)")
endif

literal:
\t$(MAKE) --no-print-directory -f "$(THIS_MAKEFILE)" child CHILD=1 MARKER="$(MARKER)"

fallback:
\t$${AUDIT_RUN_FULL_MAKE:-make} --no-print-directory -f "$(THIS_MAKEFILE)" child CHILD=1 MARKER="$(MARKER)"

normal-fallback:
\tAUDIT_RUN_FULL_MAKE="$(MAKE)"; $${AUDIT_RUN_FULL_MAKE:-make} --no-print-directory -f "$(THIS_MAKEFILE)" child CHILD=1 MARKER="$(MARKER)"

child:
\t@:
""".lstrip(),
                encoding="utf-8",
            )

            literal = subprocess.run(
                [
                    "make",
                    "-n",
                    "--no-print-directory",
                    "-f",
                    str(makefile),
                    "literal",
                    f"MARKER={marker}",
                ],
                cwd=tmp_path,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(literal.returncode, 0, literal.stderr)
            self.assertEqual(marker.read_text(encoding="utf-8"), "child-submake\n")
            marker.unlink()

            fallback = subprocess.run(
                [
                    "make",
                    "-n",
                    "--no-print-directory",
                    "-f",
                    str(makefile),
                    "fallback",
                    f"MARKER={marker}",
                ],
                cwd=tmp_path,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(fallback.returncode, 0, fallback.stderr)
            self.assertFalse(marker.exists(), fallback.stdout)

            normal = subprocess.run(
                [
                    "make",
                    "--no-print-directory",
                    "-f",
                    str(makefile),
                    "normal-fallback",
                    f"MARKER={marker}",
                ],
                cwd=tmp_path,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(normal.returncode, 0, normal.stderr)
            self.assertEqual(marker.read_text(encoding="utf-8"), "child-submake\n")

    def test_completion_is_delegated_to_final_deep_freshness_gate(self) -> None:
        body = _audit_run_full_body()

        deep_stage = body.rindex('"event":"stage-start","stage":"deep-freshness"')
        final_check = body.index(
            'tools/audit-deep-manifest.py --workspace "$(_WS_RESOLVED)" '
            "--check-fresh --require-full-invariant-denominator "
            "--audit-run-manifest \"$$manifest\" "
            '--run-id "$(_AUDIT_RUN_FULL_RUN_ID)" '
            "--append-audit-run-success-events",
            deep_stage,
        )
        fail_row = body.index('"event":"stage-fail","stage":"deep-freshness"', final_check)
        exit_rc = body.index("exit $$rc", fail_row)
        echo_complete = body.index("[make audit-run-full] complete", final_check)

        self.assertNotIn('"event":"complete"', body)
        self.assertLess(deep_stage, final_check)
        self.assertLess(final_check, fail_row)
        self.assertLess(fail_row, exit_rc)
        self.assertLess(exit_rc, echo_complete)

    def test_hunt_coverage_failure_exits_before_downstream_stages(self) -> None:
        body = _audit_run_full_body()

        coverage_gate = body.index('hunt-coverage-gate WS="$(_WS_RESOLVED)" MIN_COVERAGE=1.0 STRICT=1')
        coverage_fail = body.index('"event":"stage-fail","run_id":"%s","stage":"hunt-coverage"', coverage_gate)
        coverage_exit = body.index("exit $$rc", coverage_fail)
        conversion_start = body.index('"stage":"exploit-conversion-loop"', coverage_exit)
        proof_start = body.index('"stage":"prove-top-leads"', coverage_exit)
        final_deep = body.index('"event":"stage-start","stage":"deep-freshness"', coverage_exit)

        self.assertLess(coverage_gate, coverage_fail)
        self.assertLess(coverage_fail, coverage_exit)
        self.assertLess(coverage_exit, conversion_start)
        self.assertLess(coverage_exit, proof_start)
        self.assertLess(coverage_exit, final_deep)

    def test_coverage_seed_and_source_scan_run_before_hunt_coverage_gate(self) -> None:
        body = _audit_run_full_body()

        seed_start = body.index('"stage":"coverage-to-hunt-seed"')
        seed_cmd = body.index(
            'coverage-to-hunt-seed WS="$(_WS_RESOLVED)" REBUILD_REPORT=1 '
            'RUN_ID="$(_AUDIT_RUN_FULL_RUN_ID)"',
            seed_start,
        )
        seed_pass = body.index('"event":"stage-pass","run_id":"%s","stage":"coverage-to-hunt-seed"', seed_cmd)
        scan_start = body.index('"stage":"coverage-source-scan"', seed_pass)
        scan_cmd = body.index(
            'exploit-queue-source-mine WS="$(_WS_RESOLVED)" TOP_N=0 '
            'INCLUDE_OPEN_UNHUNTED=1 REVIEW_ONLY=1 UPDATE_QUEUE=1 '
            'RUN_ID="$(_AUDIT_RUN_FULL_RUN_ID)"',
            scan_start,
        )
        scan_pass = body.index('"event":"stage-pass","run_id":"%s","stage":"coverage-source-scan"', scan_cmd)
        coverage_start = body.index('"stage":"hunt-coverage"', scan_pass)
        coverage_gate = body.index('hunt-coverage-gate WS="$(_WS_RESOLVED)" MIN_COVERAGE=1.0 STRICT=1', coverage_start)

        self.assertLess(seed_start, seed_cmd)
        self.assertLess(seed_cmd, seed_pass)
        self.assertLess(seed_pass, scan_start)
        self.assertLess(scan_start, scan_cmd)
        self.assertLess(scan_cmd, scan_pass)
        self.assertLess(scan_pass, coverage_start)
        self.assertLess(coverage_start, coverage_gate)

    def test_coverage_seed_failure_exits_before_hunt_coverage_gate(self) -> None:
        body = _audit_run_full_body()

        seed_cmd = body.index('coverage-to-hunt-seed WS="$(_WS_RESOLVED)" REBUILD_REPORT=1')
        seed_fail = body.index('"event":"stage-fail","run_id":"%s","stage":"coverage-to-hunt-seed"', seed_cmd)
        seed_exit = body.index("exit $$rc", seed_fail)
        scan_start = body.index('"stage":"coverage-source-scan"', seed_exit)
        coverage_start = body.index('"stage":"hunt-coverage"', seed_exit)

        self.assertLess(seed_cmd, seed_fail)
        self.assertLess(seed_fail, seed_exit)
        self.assertLess(seed_exit, scan_start)
        self.assertLess(seed_exit, coverage_start)

    def test_coverage_source_scan_failure_exits_before_hunt_coverage_gate(self) -> None:
        body = _audit_run_full_body()

        scan_cmd = body.index('exploit-queue-source-mine WS="$(_WS_RESOLVED)" TOP_N=0')
        scan_fail = body.index('"event":"stage-fail","run_id":"%s","stage":"coverage-source-scan"', scan_cmd)
        scan_exit = body.index("exit $$rc", scan_fail)
        coverage_start = body.index('"stage":"hunt-coverage"', scan_exit)

        self.assertLess(scan_cmd, scan_fail)
        self.assertLess(scan_fail, scan_exit)
        self.assertLess(scan_exit, coverage_start)

    def test_audit_run_full_serial_board_makefile_wrapper_is_wired(self) -> None:
        text = MAKEFILE.read_text(encoding="utf-8")
        target = text.index("\naudit-run-full-serial-board:")
        body_end = text.index("\ncvl-spec-risk-scan:", target)
        body = text[target:body_end]

        phony_line = next(
            line
            for line in text.splitlines()
            if line.startswith(".PHONY:") and "audit-run-full" in line
        )
        self.assertIn("audit-run-full-serial-board", phony_line)
        self.assertIn(
            "make audit-run-full-serial-board [WS=~/audits/<project>|AUDITS_ROOT=~/audits] [LIVE_STATUS=1] [JSON=1]",
            text,
        )
        self.assertIn("python3 tools/audit-run-full-serial-board.py", body)
        self.assertIn('--workspace "$(_WS_RESOLVED)"', body)
        self.assertIn('--audits-root "$(if $(AUDITS_ROOT),$(AUDITS_ROOT),$(HOME)/audits)"', body)
        self.assertIn("--include-no-manifest", body)
        self.assertIn("--live-status", body)
        self.assertIn('--limit "$(LIMIT)"', body)
        self.assertIn("--json", body)

    def test_post_coverage_chain_synth_runs_before_proof_conversion(self) -> None:
        body = _audit_run_full_body()

        coverage_pass = body.index('"event":"stage-pass","run_id":"%s","stage":"hunt-coverage"')
        post_chain_start = body.index('"stage":"post-coverage-chain-synth"', coverage_pass)
        stage_env = body.index("AUDITOOOR_AUDIT_RUN_FULL_STAGE=post-coverage-chain-synth", post_chain_start)
        post_chain_cmd = body.index('chain-synth WS="$(_WS_RESOLVED)"', stage_env)
        semantic_check = body.index("tools/chain-synth-report-check.py", post_chain_cmd)
        post_chain_pass = body.index(
            '"event":"stage-pass","run_id":"%s","stage":"post-coverage-chain-synth"',
            semantic_check,
        )
        conversion_start = body.index('"stage":"exploit-conversion-loop"', post_chain_pass)

        self.assertLess(coverage_pass, post_chain_start)
        self.assertLess(post_chain_start, stage_env)
        self.assertLess(stage_env, post_chain_cmd)
        self.assertLess(post_chain_cmd, semantic_check)
        self.assertLess(semantic_check, post_chain_pass)
        self.assertLess(post_chain_pass, conversion_start)

    def test_chain_synth_semantic_check_failure_exits_before_conversion(self) -> None:
        body = _audit_run_full_body()

        semantic_check = body.index("tools/chain-synth-report-check.py")
        fail_row = body.index(
            '"event":"stage-fail","run_id":"%s","stage":"post-coverage-chain-synth","step":"chain-synth-semantic-check"',
            semantic_check,
        )
        exit_rc = body.index("exit $$rc", fail_row)
        conversion_start = body.index('"stage":"exploit-conversion-loop"', exit_rc)

        self.assertLess(semantic_check, fail_row)
        self.assertLess(fail_row, exit_rc)
        self.assertLess(exit_rc, conversion_start)

    def test_hunt_coverage_receives_audit_run_id(self) -> None:
        body = _audit_run_full_body()

        export_env = body.index("audit-run-full: export AUDITOOOR_AUDIT_RUN_FULL_ID := $(_AUDIT_RUN_FULL_RUN_ID)")
        coverage_gate = body.index(
            'hunt-coverage-gate WS="$(_WS_RESOLVED)" MIN_COVERAGE=1.0 STRICT=1 '
            'RUN_ID="$(_AUDIT_RUN_FULL_RUN_ID)"',
            export_env,
        )
        coverage_fail = body.index('"event":"stage-fail","run_id":"%s","stage":"hunt-coverage"', coverage_gate)

        self.assertLess(export_env, coverage_gate)
        self.assertLess(coverage_gate, coverage_fail)

    def test_hunt_full_pass_requires_deep_freshness_provenance(self) -> None:
        body = _audit_run_full_body()

        hunt_cmd = body.index('hunt-full WS="$(_WS_RESOLVED)"')
        freshness_check = body.index(
            'tools/audit-deep-manifest.py --workspace "$(_WS_RESOLVED)" --check-fresh',
            hunt_cmd,
        )
        emit_provenance = body.index("--emit-provenance-stage-pass hunt-full", freshness_check)
        append_provenance = body.index('payload["provenance_stage_pass"]', emit_provenance)
        next_stage = body.index('"stage":"novel-chain-hunt"', append_provenance)

        self.assertIn('"stage":"hunt-full","step":"deep-freshness-after-hunt-full"', body)
        self.assertIn("HUNT_ORCHESTRATE_SKIP_AUDIT_STAGES=1", MAKEFILE.read_text(encoding="utf-8"))
        self.assertLess(hunt_cmd, freshness_check)
        self.assertLess(freshness_check, emit_provenance)
        self.assertLess(emit_provenance, append_provenance)
        self.assertLess(append_provenance, next_stage)

    def test_audit_run_full_mktemp_templates_end_with_placeholder(self) -> None:
        body = _audit_run_full_body()

        self.assertIn(
            'mktemp "$(_WS_RESOLVED)/.auditooor/hunt-full-deep-provenance.XXXXXX"',
            body,
        )
        self.assertNotIn("hunt-full-deep-provenance.XXXXXX.json", body)
        self.assertNotIn("deep-freshness-bounded", body)

    def test_deep_freshness_flag_tracks_tool_support(self) -> None:
        body = _audit_run_full_body()
        supports_full_invariant_denominator = (
            '--require-full-invariant-denominator' in AUDIT_DEEP_MANIFEST.read_text(encoding="utf-8")
        )
        check_fresh_calls = body.count("tools/audit-deep-manifest.py --workspace \"$(_WS_RESOLVED)\" --check-fresh")
        with_flag = body.count("--require-full-invariant-denominator")

        self.assertGreaterEqual(check_fresh_calls, 3)
        if supports_full_invariant_denominator:
            self.assertEqual(with_flag, check_fresh_calls)
        else:
            self.assertEqual(with_flag, 0)

    def test_executable_audit_run_full_refuses_stale_final_deep_manifest_after_status_stages(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_exec_gate_") as tmp:
            root = Path(tmp)
            ws = root / "workspace"
            bin_dir = root / "bin"
            ws.mkdir()
            bin_dir.mkdir()
            fake_make = bin_dir / "fake-make"
            fake_python = bin_dir / "python3"
            fake_make.write_text(
                """#!/usr/bin/env bash
set -euo pipefail
target=""
ws=""
for arg in "$@"; do
  case "$arg" in
    --*) ;;
    WS=*) ws="${arg#WS=}" ;;
    *) if [ -z "$target" ]; then target="$arg"; fi ;;
  esac
done
if [ -z "$ws" ]; then
  echo "missing WS" >&2
  exit 2
fi
mkdir -p "$ws/.audit_logs"
write_manifest() {
  rid="$1"
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  log="$ws/.audit_logs/audit_deep_all_default.log"
  report="$ws/.audit_logs/audit_deep_all_report.md"
  printf 'default profile completed\\n' > "$log"
  printf '# audit-deep all-profile report\\n' > "$report"
  cat > "$ws/.audit_logs/audit_deep_all_manifest.json" <<JSON
{"schema":"auditooor.audit_deep_all.v1","workspace":"$ws","run_id":"$rid","timestamp_utc":"$ts","dry_run":false,"expected_profiles":["default"],"profiles":[{"profile":"default","status":"success","exit_code":0,"log":"$log"}],"report":"$report"}
JSON
}
case "$target" in
  hunt-full)
    write_manifest "${AUDITOOOR_AUDIT_RUN_FULL_ID:-missing-run-id}"
    ;;
  production-pipeline-check)
    write_manifest "auditrun-prior-stale"
    ;;
esac
exit 0
""",
                encoding="utf-8",
            )
            fake_python.write_text(
                f"""#!/usr/bin/env bash
set -euo pipefail
real_py={sys.executable!r}
case "${{1:-}}" in
  tools/audit-deep-manifest.py|-c)
    exec "$real_py" "$@"
    ;;
  tools/auditooor_mcp_token.py|tools/audit-mcp-preflight.py|tools/intake-baseline.py|tools/chain-synth-report-check.py)
    exit 0
    ;;
  *)
    exec "$real_py" "$@"
    ;;
esac
""",
                encoding="utf-8",
            )
            fake_make.chmod(0o755)
            fake_python.chmod(0o755)

            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
            proc = subprocess.run(
                [
                    "make",
                    "--no-print-directory",
                    "audit-run-full",
                    f"WS={ws}",
                    f"AUDIT_RUN_FULL_MAKE={fake_make}",
                    "AUDIT_RUN_FULL_MIN_FREE_MB=0",
                    "REQUIRE_RECENT_RECALL=0",
                    "JSON=1",
                ],
                cwd=ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            manifest = ws / ".auditooor" / "audit_run_full_manifest.jsonl"
            rows = [
                json.loads(line)
                for line in manifest.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertNotIn("complete", {row.get("event") for row in rows})
            self.assertTrue(
                any(
                    row.get("event") == "stage-pass"
                    and row.get("stage") == "hunt-full"
                    for row in rows
                ),
                rows,
            )
            self.assertIn("audit-complete", {row.get("stage") for row in rows})
            self.assertIn("production-pipeline-check", {row.get("stage") for row in rows})
            self.assertTrue(
                any(
                    row.get("event") == "stage-fail"
                    and row.get("stage") == "deep-freshness"
                    for row in rows
                ),
                rows,
            )

    def test_stale_prior_deep_manifest_without_typed_skip_does_not_append_complete(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_gate_") as tmp:
            ws = Path(tmp) / "workspace"
            (ws / ".auditooor").mkdir(parents=True)
            (ws / ".audit_logs").mkdir(parents=True)
            manifest = ws / ".auditooor" / "audit_run_full_manifest.jsonl"
            rows = [
                {
                    "schema": "auditooor.audit_run_full_manifest.v1",
                    "event": "start",
                    "workspace": str(ws),
                    "run_id": "auditrun-current",
                    "timestamp_utc": "2026-05-30T10:00:00Z",
                },
                {
                    "schema": "auditooor.audit_run_full_manifest.v1",
                    "event": "stage-start",
                    "stage": "hunt-full",
                    "run_id": "auditrun-current",
                    "timestamp_utc": "2026-05-30T10:01:00Z",
                },
                {
                    "schema": "auditooor.audit_run_full_manifest.v1",
                    "event": "stage-pass",
                    "stage": "hunt-full",
                    "run_id": "auditrun-current",
                    "timestamp_utc": "2026-05-30T10:02:00Z",
                },
                {
                    "schema": "auditooor.audit_run_full_manifest.v1",
                    "event": "stage-start",
                    "stage": "deep-freshness",
                    "run_id": "auditrun-current",
                    "timestamp_utc": "2026-05-30T10:03:00Z",
                },
            ]
            manifest.write_text(
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
                encoding="utf-8",
            )
            (ws / ".audit_logs" / "audit_deep_all_manifest.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.audit_deep_all.v1",
                        "workspace": str(ws),
                        "run_id": "auditrun-prior",
                        "generated_at_utc": "2026-05-30T09:59:00Z",
                        "status": "success",
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(AUDIT_DEEP_MANIFEST),
                    "--workspace",
                    str(ws),
                    "--check-fresh",
                    "--audit-run-manifest",
                    str(manifest),
                    "--run-id",
                    "auditrun-current",
                    "--append-audit-run-success-events",
                    "--json",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 1, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["verdict"], "fail-stale-deep-manifest")
            written = [
                json.loads(line)
                for line in manifest.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual(written, rows)
            self.assertNotIn("complete", {row.get("event") for row in written})

    def test_fresh_deep_manifest_missing_run_id_does_not_append_complete(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit_run_full_gate_missing_run_id_") as tmp:
            ws = Path(tmp) / "workspace"
            (ws / ".auditooor").mkdir(parents=True)
            (ws / ".audit_logs").mkdir(parents=True)
            manifest = ws / ".auditooor" / "audit_run_full_manifest.jsonl"
            rows = [
                {
                    "schema": "auditooor.audit_run_full_manifest.v1",
                    "event": "start",
                    "workspace": str(ws),
                    "run_id": "auditrun-current",
                    "timestamp_utc": "2026-05-30T10:00:00Z",
                },
                {
                    "schema": "auditooor.audit_run_full_manifest.v1",
                    "event": "stage-start",
                    "stage": "hunt-full",
                    "run_id": "auditrun-current",
                    "timestamp_utc": "2026-05-30T10:01:00Z",
                },
                {
                    "schema": "auditooor.audit_run_full_manifest.v1",
                    "event": "stage-pass",
                    "stage": "hunt-full",
                    "run_id": "auditrun-current",
                    "timestamp_utc": "2026-05-30T10:02:00Z",
                },
                {
                    "schema": "auditooor.audit_run_full_manifest.v1",
                    "event": "stage-start",
                    "stage": "deep-freshness",
                    "run_id": "auditrun-current",
                    "timestamp_utc": "2026-05-30T10:03:00Z",
                },
            ]
            manifest.write_text(
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
                encoding="utf-8",
            )
            (ws / ".audit_logs" / "audit_deep_all_manifest.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.audit_deep_all.v1",
                        "workspace": str(ws),
                        "generated_at_utc": "2026-05-30T10:04:00Z",
                        "status": "success",
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(AUDIT_DEEP_MANIFEST),
                    "--workspace",
                    str(ws),
                    "--check-fresh",
                    "--audit-run-manifest",
                    str(manifest),
                    "--run-id",
                    "auditrun-current",
                    "--append-audit-run-success-events",
                    "--json",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 1, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["verdict"], "fail-stale-deep-manifest")
            written = [
                json.loads(line)
                for line in manifest.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual(written, rows)
            self.assertNotIn("complete", {row.get("event") for row in written})


if __name__ == "__main__":
    unittest.main()
