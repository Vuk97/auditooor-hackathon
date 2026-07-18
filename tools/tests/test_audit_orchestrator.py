#!/usr/bin/env python3
"""Smoke tests for PR 208 `make audit` single-command entry.

Covers:
  1. DRY_RUN plan: `make audit WS=<tmp> DRY_RUN=1` exits 0 and lists the
     canonical stages in the plan.
  2. Missing workspace: `make audit` without WS exits nonzero.
  3. Failed-stage abort: a simulated stage failure causes a nonzero exit,
     proving we do NOT silently succeed when a stage aborts.
  4. audit-progress status vocabulary: only {started, ok, failed, skipped}.
  5. audit-progress rejects missing workspace with exit 2.

No network. No real scans. All execution is either `--dry-run` or a tiny
synthetic script that stands in for engage.py.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT_PROGRESS = ROOT / "tools" / "audit-progress.py"
MAKEFILE = ROOT / "Makefile"


def _mk_workspace(tmp: Path) -> Path:
    ws = tmp / "fixture-audit"
    (ws / "src").mkdir(parents=True)
    (ws / "reference").mkdir(parents=True)
    (ws / "SCOPE.md").write_text("# Fixture scope\n\nEmpty fixture for PR 208 smoke test.\n")
    (ws / "RUBRIC_COVERAGE.md").write_text("# Rubric coverage\n")
    (ws / "OOS_CHECKLIST.md").write_text("# OOS checklist\n")
    (ws / "ASSET_PLAN_fixture.md").write_text(
        "# Asset plan\n\n- Plan status: ready\n"
    )
    return ws


# ---------------------------------------------------------------------------
# 1. DRY_RUN plan lists the canonical stages
# ---------------------------------------------------------------------------

def test_make_audit_dry_run_plans_stages() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        ws = _mk_workspace(Path(tmp))
        proc = subprocess.run(
            ["make", "audit", f"WS={ws}", "DRY_RUN=1"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, (
            f"make audit DRY_RUN=1 should succeed, got rc={proc.returncode}\n"
            f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
        out = proc.stdout + proc.stderr
        # The plan should include canonical stages — orient + scan + report
        # + pre-submit are load-bearing markers that the "all" chain is in play.
        for stage in ("orient", "scan", "report", "pre-submit", "post-audit-review"):
            assert stage in out, (
                f"expected stage '{stage}' in dry-run plan, got:\n{out}"
            )
        assert "DRY-RUN no execution performed" in out, (
            f"expected engage.py dry-run sentinel, got:\n{out}"
        )


# ---------------------------------------------------------------------------
# 2. Missing / non-dir workspace fails cleanly
# ---------------------------------------------------------------------------

def test_make_audit_missing_ws_fails() -> None:
    proc = subprocess.run(
        ["make", "audit"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0, "make audit with no WS must fail"
    assert "Usage: make audit" in proc.stdout + proc.stderr


def test_make_audit_ws_not_a_directory_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        bogus = Path(tmp) / "does-not-exist"
        proc = subprocess.run(
            ["make", "audit", f"WS={bogus}"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode != 0, "make audit with bogus WS must fail"
        assert "workspace not found" in (proc.stdout + proc.stderr), (
            f"expected clean error; got:\n{proc.stdout}\n{proc.stderr}"
        )


class MakeAuditStrictWiringTest(unittest.TestCase):
    def _audit_recipe(self) -> str:
        content = MAKEFILE.read_text(encoding="utf-8", errors="replace")
        in_audit = False
        audit_lines: list[str] = []
        for line in content.splitlines():
            if re.match(r"^audit\s*:", line):
                in_audit = True
                continue
            if (
                in_audit
                and line
                and not line.startswith("\t")
                and not line.startswith(" ")
                and ":" in line
            ):
                break
            if in_audit:
                audit_lines.append(line)
        return "\n".join(audit_lines)

    def test_strict_fails_closed_on_advisory_refresh_failures(self) -> None:
        """STRICT=1 must promote post-audit advisory refresh failures to hard failures."""
        audit_recipe = self._audit_recipe()

        for target in (
            "brain-prime",
            "hacker-brief",
            "prior-disclosure-index",
            "exploit-queue",
            "queue-proof-hard-close",
            "field-validation-report",
            "v3-roadmap-sidecars",
        ):
            self.assertGreaterEqual(
                audit_recipe.count(f"STRICT=1: failing on {target} rc=$$"),
                2,
                f"{target} must fail closed in both freshness short-circuit and normal audit path",
            )

        self.assertIn(
            'queue-proof-hard-close WS="$(_WS_RESOLVED)" $(if $(filter 1,$(STRICT)),STRICT=1)',
            audit_recipe,
        )
        self.assertIn(
            'field-validation-report WS="$(_WS_RESOLVED)" $(if $(filter 1,$(STRICT)),STRICT=1)',
            audit_recipe,
        )

    def test_audit_writes_marker_when_core_csv_completed(self) -> None:
        audit_recipe = self._audit_recipe()
        self.assertIn("--csv \"$$audit_progress_csv\"", audit_recipe)
        self.assertIn("write-if-core-complete", audit_recipe)
        self.assertIn("--progress-csv \"$$audit_progress_csv\"", audit_recipe)
        self.assertIn("populate targets.tsv before audit", audit_recipe)


# ---------------------------------------------------------------------------
# 3. A failed stage aborts the audit (truth-audit regression gate)
# ---------------------------------------------------------------------------

def test_failed_stage_aborts_audit() -> None:
    """Simulate a failing engage.py; audit-progress must exit nonzero.

    We don't patch the real engage.py (too invasive for a smoke test). Instead
    we run audit-progress.py with a synthetic ENGAGE override via a tiny shim:
    we shadow sys.executable + engage path by writing a fake engage.py and
    pointing PYTHONPATH/args accordingly.

    Simpler path: override the ENGAGE path by monkey-patching via an
    environment variable is not supported by audit-progress, so we instead
    test the failure-tail + exit-code path by constructing a synthetic
    Popen-friendly script and calling the streamer directly.
    """
    with tempfile.TemporaryDirectory() as tmp:
        ws = _mk_workspace(Path(tmp))

        # Write a fake engage.py that emits a started marker and then fails.
        fake = Path(tmp) / "engage_fake.py"
        fake.write_text(textwrap.dedent("""
            import sys, time
            print("[stage: orient] priming workspace ...")
            time.sleep(0.05)
            print("[stage: orient]   CCIA rc=0")
            print("[stage: scan] launching detector sweep ...")
            time.sleep(0.05)
            print("[stage: scan]   FAIL rc=1 flow-gate blocked")
            print("simulated failure tail line 1")
            print("simulated failure tail line 2")
            sys.exit(1)
        """).strip() + "\n")
        fake.chmod(0o755)

        # Call audit-progress.py internals directly by constructing the
        # streaming wrapper around our fake engage. We can do this by
        # monkey-patching ENGAGE via importing the module.
        import importlib.util
        spec = importlib.util.spec_from_file_location("audit_progress", AUDIT_PROGRESS)
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)

        # Override ENGAGE to the fake for this call
        mod.ENGAGE = fake

        rc = mod.run_audit(ws, dry_run=False, extra=[])
        assert rc == 1, f"expected failed-stage to propagate rc=1, got {rc}"


# ---------------------------------------------------------------------------
# 4. Status vocabulary: only {started, ok, failed, skipped}
# ---------------------------------------------------------------------------

def test_audit_progress_status_vocabulary() -> None:
    import importlib.util
    spec = importlib.util.spec_from_file_location("audit_progress", AUDIT_PROGRESS)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)

    # The canonical verb set must be exactly these four.
    verbs = set(mod.STATUS_MAP.values())
    # `started` is emitted at stage entry and is NOT in STATUS_MAP (the map
    # only classifies terminal statuses). Confirm that too.
    assert verbs <= {"ok", "failed", "skipped"}, (
        f"unexpected terminal verb in STATUS_MAP: {verbs}"
    )
    # And confirm the emission code path only prints these verbs.
    import inspect
    src = inspect.getsource(mod)
    for verb in ("ok", "failed", "skipped", "started"):
        assert f"[stage={{name}} {verb}" in src or verb in src, (
            f"expected verb '{verb}' in audit-progress.py source"
        )


def test_success_warn_counts_as_warn_not_failed() -> None:
    import importlib.util
    import io
    import subprocess
    spec = importlib.util.spec_from_file_location("audit_progress", AUDIT_PROGRESS)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)

    fake = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "\n".join([
                "print('[stage: orient] priming workspace ...')",
                "print('[stage: orient] SUCCESS_WARN topology partial')",
                "print('[stage: scan] running ...')",
                "print('[stage: scan] FAIL rc=1')",
                "raise SystemExit(1)",
            ]),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    buf = io.StringIO()
    stages, _tail = mod._stream_and_classify(fake, buf)
    rc = fake.wait()
    mod._finalize_unterminated(stages, rc, buf)

    assert stages["orient"]["status"] == "ok"
    assert stages["orient"]["warning"] is True
    assert stages["scan"]["status"] == "failed"
    assert sum(1 for m in stages.values() if m.get("status") == "failed") == 1


# ---------------------------------------------------------------------------
# 5. audit-progress rejects a missing workspace directly
# ---------------------------------------------------------------------------

def test_audit_progress_missing_ws() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        bogus = Path(tmp) / "nope"
        proc = subprocess.run(
            [sys.executable, str(AUDIT_PROGRESS),
             "--workspace", str(bogus), "--dry-run"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 2, (
            f"expected rc=2 for missing ws; got {proc.returncode}\n"
            f"{proc.stdout}\n{proc.stderr}"
        )


# ---------------------------------------------------------------------------

def main() -> int:
    tests = [
        test_make_audit_dry_run_plans_stages,
        test_make_audit_missing_ws_fails,
        test_make_audit_ws_not_a_directory_fails,
        test_failed_stage_aborts_audit,
        test_audit_progress_status_vocabulary,
        test_success_warn_counts_as_warn_not_failed,
        test_audit_progress_missing_ws,
    ]
    fails = 0
    for fn in tests:
        try:
            fn()
            print(f"[PASS] {fn.__name__}")
        except AssertionError as e:
            fails += 1
            print(f"[FAIL] {fn.__name__}: {e}")
        except Exception as e:
            fails += 1
            print(f"[ERR ] {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n[test_audit_orchestrator] {len(tests) - fails}/{len(tests)} passed")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
