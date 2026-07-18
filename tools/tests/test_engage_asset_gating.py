"""Gap E — engage.py asset-coverage gating tests.

Verifies:
  - `engage --stage orient` blocks when INTAKE_BASELINE.json shows a missing
    asset plan (exit 2, no orient artifacts produced).
  - `engage --stage mine-prioritize` blocks for a BDL workspace that has
    Rust roots but no scan-rust artifact (exit 2).
  - `engage --stage scan-rust` + PR #115 runner contract: the runner is
    invoked at the workspace root (enabling multi-root discovery) and its
    SCAN_RUST_SUMMARY.md artifact is accepted by downstream gates.
"""
from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import tempfile
import types
import unittest
# r36-rebuttal: build lane (CAP-GAP-90 test contract update)
from pathlib import Path
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
ENGAGE = REPO / "tools" / "engage.py"


def _load_engage_module() -> types.ModuleType:
    # engage.py uses top-level `from submission_paths import ...` so the
    # tools/ directory must be on sys.path when we exec it here.
    import sys
    tools_dir = str(REPO / "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location("engage", ENGAGE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_intake_baseline(ws: Path, payload: dict) -> None:
    (ws / "INTAKE_BASELINE.json").write_text(json.dumps(payload, indent=2))


def _stage_row(output: str, stage: str) -> str:
    """Return the summary-table line matching a given stage name, or ''."""
    for line in output.splitlines():
        if line.strip().startswith("|") and f"| {stage} " in line:
            return line
    return ""


class EngageAssetGatingTest(unittest.TestCase):
    def test_orient_blocks_when_asset_plan_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_intake_baseline(ws, {
                "schema": "auditooor.intake-baseline.v1",
                "assets_in_scope": ["Smart Contract", "Blockchain/DLT"],
                "asset_coverage_plan": {
                    "Smart Contract": {
                        "roots": ["src/contracts"],
                        "strategy": "line-by-line",
                        "estimated_hours": 30,
                        "agent_hour_quota_pct": 60,
                        "plan_status": "ready",
                    },
                    "Blockchain/DLT": {
                        "roots": [],
                        "strategy": "",
                        "estimated_hours": 0,
                        "agent_hour_quota_pct": 0,
                        "plan_status": "missing",
                    },
                },
                "rust_roots": [],
                "summary": {"rust_scan_artifact_present": False},
            })

            result = subprocess.run(
                ["python3", str(ENGAGE), "--workspace", str(ws),
                 "--stage", "orient", "--summary", "--quiet"],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=60,
            )

            self.assertEqual(
                result.returncode, 2,
                f"expected exit 2, got {result.returncode}.\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
            combined = result.stdout + result.stderr
            self.assertIn("asset-coverage gate", combined)
            self.assertIn("Blockchain/DLT", combined)

    def test_mine_prioritize_blocks_when_scan_rust_missing_for_bdl(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            # Simulate a BDL workspace: Rust root + both plans ready +
            # no audit/rust-scan/summary.md + no waiver.
            (ws / "Cargo.toml").write_text('[package]\nname="x"\nversion="0.1.0"\n')
            _write_intake_baseline(ws, {
                "schema": "auditooor.intake-baseline.v1",
                "assets_in_scope": ["Smart Contract", "Blockchain/DLT"],
                "asset_coverage_plan": {
                    "Smart Contract": {
                        "roots": ["src/contracts"],
                        "strategy": "x",
                        "estimated_hours": 30,
                        "agent_hour_quota_pct": 60,
                        "plan_status": "ready",
                    },
                    "Blockchain/DLT": {
                        "roots": ["external/base"],
                        "strategy": "x",
                        "estimated_hours": 20,
                        "agent_hour_quota_pct": 40,
                        "plan_status": "ready",
                    },
                },
                "rust_roots": ["."],
                "summary": {"rust_scan_artifact_present": False},
            })

            result = subprocess.run(
                ["python3", str(ENGAGE), "--workspace", str(ws),
                 "--stage", "mine-prioritize", "--summary", "--quiet"],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=60,
            )

            self.assertEqual(
                result.returncode, 2,
                f"expected exit 2, got {result.returncode}.\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
            combined = result.stdout + result.stderr
            self.assertIn("scan-rust evidence", combined)


class ScanRustMultiRootRegressionTest(unittest.TestCase):
    """Regression for Codex review of PR #116.

    Asserts two contract properties at once:

      1. `stage_scan_rust` invokes PR #115's `rust-scan-runner.sh` at the
         **workspace root** (not narrowed to `rust_roots[0]`) so the runner
         can discover every Cargo.toml under the workspace.
      2. The artifact contract `scanners/rust/SCAN_RUST_SUMMARY.md` written
         by PR #115's default runner is accepted as scan-rust evidence by
         both `engage` and `intake-baseline` — unblocking the BDL asset
         gate without a waiver.
    """

    def test_scan_rust_multiroot_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            # Two sibling Rust roots; the workspace root has NO Cargo.toml,
            # so the pre-fix logic (narrowing to rust_roots[0]) would have
            # scanned only external/base, silently skipping external/mystic.
            (ws / "external" / "base").mkdir(parents=True)
            (ws / "external" / "mystic").mkdir(parents=True)
            (ws / "external" / "base" / "Cargo.toml").write_text(
                '[package]\nname="base"\nversion="0.1.0"\n'
            )
            (ws / "external" / "mystic" / "Cargo.toml").write_text(
                '[package]\nname="mystic"\nversion="0.1.0"\n'
            )

            # Fake PR #115-style runner: records the path it was invoked
            # with so the test can assert workspace-root invocation, then
            # writes SCAN_RUST_SUMMARY.{md,json} to the PR #115 default
            # location. Kept intentionally outside the workspace so the
            # intake-baseline scan in step (4) doesn't pick it up as a
            # tracked file.
            fake_runner = Path(tmp).parent / f"fake-rust-scan-runner-{ws.name}.sh"
            invocation_log = Path(tmp).parent / f"runner_invocation-{ws.name}.log"
            self.addCleanup(lambda p=fake_runner: p.unlink(missing_ok=True))
            self.addCleanup(lambda p=invocation_log: p.unlink(missing_ok=True))
            fake_runner.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                f'printf "%s\\n" "$1" > {invocation_log}\n'
                'out_dir="$1/scanners/rust"\n'
                'mkdir -p "$out_dir"\n'
                'printf "# SCAN_RUST_SUMMARY (PR #115 contract)\\n\\n'
                'Roots scanned: external/base, external/mystic\\n" '
                '> "$out_dir/SCAN_RUST_SUMMARY.md"\n'
                'printf "%s\\n" '
                '\'{"roots":["external/base","external/mystic"],"findings":[]}\' '
                '> "$out_dir/SCAN_RUST_SUMMARY.json"\n'
            )
            fake_runner.chmod(fake_runner.stat().st_mode | stat.S_IXUSR
                              | stat.S_IXGRP | stat.S_IXOTH)

            # Severity rubrics + asset plans so intake-baseline.py can
            # produce a valid baseline in step (4).
            (ws / "SEVERITY_SMART_CONTRACTS.md").write_text(
                "# Critical\n- Theft from smart contract escrow\n\n"
                "# High\n- Permanent smart contract freeze\n"
            )
            (ws / "SEVERITY_BLOCKCHAIN_DLT.md").write_text(
                "# Critical\n- Consensus safety failure\n\n"
                "# Medium\n- Sequencer liveness degradation\n"
            )
            (ws / "RUBRIC_COVERAGE.md").write_text(
                "# Rubric Coverage\n\n"
                "**Severity source files:**\n"
                "- `SEVERITY_SMART_CONTRACTS.md`\n"
                "- `SEVERITY_BLOCKCHAIN_DLT.md`\n\n"
                "| # | Example | Verdict | Evidence / Gap |\n"
                "|---|---|---|---|\n"
                "| C1 | Theft from smart contract escrow | \U0001F4CB NOT CHECKED | - |\n"
                "| C2 | Consensus safety failure | \U0001F4CB NOT CHECKED | - |\n"
            )
            (ws / "ASSET_PLAN_Smart_Contract.md").write_text(
                "- Roots: src/contracts\n"
                "- Strategy: line-by-line review\n"
                "- Estimated hours: 30\n"
                "- Agent hour quota pct: 60\n"
                "- Plan status: ready\n"
            )
            (ws / "ASSET_PLAN_Blockchain_DLT.md").write_text(
                "- Roots: external/base, external/mystic\n"
                "- Strategy: scanner-informed Rust review\n"
                "- Estimated hours: 20\n"
                "- Agent hour quota pct: 40\n"
                "- Plan status: ready\n"
            )

            # Minimal INTAKE_BASELINE.json: BDL + SC planned, TWO rust roots.
            # Only consumed by stage_scan_rust in step (1-3); step (4)
            # regenerates via the CLI subprocess and uses the plan files
            # above.
            _write_intake_baseline(ws, {
                "schema": "auditooor.intake-baseline.v1",
                "assets_in_scope": ["Smart Contract", "Blockchain/DLT"],
                "asset_coverage_plan": {
                    "Smart Contract": {
                        "roots": ["src/contracts"],
                        "strategy": "line-by-line",
                        "estimated_hours": 30,
                        "agent_hour_quota_pct": 60,
                        "plan_status": "ready",
                    },
                    "Blockchain/DLT": {
                        "roots": ["external/base", "external/mystic"],
                        "strategy": "scanner-informed Rust review",
                        "estimated_hours": 20,
                        "agent_hour_quota_pct": 40,
                        "plan_status": "ready",
                    },
                },
                "rust_roots": ["external/base", "external/mystic"],
                "summary": {"rust_scan_artifact_present": False},
            })

            # Run stage_scan_rust directly with RUST_SCAN_RUNNER pointed at
            # the fake runner so we don't touch tools/rust-scan-runner.sh
            # (PR #115's territory).
            engage = _load_engage_module()
            args = types.SimpleNamespace(quiet=True)
            with mock.patch.object(engage, "RUST_SCAN_RUNNER", fake_runner):
                status = engage.stage_scan_rust(ws, args)

            # (1) runner ran to success and artifact was detected.
            self.assertEqual(
                status, "SUCCESS",
                f"expected SUCCESS, got {status!r}. Runner log: "
                f"{invocation_log.read_text() if invocation_log.exists() else '<missing>'}"
            )

            # (2) runner was invoked at the WORKSPACE ROOT — not pre-narrowed
            #     to rust_roots[0]. This is the core regression assertion.
            self.assertTrue(invocation_log.exists(),
                            "fake runner was not invoked")
            invoked_with = invocation_log.read_text().strip()
            self.assertEqual(
                Path(invoked_with).resolve(), ws.resolve(),
                f"runner should be invoked at workspace root; got {invoked_with!r}"
            )

            # (3) PR #115's default artifact exists + is accepted as evidence.
            summary_md = ws / "scanners" / "rust" / "SCAN_RUST_SUMMARY.md"
            self.assertTrue(summary_md.is_file(),
                            "PR #115 SCAN_RUST_SUMMARY.md not written")
            self.assertTrue(engage._rust_scan_artifact_present(ws))

            # (4) intake-baseline's Rust scan detection now sees the PR #115
            #     artifact and no longer reports the BDL asset as blocked.
            result = subprocess.run(
                ["python3", str(REPO / "tools" / "intake-baseline.py"),
                 str(ws), "--json"],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(
                result.returncode, 0,
                "intake-baseline should accept SCAN_RUST_SUMMARY.md as "
                f"scan-rust evidence. stdout={result.stdout} "
                f"stderr={result.stderr}"
            )
            payload = json.loads(result.stdout)
            self.assertTrue(
                payload["summary"]["rust_scan_artifact_present"],
                "intake-baseline summary should reflect PR #115 artifact"
            )
            blockers = payload.get("blockers", [])
            self.assertFalse(
                any("scan-rust" in b and "Blockchain/DLT" in b for b in blockers),
                f"BDL asset should not be blocked after PR #115 scan; "
                f"blockers={blockers}"
            )


class StageOrderingRegressionTest(unittest.TestCase):
    """Regression for Codex review of PR #116 (round 2).

    The earlier ordering placed `scan-rust` AFTER `mine-prioritize`, but
    `mine-prioritize` gates on the scan-rust artifact via `_rust_gate_ok`.
    On a fresh BDL/Rust workspace running `engage --stage all`, the chain
    deadlocked at `mine-prioritize` and never reached `scan-rust`.

    Asserts:

      1. `STAGES` lists `scan-rust` BEFORE `mine-prioritize` (and before
         any later stage that gates on scan-rust evidence).
      2. The chain actually runs `scan-rust` before `mine-prioritize` on a
         fresh workspace — no scan-rust artifact preexists, so the gate
         would fire if `mine-prioritize` ran first.
    """

    def test_scan_rust_runs_before_mine_prioritize_on_fresh_workspace(self):
        # (1) Static assertion on the canonical STAGES tuple.
        engage = _load_engage_module()
        stages = list(engage.STAGES)
        self.assertIn("scan-rust", stages)
        self.assertIn("mine-prioritize", stages)
        self.assertLess(
            stages.index("scan-rust"), stages.index("mine-prioritize"),
            "scan-rust must precede mine-prioritize so the chain can "
            "produce the artifact mine-prioritize gates on. "
            f"Got order: {stages}"
        )
        # mine-briefs also gates on _rust_gate_ok, so scan-rust must
        # precede it too.
        if "mine-briefs" in stages:
            self.assertLess(
                stages.index("scan-rust"), stages.index("mine-briefs"),
                "scan-rust must precede mine-briefs (also rust-gated)."
            )

        # (2) Fresh BDL/Rust workspace dry-run: the chain plan must list
        #     scan-rust strictly before mine-prioritize.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "Cargo.toml").write_text(
                '[package]\nname="x"\nversion="0.1.0"\n'
            )
            _write_intake_baseline(ws, {
                "schema": "auditooor.intake-baseline.v1",
                "assets_in_scope": ["Smart Contract", "Blockchain/DLT"],
                "asset_coverage_plan": {
                    "Smart Contract": {
                        "roots": ["src/contracts"],
                        "strategy": "x",
                        "estimated_hours": 30,
                        "agent_hour_quota_pct": 60,
                        "plan_status": "ready",
                    },
                    "Blockchain/DLT": {
                        "roots": ["external/base"],
                        "strategy": "x",
                        "estimated_hours": 20,
                        "agent_hour_quota_pct": 40,
                        "plan_status": "ready",
                    },
                },
                "rust_roots": ["."],
                "summary": {"rust_scan_artifact_present": False},
            })

            result = subprocess.run(
                ["python3", str(ENGAGE), "--workspace", str(ws),
                 "--stage", "all", "--dry-run", "--summary", "--quiet"],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(
                result.returncode, 0,
                f"--dry-run should succeed. stdout={result.stdout} "
                f"stderr={result.stderr}"
            )
            combined = result.stdout + result.stderr
            sr_idx = combined.find("scan-rust")
            mp_idx = combined.find("mine-prioritize")
            self.assertGreater(sr_idx, -1,
                               "scan-rust must appear in dry-run plan")
            self.assertGreater(mp_idx, -1,
                               "mine-prioritize must appear in dry-run plan")
            self.assertLess(
                sr_idx, mp_idx,
                "scan-rust must be listed before mine-prioritize in "
                f"dry-run plan. Output:\n{combined}"
            )


class LegacyFallbackMultiRootRegressionTest(unittest.TestCase):
    """Regression for Codex PR #114 + PR #116 reviews.

    When only the legacy single-root `rust-scan.sh` is installed AND the
    workspace declares >1 Rust root, `stage_scan_rust` previously fell
    back to scanning `rust_roots[0]` only — recreating the blind-spot
    Gap E exists to prevent. The fix is to FAIL LOUDLY in that case so
    operators must either install `rust-scan-runner.sh` (PR #115) or add
    `ASSET_WAIVER_Blockchain_DLT.md`.
    """

    def test_legacy_fallback_multi_root_fails_loudly(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            # Two sibling Rust roots: legacy rust-scan.sh would silently
            # narrow to rust_roots[0] = external/base.
            (ws / "external" / "base").mkdir(parents=True)
            (ws / "external" / "mystic").mkdir(parents=True)
            (ws / "external" / "base" / "Cargo.toml").write_text(
                '[package]\nname="base"\nversion="0.1.0"\n'
            )
            (ws / "external" / "mystic" / "Cargo.toml").write_text(
                '[package]\nname="mystic"\nversion="0.1.0"\n'
            )
            _write_intake_baseline(ws, {
                "schema": "auditooor.intake-baseline.v1",
                "assets_in_scope": ["Smart Contract", "Blockchain/DLT"],
                "asset_coverage_plan": {
                    "Smart Contract": {
                        "roots": ["src/contracts"],
                        "strategy": "x",
                        "estimated_hours": 30,
                        "agent_hour_quota_pct": 60,
                        "plan_status": "ready",
                    },
                    "Blockchain/DLT": {
                        "roots": ["external/base", "external/mystic"],
                        "strategy": "x",
                        "estimated_hours": 20,
                        "agent_hour_quota_pct": 40,
                        "plan_status": "ready",
                    },
                },
                "rust_roots": ["external/base", "external/mystic"],
                "summary": {"rust_scan_artifact_present": False},
            })

            # Fake legacy fallback. Whether or not it would write any
            # artifact is irrelevant — the fix must reject *before*
            # invoking it on a multi-root workspace.
            fake_legacy = Path(tmp).parent / f"fake-legacy-rust-scan-{ws.name}.sh"
            invocation_log = Path(tmp).parent / f"legacy_invocation-{ws.name}.log"
            self.addCleanup(lambda p=fake_legacy: p.unlink(missing_ok=True))
            self.addCleanup(lambda p=invocation_log: p.unlink(missing_ok=True))
            fake_legacy.write_text(
                "#!/usr/bin/env bash\n"
                f'printf "%s\\n" "$1" > {invocation_log}\n'
                "exit 0\n"
            )
            fake_legacy.chmod(fake_legacy.stat().st_mode | stat.S_IXUSR
                              | stat.S_IXGRP | stat.S_IXOTH)

            # Point RUST_SCAN_RUNNER at a path that does NOT exist (so
            # the dedicated runner branch is skipped) and RUST_SCAN_FALLBACK
            # at the fake legacy script.
            engage = _load_engage_module()
            args = types.SimpleNamespace(quiet=True)
            missing_runner = Path(tmp).parent / f"definitely-not-here-{ws.name}.sh"
            with mock.patch.object(engage, "RUST_SCAN_RUNNER", missing_runner), \
                 mock.patch.object(engage, "RUST_SCAN_FALLBACK", fake_legacy):
                status = engage.stage_scan_rust(ws, args)

            # (1) status must start with FAIL — not SUCCESS_WARN, not
            #     SKIPPED.
            self.assertTrue(
                status.startswith("FAIL"),
                f"multi-root + legacy fallback must FAIL loudly; got {status!r}"
            )
            self.assertIn("multi-root", status)

            # (2) The legacy script MUST NOT have been invoked. The fix
            #     short-circuits before subprocess execution.
            self.assertFalse(
                invocation_log.exists(),
                "legacy rust-scan.sh must not be invoked on multi-root "
                "workspace; it would silently scan rust_roots[0] only"
            )

            # (3) No scan-rust artifact written → downstream gate stays
            #     blocked, as required.
            self.assertFalse(engage._rust_scan_artifact_present(ws))
            needs, reason = engage._bdl_asset_requires_rust_scan(ws)
            self.assertTrue(
                needs,
                f"BDL asset gate must remain blocked after fail-loudly. "
                f"reason={reason!r}"
            )


class EngagementRetroFreshWorkspaceTest(unittest.TestCase):
    """Regression for I-16 (PR #158).

    The Phase 45b ``engagement-retro`` stage previously hard-failed the
    terminal stage of the chain on every fresh engagement: the asset-
    coverage gate fires when no ``ASSET_WAIVER_<asset>.md`` is on disk
    AND no dispatch references the asset's roots, which is trivially
    true on a brand-new workspace where no dispatch has run yet. Per
    Issue I-16 in the 2026-04-25 session observations the gate must
    distinguish "fresh workspace, work not done yet" (warn) from
    "operator ran dispatches but selectively skipped this asset"
    (still fail).
    """

    def _baseline(self) -> dict:
        return {
            "schema": "auditooor.intake-baseline.v1",
            "assets_in_scope": ["Smart Contract"],
            "asset_coverage_plan": {
                "Smart Contract": {
                    "roots": ["src/contracts"],
                    "strategy": "line-by-line",
                    "estimated_hours": 30,
                    "agent_hour_quota_pct": 100,
                    "plan_status": "ready",
                },
            },
            "rust_roots": [],
            "summary": {"rust_scan_artifact_present": False},
        }

    def test_fresh_workspace_warns_not_fails(self):
        engage = _load_engage_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_intake_baseline(ws, self._baseline())
            verdict, errors = engage._asset_retro_gate(ws)
            self.assertEqual(
                verdict, "warn",
                f"fresh workspace (no agent_outputs/) must verdict 'warn', "
                f"got {verdict!r} errors={errors!r}",
            )
            self.assertTrue(errors, "warn verdict must still surface errors")
            args = types.SimpleNamespace(quiet=True)
            status = engage.stage_engagement_retro(ws, args)
            self.assertTrue(
                status.startswith("SUCCESS_WARN"),
                f"stage_engagement_retro should soften to SUCCESS_WARN on a "
                f"fresh workspace; got {status!r}",
            )
            self.assertIn("fresh-engagement", status)
            note = ws / "RETROSPECTIVE_ASSET_COVERAGE_BLOCKERS.md"
            self.assertTrue(
                note.is_file(),
                "warn breadcrumb must still be written so operator sees gap",
            )
            self.assertIn("fresh-engagement", note.read_text())

    def test_selective_skip_degrades_to_warn_by_default(self):
        """CAP-GAP-90 (2026-05-27): engagement-retro advisory by default.

        Pre-CAP-GAP-90 the selective-skip path returned FAIL and blocked
        `make audit` rc=0. The retro is a retrospective health check, not
        a precondition, so the default is now SUCCESS_WARN. Strict opt-in
        verified by ``test_selective_skip_strict_env_still_fails``.
        # r36-rebuttal: build lane (CAP-GAP-90 test contract update)
        """
        engage = _load_engage_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_intake_baseline(ws, self._baseline())
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            (audit_dir / "spawn_worker_events.jsonl").write_text(
                json.dumps({
                    "lane_id": "asset-audit-1",
                    "lane_type": "hunt",
                    "refused": False,
                }) + "\n"
            )
            agent_dir = ws / "agent_outputs"
            agent_dir.mkdir()
            (agent_dir / "dispatch_unrelated.md").write_text(
                "mentions src/other_module/X.sol\n"
            )
            verdict, errors = engage._asset_retro_gate(ws)
            self.assertEqual(
                verdict, "fail",
                f"selective skip must verdict 'fail' at gate level (the "
                f"degrade-permissive is applied by stage_engagement_retro "
                f"on top of gate verdict), got {verdict!r} errors={errors!r}",
            )
            args = types.SimpleNamespace(quiet=True)
            prior = os.environ.pop("AUDITOOOR_STRICT_ENGAGEMENT_RETRO", None)
            try:
                status = engage.stage_engagement_retro(ws, args)
            finally:
                if prior is not None:
                    os.environ["AUDITOOOR_STRICT_ENGAGEMENT_RETRO"] = prior
            self.assertTrue(
                status.startswith("SUCCESS_WARN"),
                f"stage_engagement_retro must degrade to SUCCESS_WARN on "
                f"selective skip by default (CAP-GAP-90); got {status!r}",
            )
            self.assertIn("advisory", status)

    def test_selective_skip_strict_env_still_fails(self):
        """CAP-GAP-90 STRICT opt-in: hard-fail when operator asks.

        # r36-rebuttal: build lane (CAP-GAP-90 test contract update)
        """
        engage = _load_engage_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_intake_baseline(ws, self._baseline())
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            (audit_dir / "spawn_worker_events.jsonl").write_text(
                json.dumps({
                    "lane_id": "asset-audit-1",
                    "lane_type": "hunt",
                    "refused": False,
                }) + "\n"
            )
            agent_dir = ws / "agent_outputs"
            agent_dir.mkdir()
            (agent_dir / "dispatch_unrelated.md").write_text(
                "mentions src/other_module/X.sol\n"
            )
            args = types.SimpleNamespace(quiet=True)
            prior = os.environ.get("AUDITOOOR_STRICT_ENGAGEMENT_RETRO")
            os.environ["AUDITOOOR_STRICT_ENGAGEMENT_RETRO"] = "1"
            try:
                status = engage.stage_engagement_retro(ws, args)
            finally:
                if prior is None:
                    os.environ.pop("AUDITOOOR_STRICT_ENGAGEMENT_RETRO", None)
                else:
                    os.environ["AUDITOOOR_STRICT_ENGAGEMENT_RETRO"] = prior
            self.assertTrue(
                status.startswith("FAIL"),
                f"stage_engagement_retro must FAIL on selective skip with "
                f"AUDITOOOR_STRICT_ENGAGEMENT_RETRO=1; got {status!r}",
            )

    def test_generated_dispatch_only_is_still_fresh_warn(self):
        engage = _load_engage_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_intake_baseline(ws, self._baseline())
            agent_dir = ws / "agent_outputs"
            agent_dir.mkdir()
            (agent_dir / "dispatch_generated.md").write_text(
                "generated first-run brief for src/other_module/X.sol\n"
            )
            verdict, errors = engage._asset_retro_gate(ws)
            self.assertEqual(
                verdict,
                "warn",
                f"generated dispatch briefs without worker activity must warn; "
                f"got {verdict!r} errors={errors!r}",
            )
            self.assertTrue(errors)

    def test_dispatch_covering_asset_passes(self):
        engage = _load_engage_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_intake_baseline(ws, self._baseline())
            agent_dir = ws / "agent_outputs"
            agent_dir.mkdir()
            (agent_dir / "dispatch_real.md").write_text(
                "finding in src/contracts/Vault.sol#L42\n"
            )
            verdict, errors = engage._asset_retro_gate(ws)
            self.assertEqual(
                verdict, "ok",
                f"dispatch covering asset roots must verdict 'ok', got "
                f"{verdict!r} errors={errors!r}",
            )
            self.assertEqual(errors, [])

    def test_dispatch_linked_brief_covering_asset_passes(self):
        engage = _load_engage_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_intake_baseline(ws, self._baseline())
            agent_dir = ws / "agent_outputs"
            agent_dir.mkdir()
            brief = agent_dir / "brief_20260429T000000Z_Vault.md"
            brief.write_text("Investigate src/contracts/Vault.sol\n")
            (agent_dir / "dispatch_real.md").write_text(
                f"=== READY FOR DISPATCH ===\n  Brief: {brief}\n"
            )
            verdict, errors = engage._asset_retro_gate(ws)
            self.assertEqual(
                verdict, "ok",
                f"dispatch wrapper linked to covering brief must verdict 'ok', got "
                f"{verdict!r} errors={errors!r}",
            )
            self.assertEqual(errors, [])

    def test_generated_brief_covering_asset_passes(self):
        engage = _load_engage_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_intake_baseline(ws, self._baseline())
            agent_dir = ws / "agent_outputs"
            agent_dir.mkdir()
            (agent_dir / "brief_20260429T000000Z_Vault.md").write_text(
                "- **Contract:** /tmp/ws/src/contracts/Vault.sol\n"
            )
            verdict, errors = engage._asset_retro_gate(ws)
            self.assertEqual(
                verdict,
                "ok",
                f"generated brief covering asset roots must verdict 'ok', got "
                f"{verdict!r} errors={errors!r}",
            )
            self.assertEqual(errors, [])


class MinePrioritizeTimeoutAdvisoryTest(unittest.TestCase):
    """mine-prioritize is a non-load-bearing CCIA ranking hint. A timeout/crash
    there must be ADVISORY (SUCCESS_WARN), not a hard FAIL that aborts the whole
    audit-deep under engage --fail-fast (G9: Step-1 ORIENT failures must not
    block the deep engines)."""

    def _args(self, engage):
        return types.SimpleNamespace(quiet=True)

    def test_timeout_is_success_warn_not_fail(self):
        engage = _load_engage_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "ccia_report.json").write_text("[]")  # so the stage is not SKIPPED
            with mock.patch.object(engage, "run", return_value=(124, "", "timed out")):
                status = engage.stage_mine_prioritize(ws, self._args(engage))
        self.assertTrue(status.startswith("SUCCESS_WARN"), status)
        self.assertNotIn("FAIL", status)

    def test_nonzero_crash_is_success_warn_not_fail(self):
        engage = _load_engage_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "ccia_report.json").write_text("[]")
            with mock.patch.object(engage, "run", return_value=(2, "", "boom")):
                status = engage.stage_mine_prioritize(ws, self._args(engage))
        self.assertTrue(status.startswith("SUCCESS_WARN"), status)


if __name__ == "__main__":
    unittest.main()
