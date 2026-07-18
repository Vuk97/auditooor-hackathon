"""Gap E — asset-coverage hard-gate tests for tools/intake-baseline.py.

Covers the four acceptance scenarios from
docs/ENGAGEMENT_3_AUDIT_DEPTH_ROADMAP.md L113-122:

  1. SC + BDL rubrics but only SC plan       → exit 2 (asset coverage blocker)
  2. Both assets planned                     → exit 0 + schema validates
  3. BDL + Rust roots, no scan-rust artifact → WARNING (deferred), exit 0
  4. Operator waiver present                 → exit 0 with waiver noted

Scenario 3 corrected (Axelar-DLT field run 2026-07-12): intake-baseline is
engage STAGE 1 while scan-rust is a LATER stage of the same `make audit`
pipeline. A hard exit-2 blocker here deadlocked every Rust-containing workspace
under --fail-fast (scan-rust could never run). The missing artifact is now a
deferred WARNING (consistent with all other not-yet-run scanners); enforcement
that scan-rust actually ran moves to the scan-rust stage where it belongs.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "intake-baseline.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("intake_baseline", TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _write_split_rubrics(ws: Path) -> None:
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
        "| C1 | Theft from smart contract escrow | 📋 NOT CHECKED | — |\n"
        "| C2 | Consensus safety failure | 📋 NOT CHECKED | — |\n"
    )


def _write_sc_plan(ws: Path) -> None:
    (ws / "ASSET_PLAN_Smart_Contract.md").write_text(
        "- Roots: src/contracts\n"
        "- Strategy: line-by-line review\n"
        "- Estimated hours: 30\n"
        "- Agent hour quota pct: 60\n"
        "- Plan status: ready\n"
    )


def _write_bdl_plan(ws: Path) -> None:
    (ws / "ASSET_PLAN_Blockchain_DLT.md").write_text(
        "- Roots: external/base\n"
        "- Strategy: scanner-informed Rust review\n"
        "- Estimated hours: 20\n"
        "- Agent hour quota pct: 40\n"
        "- Plan status: ready\n"
    )


def _write_rust_scan_artifact(ws: Path) -> None:
    out_dir = ws / "audit" / "rust-scan"
    out_dir.mkdir(parents=True)
    (out_dir / "summary.md").write_text("# rust-scan summary (synthetic)\n")
    (out_dir / "rust-scan.log").write_text("stub log\n")


def _run_cli(ws: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["python3", str(TOOL), str(ws), "--json"],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=15,
    )


class AssetCoverageGateTest(unittest.TestCase):
    def test_sc_and_bdl_rubrics_but_only_sc_plan_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_split_rubrics(ws)
            _write_sc_plan(ws)  # BDL plan deliberately missing

            result = _run_cli(ws)

            self.assertEqual(
                result.returncode, 2,
                f"expected exit 2, got {result.returncode}. stderr={result.stderr}"
            )
            payload = json.loads(result.stdout)
            blockers = payload["blockers"]
            self.assertTrue(
                any(b.startswith("asset coverage blocker:") and "Blockchain/DLT" in b
                    for b in blockers),
                f"missing BDL asset coverage blocker in: {blockers}"
            )

    def test_both_assets_planned_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_split_rubrics(ws)
            _write_sc_plan(ws)
            _write_bdl_plan(ws)
            # BDL plan is ready but no Rust roots present, so no scan-rust
            # evidence is required. Exit should be 0.
            result = _run_cli(ws)

            self.assertEqual(
                result.returncode, 0,
                f"expected exit 0, got {result.returncode}. stderr={result.stderr}"
            )
            payload = json.loads(result.stdout)
            self.assertEqual(
                payload["assets_in_scope"], ["Smart Contract", "Blockchain/DLT"]
            )
            plan = payload["asset_coverage_plan"]
            self.assertEqual(plan["Smart Contract"]["plan_status"], "ready")
            self.assertEqual(plan["Blockchain/DLT"]["plan_status"], "ready")
            self.assertEqual(plan["Smart Contract"]["estimated_hours"], 30)
            self.assertEqual(plan["Blockchain/DLT"]["agent_hour_quota_pct"], 40)

    def test_bdl_with_rust_roots_and_no_scan_artifact_warns_not_blocks(self):
        # Corrected behavior: scan-rust runs DOWNSTREAM in the same `make audit`
        # pipeline, so an absent artifact at intake-baseline (stage 1) is a
        # deferred WARNING, not a hard exit-2 blocker. A blocker here deadlocked
        # every Rust workspace under --fail-fast.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_split_rubrics(ws)
            _write_sc_plan(ws)
            _write_bdl_plan(ws)
            # Simulate Rust root by creating a Cargo.toml.
            (ws / "Cargo.toml").write_text('[package]\nname="stub"\nversion="0.1.0"\n')
            # No audit/rust-scan/summary.md and no waiver -> WARN (not block).

            result = _run_cli(ws)

            self.assertEqual(
                result.returncode, 0,
                f"expected exit 0 (deferred warn), got {result.returncode}. "
                f"stderr={result.stderr}"
            )
            payload = json.loads(result.stdout)
            blockers = payload["blockers"]
            self.assertFalse(
                any("scan-rust" in b for b in blockers),
                f"scan-rust must NOT be a hard blocker (deadlock); got: {blockers}"
            )
            self.assertTrue(
                any("scan-rust" in w and "Blockchain/DLT" in w
                    for w in payload.get("warnings", [])),
                f"expected a deferred scan-rust WARNING in: {payload.get('warnings')}"
            )

    def test_bdl_with_rust_roots_and_scan_artifact_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_split_rubrics(ws)
            _write_sc_plan(ws)
            _write_bdl_plan(ws)
            (ws / "Cargo.toml").write_text('[package]\nname="stub"\nversion="0.1.0"\n')
            _write_rust_scan_artifact(ws)

            result = _run_cli(ws)

            self.assertEqual(
                result.returncode, 0,
                f"expected exit 0, got {result.returncode}. stderr={result.stderr}"
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload["summary"]["rust_scan_artifact_present"])

    def test_operator_waiver_bypasses_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_split_rubrics(ws)
            _write_sc_plan(ws)
            _write_bdl_plan(ws)
            (ws / "Cargo.toml").write_text('[package]\nname="stub"\nversion="0.1.0"\n')
            # No scan-rust artifact, but operator writes an explicit waiver.
            (ws / "ASSET_WAIVER_Blockchain_DLT.md").write_text(
                "scan-rust waived: toolchain unavailable in CI.\n"
            )

            result = _run_cli(ws)

            self.assertEqual(
                result.returncode, 0,
                f"expected exit 0 with waiver, got {result.returncode}. "
                f"stderr={result.stderr}"
            )
            payload = json.loads(result.stdout)
            entry = payload["asset_coverage_plan"]["Blockchain/DLT"]
            self.assertIn("waiver", entry)
            # Warning should cite the waiver.
            self.assertTrue(
                any("waived" in w.lower() for w in payload.get("warnings", [])),
                f"expected waiver warning in: {payload.get('warnings')}"
            )

    def test_build_baseline_schema_fields(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_split_rubrics(ws)
            _write_sc_plan(ws)
            _write_bdl_plan(ws)
            payload = tool.build_baseline(ws)
        # schema: roots/strategy/estimated_hours/agent_hour_quota_pct/plan_status
        entry = payload["asset_coverage_plan"]["Smart Contract"]
        for field in ("roots", "strategy", "estimated_hours",
                      "agent_hour_quota_pct", "plan_status"):
            self.assertIn(field, entry, f"asset entry missing `{field}`")


if __name__ == "__main__":
    unittest.main()
