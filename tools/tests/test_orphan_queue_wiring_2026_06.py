#!/usr/bin/env python3
# r36-rebuttal: lane orphan-queue-wiring-2026-06 registered in .auditooor/agent_pathspec.json
"""Tests for the 2026-06 orphan/dead-queue wiring (FIX 1-4).

FIX 1: economic-hypotheses producer wired into audit-deep Step 16 + its output
       injected into hunt/MIMO briefs (per-fn-mimo-batch-gen + dispatch 15t).
FIX 2: per-chain-blast-radius enumerator wired into audit-deep Step 17 (advisory,
       cross-chain summary) + surfaced into briefs when the unit is cross-chain.
FIX 3: proof-obligation-queue invoked inside audit-deep Step 18 (advisory).
FIX 4: detector-proof-gap-queue invoked inside audit-deep Step 19 (advisory).

The audit-deep checks use DRY_RUN to keep them fast and offline (stage presence
only); the brief-injection checks exercise the real loader/format helpers
against seeded silo artifacts.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
AUDIT_DEEP = REPO / "tools" / "audit-deep.sh"
PER_FN = REPO / "tools" / "per-fn-mimo-batch-gen.py"
DISPATCH = REPO / "tools" / "dispatch-agent-with-prebriefing.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class AuditDeepStagePresenceTests(unittest.TestCase):
    """FIX 1-4: the four new advisory stages render in the deep report."""

    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which("bash"):
            raise unittest.SkipTest("bash not on PATH")
        if not AUDIT_DEEP.is_file():
            raise unittest.SkipTest("audit-deep.sh not found")

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="orphan_wiring_ad_"))
        (self.tmp / "src").mkdir(parents=True)
        (self.tmp / "src" / "Vault.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
            "contract Vault {}\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_dry_run_renders_all_four_stages(self) -> None:
        env = os.environ.copy()
        env["AUDIT_DEEP_DRY_RUN"] = "1"
        proc = subprocess.run(
            ["bash", str(AUDIT_DEEP), str(self.tmp)],
            cwd=REPO, env=env, capture_output=True, text=True, timeout=180,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = self.tmp / ".audit_logs" / "audit_deep_report.md"
        self.assertTrue(report.is_file(), "deep report not written")
        text = report.read_text(encoding="utf-8")
        for header in (
            "Step 16 - Economic attack-hypothesis enumeration (FIX 1)",
            "Step 17 - Per-chain blast-radius enumeration (FIX 2)",
            "Step 18 - Proof-obligation queue (FIX 3)",
            "Step 19 - Detector proof/fixture-gap queue (FIX 4)",
        ):
            self.assertIn(header, text, f"missing stage header: {header}")


class EconomicHypothesesBriefInjectionTests(unittest.TestCase):
    """FIX 1: per-fn-mimo + dispatch surface the economic surface silo."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="orphan_wiring_econ_"))
        self.ws = self.tmp / "ws"
        (self.ws / "src").mkdir(parents=True)
        (self.ws / ".auditooor").mkdir(parents=True)
        # Seed the markdown the .sh would have produced.
        md_dir = self.ws / "src" / "economic_hypotheses"
        md_dir.mkdir(parents=True)
        md = md_dir / "Vault.md"
        md.write_text(
            "## Summary table\n\n"
            "| # | Category | Hits | Key signal |\n"
            "|---|---|---|---|\n"
            "| 1 | Oracle calls | 3 | staleness guards: 0 |\n"
            "| 2 | Flashloan callbacks | 0 | - |\n"
            "| 3 | Rate/reward computations | 2 | - |\n\n"
            "## 1. Oracle calls (3 hit(s))\n",
            encoding="utf-8",
        )
        (self.ws / ".auditooor" / "economic_hypotheses.json").write_text(
            json.dumps({
                "schema": "auditooor.economic_hypotheses.v1",
                "per_file": [{
                    "file": str(self.ws / "src" / "Vault.sol"),
                    "markdown": str(md),
                    "markdown_written": True,
                }],
            }),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_per_fn_loader_and_block(self) -> None:
        mod = _load("_per_fn", PER_FN)
        idx = mod.load_economic_hypotheses_indexed(self.ws)
        self.assertIn("vault", idx, "economic surface not indexed by stem")
        block = mod.build_economic_hypotheses_block(
            str(self.ws / "src" / "Vault.sol"), idx
        )
        self.assertIn("ECONOMIC ATTACK SURFACE", block)
        self.assertIn("Oracle calls", block)
        # Zero-hit categories are filtered out.
        self.assertNotIn("Flashloan callbacks", block)

    def test_dispatch_context_and_section(self) -> None:
        mod = _load("_dispatch_econ", DISPATCH)
        ctx = mod.build_deep_analysis_silos_context(
            workspace_path=self.ws, lane_type="hunt"
        )
        self.assertIsNotNone(ctx)
        self.assertTrue(ctx.get("economic_present"))
        lines = mod._format_deep_analysis_silos_section(ctx)
        joined = "\n".join(lines)
        self.assertIn("Economic attack surface", joined)
        self.assertIn("Oracle calls", joined)


class PerChainBlastRadiusBriefInjectionTests(unittest.TestCase):
    """FIX 2: dispatch surfaces the cross-chain blast-radius summary."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="orphan_wiring_pcb_"))
        self.ws = self.tmp / "ws"
        pcb_dir = self.ws / ".auditooor" / "per_chain_blast_radius"
        pcb_dir.mkdir(parents=True)
        (pcb_dir / "_workspace_summary.json").write_text(
            json.dumps({
                "schema_version": "auditooor.per_chain_blast_radius.v1",
                "scope": "workspace-summary",
                "is_cross_chain_target": True,
                "registration_anchor_count": 4,
                "blast_radius_count": 2,
                "registered_chains": [
                    {"name": "Optimism"}, {"name": "Arbitrum"}, {"name": "Base"},
                ],
            }),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_dispatch_context_and_section(self) -> None:
        mod = _load("_dispatch_pcb", DISPATCH)
        ctx = mod.build_deep_analysis_silos_context(
            workspace_path=self.ws, lane_type="hunt"
        )
        self.assertIsNotNone(ctx)
        self.assertTrue(ctx.get("per_chain_present"))
        lines = mod._format_deep_analysis_silos_section(ctx)
        joined = "\n".join(lines)
        self.assertIn("Cross-chain blast radius", joined)
        self.assertIn("Optimism", joined)

    def test_non_cross_chain_target_omitted(self) -> None:
        # A summary with is_cross_chain_target=False must not surface.
        (self.ws / ".auditooor" / "per_chain_blast_radius"
         / "_workspace_summary.json").write_text(
            json.dumps({"is_cross_chain_target": False}), encoding="utf-8"
        )
        mod = _load("_dispatch_pcb2", DISPATCH)
        ctx = mod.build_deep_analysis_silos_context(
            workspace_path=self.ws, lane_type="hunt"
        )
        # No other silo present -> None.
        self.assertIsNone(ctx)


class ProducerInvocabilityTests(unittest.TestCase):
    """FIX 3 + FIX 4: the queue producers run and write their artifacts."""

    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which("python3"):
            raise unittest.SkipTest("python3 not on PATH")

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="orphan_wiring_queue_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_proof_obligation_queue_runs(self) -> None:
        tool = REPO / "tools" / "proof-obligation-queue.py"
        if not tool.is_file():
            self.skipTest("proof-obligation-queue.py missing")
        out = self.tmp / "poq.json"
        proc = subprocess.run(
            ["python3", str(tool), "--workspace", str(self.tmp), "--out", str(out)],
            cwd=REPO, capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(out.is_file(), "proof-obligation queue not written")

    def test_detector_proof_gap_queue_runs(self) -> None:
        tool = REPO / "tools" / "detector-proof-gap-queue.py"
        if not tool.is_file():
            self.skipTest("detector-proof-gap-queue.py missing")
        out = self.tmp / "dpgq.json"
        md = self.tmp / "dpgq.md"
        proc = subprocess.run(
            ["python3", str(tool), "--repo-root", str(REPO),
             "--refresh-from-repo", "--json-out", str(out), "--md-out", str(md)],
            cwd=REPO, capture_output=True, text=True, timeout=300,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(out.is_file(), "detector proof-gap queue not written")


if __name__ == "__main__":
    unittest.main()
