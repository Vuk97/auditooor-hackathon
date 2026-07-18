"""test_dispatch_prebriefing_reliability.py

Regression tests for the 2026-05-26 100% degradation bug:
spawn-worker.sh passed --lane-type tool-build (and other extended lane types)
which were not in the old argparse choices= list, causing argparse to exit
rc=2 before any stdout was written, leaving ENRICHED_FILE empty and triggering
status=failed-raw-fallback on every dispatch.

Root cause: _build_parser() had choices=list(VALID_LANE_TYPES) + [None]
which excluded spawn-worker.sh extended types: tool-build, wire-audit,
capability, infra.

Fix: removed choices= restriction; unknown types are downgraded to filing
inside build_enriched_prompt() via the lane_type_fallback_from path.
"""
from __future__ import annotations

import importlib.util
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "dispatch-agent-with-prebriefing.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("dispatch_agent_with_prebriefing", TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load module at {TOOL_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["dispatch_agent_with_prebriefing"] = mod
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod


dap = _load_module()

BEGIN_MARKER = "<!-- BEGIN dispatch-agent-with-prebriefing META-1 block -->"
END_MARKER = "<!-- END dispatch-agent-with-prebriefing META-1 block -->"
EXTENDED_LANE_TYPES = ["tool-build", "wire-audit", "capability", "infra"]
CANONICAL_LANE_TYPES = list(dap.VALID_LANE_TYPES)


def _noop_mcp(lane_type, severity, workspace_path, target_finding_class=""):
    return None


def _minimal_mcp(lane_type, severity, workspace_path, target_finding_class=""):
    return {
        "schema": "auditooor.vault_dispatch_brief_skeleton.v1",
        "context_pack_id": "test:abc123",
        "lane_specific_rules": [],
        "skeleton_sections": {},
        "rubric_excerpt": {},
        "originality_anchors": [],
        "recall_summary": "(test)",
        "busywork_refusals": [],
        "pre_submit_preview": [],
    }


def _noop_pillar(workspace_path, query_text="", target_finding_class="", now=None):
    return {
        "schema": "auditooor.dispatch_phase_a_pillar_context.v1",
        "p1": {"degraded": True, "reason": "test-noop"},
        "p3": {"degraded": True, "reason": "test-noop"},
        "p5": {"degraded": True, "reason": "test-noop"},
        "live_target_staleness": {"status": "not_checked", "warning": ""},
    }


class TestExtendedLaneTypesAccepted(unittest.TestCase):
    """Extended lane types from spawn-worker.sh must not cause argparse rc=2."""

    def test_extended_lane_types_do_not_raise(self):
        parser = dap._build_parser()
        for lt in EXTENDED_LANE_TYPES:
            with self.subTest(lane_type=lt):
                try:
                    args = parser.parse_args(["--prompt", "test", "--lane-type", lt])
                    self.assertEqual(args.lane_type, lt)
                except SystemExit as exc:
                    self.fail(
                        f"argparse raised SystemExit({exc.code}) for --lane-type {lt!r}. "
                        "2026-05-26 regression: choices= removed to allow extended types."
                    )

    def test_canonical_lane_types_still_accepted(self):
        parser = dap._build_parser()
        for lt in CANONICAL_LANE_TYPES:
            with self.subTest(lane_type=lt):
                try:
                    args = parser.parse_args(["--prompt", "test", "--lane-type", lt])
                    self.assertEqual(args.lane_type, lt)
                except SystemExit as exc:
                    self.fail(f"canonical type {lt!r} rejected: SystemExit({exc.code})")


class TestBeginEndMarkersPresent(unittest.TestCase):
    """BEGIN/END markers always present in enriched output."""

    def _enrich(self, lt, mcp=None):
        enriched, meta = dap.build_enriched_prompt(
            prompt_text="test prompt",
            lane_type=lt,
            severity="HIGH",
            workspace_path=None,
            infer_missing=False,
            mcp_caller=mcp or _noop_mcp,
            pillar_context_caller=_noop_pillar,
        )
        return enriched, meta

    def test_extended_lanes_have_both_markers(self):
        for lt in EXTENDED_LANE_TYPES:
            with self.subTest(lane_type=lt):
                enriched, _ = self._enrich(lt)
                self.assertIn(BEGIN_MARKER, enriched, f"BEGIN missing for {lt!r}")
                self.assertIn(END_MARKER, enriched, f"END missing for {lt!r}")

    def test_canonical_lanes_have_both_markers(self):
        for lt in CANONICAL_LANE_TYPES:
            with self.subTest(lane_type=lt):
                enriched, _ = self._enrich(lt, mcp=_minimal_mcp)
                self.assertIn(BEGIN_MARKER, enriched)
                self.assertIn(END_MARKER, enriched)


class TestUnknownLaneTypeDowngraded(unittest.TestCase):
    """Unknown lane type downgraded to filing; logged in meta."""

    def test_tool_build_downgraded(self):
        _, meta = dap.build_enriched_prompt(
            prompt_text="test", lane_type="tool-build", severity="HIGH",
            workspace_path=None, infer_missing=False,
            mcp_caller=_noop_mcp, pillar_context_caller=_noop_pillar,
        )
        self.assertEqual(meta["lane_type"], "filing")
        self.assertEqual(meta["inferred"].get("lane_type_fallback_from"), "tool-build")

    def test_wire_audit_downgraded(self):
        _, meta = dap.build_enriched_prompt(
            prompt_text="test", lane_type="wire-audit", severity="HIGH",
            workspace_path=None, infer_missing=False,
            mcp_caller=_noop_mcp, pillar_context_caller=_noop_pillar,
        )
        self.assertEqual(meta["lane_type"], "filing")
        self.assertEqual(meta["inferred"].get("lane_type_fallback_from"), "wire-audit")

    def test_canonical_not_downgraded(self):
        for lt in CANONICAL_LANE_TYPES:
            with self.subTest(lane_type=lt):
                _, meta = dap.build_enriched_prompt(
                    prompt_text="test", lane_type=lt, severity="HIGH",
                    workspace_path=None, infer_missing=False,
                    mcp_caller=_noop_mcp, pillar_context_caller=_noop_pillar,
                )
                self.assertEqual(meta["lane_type"], lt)
                self.assertNotIn("lane_type_fallback_from", meta["inferred"])


class TestSubprocessExitCode(unittest.TestCase):
    """Subprocess invocation must exit rc=0 and emit BEGIN marker."""

    def _run(self, lane_type):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False, encoding="utf-8") as f:
            f.write("test prompt for reliability regression")
            p = f.name
        try:
            return subprocess.run(
                [sys.executable, str(TOOL_PATH), "--prompt-file", p,
                 "--lane-type", lane_type, "--severity", "HIGH", "--no-infer"],
                capture_output=True, text=True, timeout=90,
                env={**os.environ, "AUDITOOOR_BRIEF_CLI_VALIDATOR_DISABLE": "1"},
            )
        finally:
            try: os.unlink(p)
            except OSError: pass

    def test_tool_build_rc0_with_begin_marker(self):
        """Core regression: --lane-type tool-build must no longer exit rc=2."""
        r = self._run("tool-build")
        self.assertEqual(r.returncode, 0,
            f"rc={r.returncode} for tool-build. stderr: {r.stderr[:400]}")
        self.assertIn(BEGIN_MARKER, r.stdout,
            "BEGIN marker missing for tool-build. 2026-05-26 regression.")

    def test_wire_audit_rc0(self):
        self.assertEqual(self._run("wire-audit").returncode, 0)

    def test_capability_rc0(self):
        self.assertEqual(self._run("capability").returncode, 0)

    def test_infra_rc0(self):
        self.assertEqual(self._run("infra").returncode, 0)

    def test_hunt_still_rc0(self):
        self.assertEqual(self._run("hunt").returncode, 0)

    def test_dispute_still_rc0(self):
        self.assertEqual(self._run("dispute").returncode, 0)


if __name__ == "__main__":
    unittest.main()
