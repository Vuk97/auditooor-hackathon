"""test_dispatch_poc_build_env_injection.py - sibling test for the dispatch-time
"FORGE BUILD ENV - ALREADY SET UP, REUSE IT" block injected into the
Harness-Authoring Requirements section of
tools/dispatch-agent-with-prebriefing.py.

Motivation (NUVA 2026-06-30): two separately dispatched agents (a Chimera harness
author + a PoC verifier) EACH spent ~10 steps re-deriving the identical forge build
env - where foundry.toml lives, whether node_modules is present, that forge-std is
missing, the @openzeppelin remapping - all ALREADY solved on disk by audit-deep /
forge-deps-checker. The fix surfaces that context up front via
tools/poc-harness-bootstrap.py::brief_block, injected right under Section 0
("surface what is already built") of the harness brief.

Cases:
  1. when a forge-buildable repo + a reusable forge-std harness exist in the ws, a
     harness-authoring brief CONTAINS the build-env block (with the donor harness
     dir + the bootstrap one-liner).
  2. the block is injected directly UNDER the Section-0 header (reuse-first ordering).
  3. no workspace_path -> _poc_build_env_block degrades to [] (no crash, no block).
  4. a ws with no foundry.toml / no reusable harness -> empty block (nothing to reuse).
  5. a NON-harness lane never carries the block (the whole section is gated off).
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "dispatch-agent-with-prebriefing.py"

BLOCK_HEADER = "FORGE BUILD ENV - ALREADY SET UP, REUSE IT"
SECTION0 = "### 0. BEFORE YOU WRITE A LINE - surface what is already built"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "dispatch_agent_with_prebriefing", TOOL_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load module at {TOOL_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["dispatch_agent_with_prebriefing"] = mod
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod


prebriefing = _load_module()


def _make_ws_with_build_env() -> pathlib.Path:
    """A ws holding a forge-buildable repo (src/<repo>/foundry.toml + node_modules)
    and a reusable harness dir with lib/forge-std + foundry.toml + remappings."""
    ws = pathlib.Path(tempfile.mkdtemp(prefix="poc_buildenv_"))
    repo = ws / "src" / "demo-evm-contracts"
    (repo / "contracts").mkdir(parents=True)
    (repo / "node_modules").mkdir()
    (repo / "foundry.toml").write_text("[profile.default]\nsrc='contracts'\n")
    harness = ws / "poc-tests" / "Demo-engine-harness"
    (harness / "lib" / "forge-std" / "src").mkdir(parents=True)
    (harness / "foundry.toml").write_text("[profile.default]\n")
    (harness / "remappings.txt").write_text("forge-std/=lib/forge-std/src/\n")
    return ws


def _render_section(*, lane_type: str, prompt_text: str, workspace_path):
    return prebriefing._format_harness_authoring_requirements_section(
        lane_type=lane_type, prompt_text=prompt_text, workspace_path=workspace_path
    )


class PocBuildEnvInjectionTest(unittest.TestCase):
    def test_case1_block_present_for_harness_lane_with_build_env(self):
        ws = _make_ws_with_build_env()
        section = "\n".join(
            _render_section(
                lane_type="harness",
                prompt_text="author the chimera invariant harness",
                workspace_path=ws,
            )
        )
        self.assertIn(BLOCK_HEADER, section)
        # donor harness dir surfaced
        self.assertIn("Demo-engine-harness", section)
        # the bootstrap one-liner is present so the agent reuses it
        self.assertIn("poc-harness-bootstrap.py", section)

    def test_case2_block_injected_under_section0(self):
        ws = _make_ws_with_build_env()
        lines = _render_section(
            lane_type="invariant",
            prompt_text="build the suite",
            workspace_path=ws,
        )
        self.assertIn(SECTION0, lines)
        self.assertIn(BLOCK_HEADER, "\n".join(lines))
        idx0 = lines.index(SECTION0)
        idx_block = next(i for i, ln in enumerate(lines) if BLOCK_HEADER in ln)
        # block sits immediately under Section 0 (reuse-first), before later sections
        self.assertGreater(idx_block, idx0)
        self.assertLess(idx_block - idx0, 4)

    def test_case3_no_workspace_degrades_to_empty(self):
        self.assertEqual(prebriefing._poc_build_env_block(None), [])
        # and the harness section still renders fine without a ws
        section = _render_section(
            lane_type="harness", prompt_text="build it", workspace_path=None
        )
        self.assertTrue(section)
        self.assertNotIn(BLOCK_HEADER, "\n".join(section))

    def test_case4_ws_without_build_env_no_block(self):
        empty = pathlib.Path(tempfile.mkdtemp(prefix="poc_nobuild_"))
        self.assertEqual(prebriefing._poc_build_env_block(empty), [])
        section = _render_section(
            lane_type="harness", prompt_text="build it", workspace_path=empty
        )
        self.assertNotIn(BLOCK_HEADER, "\n".join(section))

    def test_case6_forge_log_truncation_footgun_present(self):
        # NUVA 2026-06-30: a verify lane nearly doubted its own R82 recovery proof
        # because forge truncated the recovery console.logs. The harness brief must
        # warn that a PASS means all asserts ran and Logs: is not an execution signal.
        section = "\n".join(
            _render_section(
                lane_type="harness",
                prompt_text="author the invariant suite",
                workspace_path=None,
            )
        )
        self.assertIn("TRUNCATES the `Logs:` block", section)
        self.assertIn("does NOT mean that branch did not execute", section)
        self.assertIn("-vvv", section)

    def test_case5_non_harness_lane_never_carries_block(self):
        ws = _make_ws_with_build_env()
        section = _render_section(
            lane_type="triage",
            prompt_text="summarize the rubric",
            workspace_path=ws,
        )
        # non-harness lane -> whole section is gated off, so no block either
        self.assertEqual(section, [])


if __name__ == "__main__":
    unittest.main()
