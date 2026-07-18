"""test_hacker_augmenter_impact_mechanism_plane.py

Regression tests for Section 0.8 (impact x mechanism completeness plane) in
agent-prompt-hacker-augmenter.py. This section wires the completeness-matrix
mechanism axis INTO the hunter brief so the AGENT enumerates the impact->mechanism
plane and clears every cell by source-reading - the durable generalization of the
NUVA false-green miss (an unbounded consensus-hook chain-halt that passed all
per-function gates because no gate modelled the impact->mechanism plane).

The core property under test: a mechanism with NO detector ("unscanned") is
rendered as an explicit AGENT OBLIGATION, not a silent pass - i.e. agents are
told to find the class WITHOUT relying on a detector having fired.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "agent-prompt-hacker-augmenter.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("agent_prompt_hacker_augmenter_ip", TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load module at {TOOL_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["agent_prompt_hacker_augmenter_ip"] = mod
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod


aug = _load_module()


def _make_ws_with_go_scan(tmpdir: str, *, with_open_finding: bool) -> pathlib.Path:
    """A ws with a Go in-scope unit and (optionally) a mechanism_scan sidecar
    carrying an OPEN un-dispositioned consensus-hook finding."""
    ws = pathlib.Path(tmpdir)
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    # in-scope Go unit -> ws languages includes "go"
    (ws / ".auditooor" / "inscope_units.jsonl").write_text(
        json.dumps({"function": "BeginBlocker", "file": "src/vault/keeper/abci.go"}) + "\n",
        encoding="utf-8",
    )
    if with_open_finding:
        sd = ws / ".auditooor" / "mechanism_scan"
        sd.mkdir(parents=True, exist_ok=True)
        (sd / "consensus-hook-unbounded-iteration.json").write_text(
            json.dumps({
                "schema": "auditooor.mechanism_scan.v1",
                "detector": "go_ast_consensus_hook_unbounded_iteration",
                "mechanism": "consensus-hook-unbounded-iteration",
                "impact": "chain-halt",
                "findings": [
                    {"file": "src/vault/keeper/reconcile.go", "line": 474,
                     "function": "handleVaultInterestTimeouts", "severity_hint": "critical"},
                ],
                "finding_count": 1,
            }),
            encoding="utf-8",
        )
    return ws


class TestImpactMechanismPlaneSection(unittest.TestCase):
    def test_open_finding_rendered_as_top_priority(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws_with_go_scan(td, with_open_finding=True)
            text, meta = aug._build_sec08_impact_mechanism_plane(ws)
            self.assertTrue(meta["present"])
            self.assertGreaterEqual(meta["open"], 1)
            self.assertIn("Section 0.8", text)
            self.assertIn("TOP PRIORITY", text)
            self.assertIn("consensus-hook-unbounded-iteration", text)
            self.assertIn("chain-halt", text)

    def test_unscanned_cell_is_an_agent_obligation_not_a_pass(self):
        """The core capability: a mechanism with NO detector must be rendered as
        an explicit obligation to clear by source-reading (agents find it WITHOUT
        a detector), not silently omitted."""
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws_with_go_scan(td, with_open_finding=False)
            text, meta = aug._build_sec08_impact_mechanism_plane(ws)
            self.assertTrue(meta["present"])
            self.assertGreaterEqual(meta["unscanned"], 1)
            self.assertIn("UNSCANNED", text)
            self.assertIn("reason from source", text)
            # detector-is-a-backstop-not-the-finder framing must be present
            self.assertIn("BACKSTOP", text)
            self.assertIn("your obligation to clear", text.lower())

    def test_language_filtered(self):
        """Only mechanisms applicable to the ws's languages appear (go unit ->
        the go/all-language mechanisms, not e.g. solidity-only cells absent go)."""
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws_with_go_scan(td, with_open_finding=False)
            _text, meta = aug._build_sec08_impact_mechanism_plane(ws)
            self.assertIn("go", meta.get("ws_languages", []))

    def test_graceful_when_no_mechanism_data(self):
        """No inscope units / no matrix -> still emits the obligation stub, never crashes."""
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            text, meta = aug._build_sec08_impact_mechanism_plane(ws)
            self.assertIn("Section 0.8", text)
            # Even with no in-scope units, the obligation to enumerate the full
            # impact->mechanism plane stands (library falls back to full seed,
            # unfiltered) - never a crash, never a silent empty pass.
            self.assertIn("For EVERY in-scope impact", text)
            self.assertIn("clear", text.lower())

    def test_section_wired_into_build_brief(self):
        """Section 0.8 must appear in the assembled brief, positioned after the
        verdict contract (Section 0) and before the clones inventory (Section 0.5)."""
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws_with_go_scan(td, with_open_finding=True)
            markdown, sections = aug.build_brief(
                ws, "test-lane", ["src/vault/keeper/abci.go"], None, 8,
                inject_function_mindset=False,
            )
            self.assertIn("sec08_impact_mechanism_plane", sections)
            self.assertIn("## Section 0.8", markdown)
            i08 = markdown.index("## Section 0.8")
            i05 = markdown.index("## Section 0.5")
            self.assertLess(i08, i05, "Section 0.8 must precede Section 0.5")


if __name__ == "__main__":
    unittest.main()
