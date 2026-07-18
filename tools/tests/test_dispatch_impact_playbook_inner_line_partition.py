#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the per-LINE foreign-ecosystem partition in
_render_one_impact_playbook (tools/dispatch-agent-with-prebriefing.py).

Adversarial-verify L6 bug: the playbook-level SELECT (contract-kind + language)
is correct, but a multi-ecosystem playbook (one that lists solidity AND go/rust)
rendered its inner body VERBATIM, so a Solidity ERC-4626 DeFi lane carried
foreign-ecosystem EXAMPLE lines (cosmos / cosmwasm / ibc / authz / fee-payer /
*Block / baseapp; FaultDisputeGame / DisputeGameFactory / cannon /
anchorstateregistry / op-stack / opfaultverifier) in its critical_paths /
attack_surface / hacker_questions / incident_anchors blocks. The fix DROPS those
inner example lines for a Solidity DeFi lane while keeping every Solidity line,
and is language-gated so a Go/cosmos lane is unaffected.

The module file is hyphenated, loaded via importlib with a sys.modules
registration BEFORE exec_module (Python 3.14 self-import safety), matching the
sibling dispatch tests.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "dispatch-agent-with-prebriefing.py"

# The four EXAMPLE-line block headers the per-line filter must clean. The
# severity_mapping / caveats blocks are intentionally OUT of scope (they hold
# sub-impact variant keys + over-claim guard prose, not example lines).
_TARGETED_BLOCK_HEADERS = (
    "Critical paths",
    "Attack surface",
    "hacker questions",
    "Incident anchors",
)


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


def _foreign_example_lines(section_lines):
    """Return the foreign-ecosystem bullet lines that appear inside the four
    targeted EXAMPLE blocks (critical_paths / attack_surface / hacker_questions /
    incident_anchors). A line counts only when it is a bullet ('- ...') under a
    targeted '#### ' sub-header AND contains a foreign-ecosystem token. This
    scopes the assertion to the blocks the fix targets, not severity_mapping or
    caveats prose.
    """
    toks = prebriefing._FOREIGN_ECOSYSTEM_LINE_TOKENS
    in_targeted = False
    out = []
    for line in section_lines:
        if line.startswith("#### "):
            in_targeted = any(h in line for h in _TARGETED_BLOCK_HEADERS)
            continue
        if (
            in_targeted
            and line.lstrip().startswith("-")
            and any(t in line.lower() for t in toks)
        ):
            out.append(line)
    return out


def _solidity_vault_ws() -> pathlib.Path:
    """A Solidity ERC-4626 DeFi vault ws WITH real .sol source on disk so the
    language scan resolves to 'solidity' and the contract-kind to 'vault'."""
    ws = pathlib.Path(tempfile.mkdtemp(prefix="innerline_vault_"))
    (ws / "SCOPE.md").write_text(
        "ERC4626 vault deposit withdraw redeem shares totalAssets "
        "convertToShares",
        encoding="utf-8",
    )
    src = ws / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "Vault.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Vault {\n"
        "  function withdraw(uint256 a) external {}\n"
        "  function deposit(uint256 a) external {}\n"
        "}\n",
        encoding="utf-8",
    )
    return ws


def _go_consensus_src_ws() -> pathlib.Path:
    """A Go/consensus ws WITH real .go source so the language scan resolves to
    'go' - the foreign-line filter must NOT fire (those lines are native here)."""
    ws = pathlib.Path(tempfile.mkdtemp(prefix="innerline_go_"))
    (ws / "SCOPE.md").write_text(
        "cosmos-sdk cometbft consensus module x/foo FinalizeBlock abci "
        "BeginBlock EndBlock baseapp",
        encoding="utf-8",
    )
    src = ws / "x"
    src.mkdir(parents=True, exist_ok=True)
    (src / "abci.go").write_text(
        "package foo\nfunc FinalizeBlock() error { return nil }\n",
        encoding="utf-8",
    )
    return ws


class ForeignLineHelper(unittest.TestCase):
    def test_token_set_covers_both_ecosystems(self):
        toks = {t.lower() for t in prebriefing._FOREIGN_ECOSYSTEM_LINE_TOKENS}
        for go_tok in ("cosmos", "cosmwasm", "ibc", "authz", "baseapp"):
            self.assertIn(go_tok, toks)
        for op_tok in (
            "faultdisputegame",
            "disputegamefactory",
            "cannon",
            "anchorstateregistry",
        ):
            self.assertIn(op_tok, toks)

    def test_line_is_foreign_detects_and_passes(self):
        self.assertTrue(
            prebriefing._line_is_foreign_ecosystem(
                "- attacker drains via BeginBlock hook on cosmos"
            )
        )
        self.assertTrue(
            prebriefing._line_is_foreign_ecosystem(
                "- FaultDisputeGame resolve race on op-stack"
            )
        )
        # A pure Solidity DeFi line is NOT foreign.
        self.assertFalse(
            prebriefing._line_is_foreign_ecosystem(
                "- withdraw() lets attacker drain vault shares"
            )
        )

    def test_solidity_defi_lane_gate(self):
        self.assertTrue(
            prebriefing._is_solidity_defi_lane("solidity", "vault")
        )
        self.assertTrue(
            prebriefing._is_solidity_defi_lane("solidity", "lending")
        )
        # Go ws never filters; unknown language never filters.
        self.assertFalse(prebriefing._is_solidity_defi_lane("go", "vault"))
        self.assertFalse(prebriefing._is_solidity_defi_lane("", "vault"))
        # GENERIC FIX (L5+L6 recurring root): the foreign-line drop is now gated
        # on LANGUAGE alone, NOT a finite contract_kind allowlist. A Solidity
        # target with ANY kind outside the historic DeFi set (consensus, oracle,
        # etc.) STILL filters - a Solidity contract is never a real Cosmos
        # consensus module, so if it gets mislabeled the foreign lines must still
        # be dropped. (Was assertFalse under the buggy allowlist gate.)
        self.assertTrue(
            prebriefing._is_solidity_defi_lane("solidity", "consensus")
        )
        self.assertTrue(
            prebriefing._is_solidity_defi_lane("solidity", "oracle")
        )


class InnerLinePartition(unittest.TestCase):
    def test_render_one_playbook_drops_foreign_lines_for_solidity_vault(self):
        # Pick a real corpus playbook that admits solidity AND has >=1 foreign
        # example line in a targeted block, then prove the gated render drops it
        # while the ungated render keeps it (mutation-kill witness).
        pbs = prebriefing.load_impact_playbooks()
        self.assertTrue(pbs, "corpus must load for this repo")
        toks = prebriefing._FOREIGN_ECOSYSTEM_LINE_TOKENS
        witness = None
        for pb in pbs:
            langs = [
                str(x).lower()
                for x in (pb.get("applies_to_languages") or [])
            ]
            if not langs or "solidity" not in langs:
                continue
            ungated = prebriefing._render_one_impact_playbook(pb)
            if _foreign_example_lines(ungated):
                witness = pb
                break
        self.assertIsNotNone(
            witness,
            "no multi-ecosystem solidity playbook with a foreign example line "
            "found - the corpus shape the bug depends on is gone",
        )
        # Ungated (old behavior) keeps >=1 foreign example line.
        ungated = prebriefing._render_one_impact_playbook(witness)
        self.assertTrue(_foreign_example_lines(ungated))
        # Gated for solidity/vault: 0 foreign example lines remain.
        gated = prebriefing._render_one_impact_playbook(
            witness, language="solidity", contract_kind="vault"
        )
        self.assertEqual(_foreign_example_lines(gated), [])
        # Non-vacuity: Solidity-relevant content survives (the body is not
        # emptied - it still renders bullets / sub-headers).
        self.assertTrue(any(l.startswith("- ") for l in gated))

    def test_render_one_playbook_keeps_foreign_lines_for_go_lane(self):
        # The other half: a Go lane (language='go') keeps every line - the
        # filter is language-gated, so foreign lines that are NATIVE to Go are
        # preserved verbatim.
        pbs = prebriefing.load_impact_playbooks()
        witness = None
        for pb in pbs:
            ungated = prebriefing._render_one_impact_playbook(pb)
            if _foreign_example_lines(ungated):
                witness = pb
                break
        self.assertIsNotNone(witness)
        go_render = prebriefing._render_one_impact_playbook(
            witness, language="go", contract_kind="consensus"
        )
        ungated = prebriefing._render_one_impact_playbook(witness)
        self.assertEqual(
            _foreign_example_lines(go_render),
            _foreign_example_lines(ungated),
            "go lane must keep every line (language-gated filter)",
        )


class SectionLevelPartition(unittest.TestCase):
    def test_solidity_vault_section_has_zero_foreign_example_lines(self):
        # End-to-end: the full Per-Impact methodology section for a Solidity
        # ERC-4626 vault lane (the strata shape) carries ZERO foreign-ecosystem
        # example lines in the four targeted blocks.
        ws = _solidity_vault_ws()
        sec = prebriefing._format_impact_methodology_section(
            lane_type="hunt",
            prompt_text="hunt direct theft of funds in withdraw()",
            workspace_path=ws,
        )
        self.assertTrue(sec)
        # Sanity: the lane really resolved to solidity/vault (so the gate is on).
        self.assertEqual(prebriefing._infer_workspace_language(ws), "solidity")
        self.assertEqual(_foreign_example_lines(sec), [])
        # Non-vacuity: a real DeFi playbook attached (not the generic stub).
        txt = "\n".join(sec)
        self.assertNotIn("name the exact impact class", txt)
        self.assertIn("### Impact: `direct-theft-funds`", txt)
        # The anti-pollution guidance PROSE is preserved (must NOT be dropped).
        self.assertIn(
            "a Solidity DeFi target does NOT get chain-halt".lower(),
            txt.lower(),
        )

    def test_go_consensus_section_unaffected(self):
        # A Go/consensus lane is unaffected: its native foreign lines remain
        # (the filter is language-gated, not a blanket scrub).
        ws = _go_consensus_src_ws()
        sec = prebriefing._format_impact_methodology_section(
            lane_type="hunt",
            prompt_text="prove the chain halt on FinalizeBlock",
            workspace_path=ws,
        )
        self.assertTrue(sec)
        self.assertEqual(prebriefing._infer_workspace_language(ws), "go")
        # The chain-halt playbook attached and its native consensus example
        # lines were kept (>=1 foreign-token line survives for a go lane).
        self.assertIn("### Impact: `chain-halt-shutdown`", "\n".join(sec))
        self.assertGreater(
            len(_foreign_example_lines(sec)),
            0,
            "go consensus lane must keep its native consensus example lines",
        )


if __name__ == "__main__":
    unittest.main()
