#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the GENERIC (language-gated) foreign-ecosystem inner-line filter in
_render_one_impact_playbook (tools/dispatch-agent-with-prebriefing.py).

Recurring root (L5+L6): the foreign-ecosystem drop used to be gated on a FINITE
contract_kind allowlist (_SOLIDITY_DEFI_KINDS = vault/proxy/lending/amm/bridge/
token/governance). A Solidity target classified with a kind OUTSIDE that set
(strata classifies contract_kind='oracle' due to AprPairFeed; earlier it was
'proxy') had _drop_foreign=False, so cosmos / ABCI / BeginBlock / Go / Rust /
OP-Stack example lines LEAKED into a Solidity prompt. Whack-a-mole every time a
new kind appears.

Generic fix verified here:
  - _drop_foreign is gated on LANGUAGE (solidity/vyper), independent of
    contract_kind, so the strata oracle shape is cleaned.
  - the severity_mapping emission loop (previously UNFILTERED) now drops a
    foreign row (chain_halt_via_div_by_zero_or_panic).
  - the token set covers 'tendermint' and 'penumbra'.
  - a Go/consensus lane keeps every line (filter stays language-gated).

The module file is hyphenated, loaded via importlib with a sys.modules
registration BEFORE exec_module (Python 3.14 self-import safety), matching the
sibling dispatch tests.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "dispatch-agent-with-prebriefing.py"


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

_TOKS = prebriefing._FOREIGN_ECOSYSTEM_LINE_TOKENS


def _foreign_lines(rendered):
    """Every rendered bullet line carrying a foreign-ecosystem token, anywhere
    in the playbook body (severity_mapping included, since that block is now
    in-scope for the filter)."""
    out = []
    for line in rendered:
        if line.lstrip().startswith("-") and any(
            t in line.lower() for t in _TOKS
        ):
            out.append(line)
    return out


# A multi-ecosystem playbook fixture: a severity_mapping variant + example
# lines across every targeted block, mixing a pure-Solidity line with foreign
# (Go/Cosmos, OP-Stack, other-chain) lines. Shapes the strata leak directly.
_MIXED_PLAYBOOK = {
    "impact_id": "direct-theft-funds",
    "title": "Direct theft of user funds",
    "severity_mapping": {
        "evm_drain": {
            "verdict": "Critical",
            "rubric_rows": ["Direct theft of user funds"],
        },
        "chain_halt_via_div_by_zero_or_panic": {
            "verdict": "High",
            "rubric_rows": ["Chain halt via panic in BeginBlock"],
        },
    },
    "critical_paths": [
        {"path": "withdraw() lets attacker drain vault shares"},
        {"path": "BeginBlock hook on cosmos panics the chain"},
        {"path": "FaultDisputeGame resolve race on op-stack"},
        {"path": "tendermint consensus stall via penumbra note"},
    ],
    "attack_surface": [
        {"actor": "any EOA", "surface": "redeem() reentrancy"},
        {"actor": "validator", "surface": "baseapp ante-handler authz bypass"},
    ],
    "hacker_questions": [
        {"q": "Can withdraw() be reentered to over-withdraw shares?"},
        {"q": "Does EndBlock div-by-zero halt the cometbft chain?"},
    ],
    "incident_anchors": [
        {"anchor": "ERC4626 inflation attack on a real vault"},
        {"anchor": "ibc relayer fund-loss incident"},
    ],
}


class TokenSetExtension(unittest.TestCase):
    def test_tendermint_and_penumbra_present(self):
        low = {t.lower() for t in _TOKS}
        self.assertIn("tendermint", low)
        self.assertIn("penumbra", low)


class LanguageGate(unittest.TestCase):
    def test_gate_fires_for_oracle_kind(self):
        # THE strata regression: contract_kind='oracle' is OUTSIDE the historic
        # DeFi allowlist, yet a Solidity lane must still drop foreign lines.
        self.assertTrue(
            prebriefing._is_solidity_defi_lane("solidity", "oracle")
        )
        # And for any other non-allowlist kind a Solidity target might get.
        for kind in ("oracle", "feed", "registry", "", "weird-new-kind"):
            self.assertTrue(
                prebriefing._is_solidity_defi_lane("solidity", kind),
                f"solidity/{kind!r} must enable the foreign-line drop",
            )
        # Vyper is also EVM-source.
        self.assertTrue(prebriefing._is_solidity_defi_lane("vyper", "oracle"))

    def test_gate_off_for_go_and_unknown(self):
        self.assertFalse(prebriefing._is_solidity_defi_lane("go", "vault"))
        self.assertFalse(prebriefing._is_solidity_defi_lane("rust", "vault"))
        self.assertFalse(prebriefing._is_solidity_defi_lane("", "vault"))


class StrataOracleShape(unittest.TestCase):
    def test_oracle_lane_drops_all_foreign_lines_including_severity(self):
        # Ungated (old behavior baseline): the mixed playbook carries foreign
        # lines in BOTH severity_mapping and the example blocks.
        ungated = prebriefing._render_one_impact_playbook(_MIXED_PLAYBOOK)
        ungated_foreign = _foreign_lines(ungated)
        self.assertTrue(
            ungated_foreign,
            "fixture must contain foreign lines or the test is vacuous",
        )
        # The severity_mapping foreign row leaked in the ungated render
        # (proves part (a) had no filter before the fix).
        self.assertTrue(
            any("chain_halt_via_div_by_zero_or_panic" in l for l in ungated),
            "severity row must render ungated",
        )

        # Gated for solidity/oracle (the strata shape): ZERO foreign lines,
        # severity row included.
        gated = prebriefing._render_one_impact_playbook(
            _MIXED_PLAYBOOK, language="solidity", contract_kind="oracle"
        )
        self.assertEqual(
            _foreign_lines(gated),
            [],
            "solidity/oracle lane must carry no cosmos/ABCI/beginblock/"
            "chain_halt_via_div/tendermint/penumbra lines",
        )
        # Specific witnesses are gone.
        joined = "\n".join(gated).lower()
        for needle in (
            "chain_halt_via_div_by_zero_or_panic",
            "beginblock",
            "tendermint",
            "penumbra",
            "cosmos",
        ):
            self.assertNotIn(needle, joined, f"{needle} must be dropped")
        # Non-vacuity: the pure-Solidity content survives.
        self.assertTrue(
            any("withdraw()" in l for l in gated),
            "solidity content must NOT be emptied",
        )
        self.assertTrue(
            any("evm_drain" in l for l in gated),
            "solidity severity row must survive",
        )


class GoConsensusUnaffected(unittest.TestCase):
    def test_go_lane_keeps_every_line(self):
        # The other half: a Go lane keeps native consensus lines (the filter is
        # language-gated, not a blanket scrub).
        ungated = prebriefing._render_one_impact_playbook(_MIXED_PLAYBOOK)
        go_render = prebriefing._render_one_impact_playbook(
            _MIXED_PLAYBOOK, language="go", contract_kind="consensus"
        )
        self.assertEqual(
            _foreign_lines(go_render),
            _foreign_lines(ungated),
            "go lane must keep every foreign line (language-gated filter)",
        )


if __name__ == "__main__":
    unittest.main()
