#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the Per-Impact Hunting Methodology injection in
tools/dispatch-agent-with-prebriefing.py.

Mirrors the harness-authoring injection test discipline: assert the lane gate,
the impact-class inference, the graceful corpus loader, and that the rendered
section ATTACHES correctly for a Go/consensus target (chain-halt), a DeFi
target (its impact methodology and NOT chain-halt), and is OMITTED for a
non-hunt lane. Non-vacuous: every positive assertion checks real playbook
content reaches the brief, not just that a function returns truthy.

The module file is hyphenated, so it is loaded via importlib with a
sys.modules registration BEFORE exec_module (Python 3.14 self-import safety),
matching tools/tests/test_dispatch_agent_with_prebriefing.py.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
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
    # Python 3.14: register before exec so a self-referential import resolves.
    sys.modules["dispatch_agent_with_prebriefing"] = mod
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod


prebriefing = _load_module()


def _attach(impact_id: str) -> str:
    """The precise per-playbook ATTACH marker the section emits for a rendered
    playbook (``### Impact: `<id>` - ...``). Asserting on this marker (rather
    than the bare impact-id substring) makes the partition checks precise: a
    playbook that genuinely attached emits the marker, whereas a mere prose
    cross-reference to an out-of-partition impact-id inside another playbook's
    caveat does NOT (so it never false-positives the no-chain-halt assertion).
    """
    return f"### Impact: `{impact_id}`"


def _go_consensus_ws() -> pathlib.Path:
    ws = pathlib.Path(tempfile.mkdtemp(prefix="impactwire_go_"))
    (ws / "SCOPE.md").write_text(
        "cosmos-sdk cometbft consensus module x/foo FinalizeBlock abci "
        "BeginBlock EndBlock baseapp",
        encoding="utf-8",
    )
    return ws


def _defi_vault_ws() -> pathlib.Path:
    ws = pathlib.Path(tempfile.mkdtemp(prefix="impactwire_defi_"))
    (ws / "SCOPE.md").write_text(
        "ERC4626 vault deposit withdraw redeem shares totalAssets "
        "convertToShares",
        encoding="utf-8",
    )
    return ws


def _ssv_solidity_ws() -> pathlib.Path:
    """An SSV-shaped Solidity DeFi workspace WITH real .sol source on disk, so
    the language scan resolves to 'solidity' and the language partition fires
    (chain-halt / bc-* are [go, rust]-only and must be EXCLUDED). The scope text
    routes to a lending/liquidation/staking contract-kind.
    """
    ws = pathlib.Path(tempfile.mkdtemp(prefix="impactwire_ssv_"))
    (ws / "SCOPE.md").write_text(
        "SSV Network operator cluster validator liquidation collateral "
        "borrow balance withdraw deposit staking liquidate",
        encoding="utf-8",
    )
    src = ws / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "SSVNetwork.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract SSVNetwork {\n"
        "  function liquidate(address cluster) external {}\n"
        "  function withdraw(uint256 amount) external {}\n"
        "}\n",
        encoding="utf-8",
    )
    (src / "Cluster.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "library ClusterLib {\n"
        "  function balanceOf(bytes32 id) internal returns (uint256) {}\n"
        "}\n",
        encoding="utf-8",
    )
    return ws


def _go_consensus_src_ws() -> pathlib.Path:
    """A Go/consensus workspace WITH real .go source on disk so the language
    scan resolves to 'go' (the solidity-only DeFi impacts must be EXCLUDED).
    """
    ws = pathlib.Path(tempfile.mkdtemp(prefix="impactwire_gosrc_"))
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
    (src / "keeper.go").write_text(
        "package foo\nfunc BeginBlock() {}\n",
        encoding="utf-8",
    )
    return ws


class ImpactMethodologyLaneGate(unittest.TestCase):
    def test_hunt_lane_type_fires(self):
        self.assertTrue(prebriefing.is_impact_methodology_lane("hunt", ""))

    def test_harness_and_audit_lane_types_fire(self):
        self.assertTrue(prebriefing.is_impact_methodology_lane("harness", ""))
        self.assertTrue(prebriefing.is_impact_methodology_lane("audit", ""))
        self.assertTrue(
            prebriefing.is_impact_methodology_lane("exploit-conversion", "")
        )

    def test_non_impact_filing_lane_does_not_fire(self):
        self.assertFalse(
            prebriefing.is_impact_methodology_lane("filing", "refile cantina-202")
        )

    def test_impact_keyword_in_prompt_fires_on_generic_lane(self):
        # keyword path: a filing lane whose prompt asserts an impact class.
        self.assertTrue(
            prebriefing.is_impact_methodology_lane(
                "filing", "prove the chain halt impact"
            )
        )


class ImpactClassInference(unittest.TestCase):
    def test_chain_halt_inferred(self):
        self.assertEqual(
            prebriefing.infer_target_impact_class(
                "Lane X: prove the chain halt on Finalize"
            ),
            "chain-halt-shutdown",
        )

    def test_share_inflation_inferred_from_donation(self):
        self.assertEqual(
            prebriefing.infer_target_impact_class(
                "hunt first-depositor donation attack"
            ),
            "share-supply-inflation",
        )

    def test_direct_theft_inferred(self):
        self.assertEqual(
            prebriefing.infer_target_impact_class(
                "hunt direct theft of funds in withdraw()"
            ),
            "direct-theft-funds",
        )

    def test_empty_prompt_returns_empty(self):
        self.assertEqual(prebriefing.infer_target_impact_class(""), "")

    def test_every_inferred_id_resolves_to_a_real_playbook(self):
        # Non-vacuity: every id the inference can return must exist in the
        # corpus (so the dispatch section never injects a dangling id).
        ids = {p["impact_id"] for p in prebriefing.load_impact_playbooks()}
        self.assertTrue(ids, "corpus must be present for this repo")
        for impact_id, _kws in prebriefing._IMPACT_KEYWORD_RULES:
            self.assertIn(impact_id, ids, impact_id)


class ImpactPlaybookLoader(unittest.TestCase):
    def test_corpus_loads_non_empty(self):
        pbs = prebriefing.load_impact_playbooks()
        self.assertTrue(pbs)
        for p in pbs:
            self.assertTrue(str(p.get("impact_id") or "").strip())

    def test_missing_corpus_degrades_to_empty(self):
        self.assertEqual(
            prebriefing.load_impact_playbooks(
                pathlib.Path("/nonexistent/impact_hunting_methodology.yaml")
            ),
            [],
        )

    def test_contract_kind_inference(self):
        self.assertEqual(
            prebriefing._infer_contract_kind(
                prompt_text="cometbft finalize block", scope_text=""
            ),
            "consensus",
        )
        self.assertEqual(
            prebriefing._infer_contract_kind(
                prompt_text="erc4626 vault withdraw", scope_text=""
            ),
            "vault",
        )


class ImpactMethodologySectionRender(unittest.TestCase):
    def test_go_consensus_target_gets_chain_halt_block(self):
        ws = _go_consensus_ws()
        sec = prebriefing._format_impact_methodology_section(
            lane_type="hunt",
            prompt_text="prove the chain halt on FinalizeBlock",
            workspace_path=ws,
        )
        self.assertTrue(sec)
        txt = "\n".join(sec)
        self.assertIn(prebriefing._IMPACT_METHODOLOGY_SECTION_HEADER, txt)
        self.assertIn(_attach("chain-halt-shutdown"), txt)
        # Non-vacuity: real chain-halt playbook content reaches the brief.
        self.assertIn("Critical paths", txt)
        self.assertIn("hacker questions", txt.lower())

    def test_defi_target_gets_impact_methodology_and_not_chain_halt(self):
        ws = _defi_vault_ws()
        sec = prebriefing._format_impact_methodology_section(
            lane_type="hunt",
            prompt_text="hunt direct theft of funds in withdraw()",
            workspace_path=ws,
        )
        self.assertTrue(sec)
        txt = "\n".join(sec)
        self.assertIn(prebriefing._IMPACT_METHODOLOGY_SECTION_HEADER, txt)
        self.assertIn(_attach("direct-theft-funds"), txt)
        # The DeFi brief must NOT carry the chain-halt playbook (a prose
        # cross-reference in another playbook's caveat is allowed; the attach
        # marker is the precise partition check).
        self.assertNotIn(_attach("chain-halt-shutdown"), txt)

    def test_non_hunt_lane_gets_neither(self):
        ws = _defi_vault_ws()
        sec = prebriefing._format_impact_methodology_section(
            lane_type="filing",
            prompt_text="refile cantina-202",
            workspace_path=ws,
        )
        self.assertEqual(sec, [])

    def test_contract_kind_partition_gates_out_mismatched_playbook(self):
        # A 'chain halt' prompt over a DeFi vault ws: chain-halt is gated out by
        # applies_to_contract_kinds (a vault is not a consensus kind), so the
        # ABCI block must NOT render. The renderer-aligned selection now surfaces
        # the vault's REAL impact classes (direct-theft / freeze) from the kind
        # family instead of falling back to the generic stub - the partition
        # holds AND the lane gets concrete impact methodology.
        ws = _defi_vault_ws()
        sec = prebriefing._format_impact_methodology_section(
            lane_type="hunt",
            prompt_text="chain halt on this vault",
            workspace_path=ws,
        )
        self.assertTrue(sec)
        txt = "\n".join(sec)
        # The consensus chain-halt PLAYBOOK must NOT attach to a vault (the
        # precise partition check is the attach marker; a prose cross-reference
        # to a consensus hook inside another DeFi playbook's body is allowed).
        self.assertNotIn(_attach("chain-halt-shutdown"), txt)
        self.assertNotIn(_attach("chain-split-fork"), txt)
        self.assertNotIn(_attach("bc-consensus-transient-failure"), txt)
        # And it is NOT the generic stub: a real vault impact class attached.
        self.assertNotIn("name the exact impact class", txt)
        self.assertIn(_attach("direct-theft-funds"), txt)

    def test_missing_corpus_renders_generic_stub(self):
        ws = _defi_vault_ws()
        orig = prebriefing._IMPACT_HUNTING_METHODOLOGY_PATH
        try:
            prebriefing._IMPACT_HUNTING_METHODOLOGY_PATH = pathlib.Path(
                "/nonexistent/impact_hunting_methodology.yaml"
            )
            sec = prebriefing._format_impact_methodology_section(
                lane_type="hunt",
                prompt_text="hunt direct theft of funds",
                workspace_path=ws,
            )
        finally:
            prebriefing._IMPACT_HUNTING_METHODOLOGY_PATH = orig
        self.assertTrue(sec)
        self.assertIn(
            prebriefing._IMPACT_METHODOLOGY_SECTION_HEADER, "\n".join(sec)
        )


class ImpactMethodologyAssemblyWiring(unittest.TestCase):
    def test_section_lands_in_full_brief_for_go_target(self):
        ws = _go_consensus_ws()
        out = prebriefing.format_skeleton_as_markdown(
            None,
            lane_type="hunt",
            severity="CRITICAL",
            workspace_path=ws,
            prompt_text="prove the chain halt on FinalizeBlock",
        )
        self.assertIn(prebriefing._IMPACT_METHODOLOGY_SECTION_HEADER, out)
        self.assertIn(_attach("chain-halt-shutdown"), out)

    def test_section_is_idempotent_in_assembly(self):
        ws = _defi_vault_ws()
        out = prebriefing.format_skeleton_as_markdown(
            None,
            lane_type="hunt",
            severity="HIGH",
            workspace_path=ws,
            prompt_text="hunt direct theft of funds",
        )
        self.assertEqual(
            out.count(prebriefing._IMPACT_METHODOLOGY_SECTION_HEADER), 1
        )

    def test_non_hunt_assembly_omits_the_section(self):
        ws = _defi_vault_ws()
        out = prebriefing.format_skeleton_as_markdown(
            None,
            lane_type="filing",
            severity="HIGH",
            workspace_path=ws,
            prompt_text="refile cantina-202",
        )
        self.assertNotIn(prebriefing._IMPACT_METHODOLOGY_SECTION_HEADER, out)


def _stub_skeleton_unavailable(**_kwargs):
    """MCP caller stub that forces the skeleton-unavailable (degraded) brief
    path - the branch that injects the impact section at iter 1 even when MCP
    is down. Returning None routes build_enriched_prompt to the degraded
    assembly that calls _format_impact_methodology_section at line ~4374.
    """
    return None


def _stub_phase_a(**_kwargs):
    return {}


# The 8 hunt-class lane types that are NOT in VALID_LANE_TYPES and were
# therefore force-downgraded to "filing" before the impact section rendered -
# the exact G3 silent-drop set. Each must now render the section.
_DOWNGRADED_IMPACT_LANES = (
    "harness",
    "poc",
    "invariant",
    "prove",
    "exploit-conversion",
    "audit",
    "audit-deep",
    "deep",
)


class G3DispatchReachAcrossDowngradedLanes(unittest.TestCase):
    """G3: the section must render through build_enriched_prompt for the
    hunt-class lane types that get downgraded to 'filing', INCLUDING on a
    neutral (non-impact-keyword) prompt - the case that was silently dropped.
    """

    def test_section_renders_for_all_eight_downgraded_lane_types_neutral_prompt(
        self,
    ):
        ws = _go_consensus_ws()
        # A neutral, harness-flavored prompt: it trips NO impact-noun keyword,
        # so before the fix the downgrade-to-filing killed the section.
        neutral_prompt = "scaffold a medusa harness for this module"
        rendered = 0
        for lane in _DOWNGRADED_IMPACT_LANES:
            enriched, meta = prebriefing.build_enriched_prompt(
                prompt_text=neutral_prompt,
                lane_type=lane,
                severity="HIGH",
                workspace_path=ws,
                mcp_caller=_stub_skeleton_unavailable,
                pillar_context_caller=_stub_phase_a,
            )
            # The lane was indeed downgraded (proves we exercise the G3 path).
            self.assertEqual(meta["lane_type"], "filing", lane)
            self.assertEqual(meta["original_lane_type"], lane, lane)
            self.assertIn(
                prebriefing._IMPACT_METHODOLOGY_SECTION_HEADER,
                enriched,
                f"impact section silently dropped for downgraded lane {lane!r}",
            )
            rendered += 1
        # Non-vacuity: assert we covered >= 8 lane types (the G3 claim).
        self.assertGreaterEqual(rendered, 8)

    def test_go_consensus_harness_brief_contains_chain_halt_methodology(self):
        # A harness lane (downgraded to filing) over a Go/consensus target whose
        # brief names the impact must carry the REAL chain-halt playbook content,
        # not just the header. This is the load-bearing G3 case: BEFORE the fix
        # the harness->filing downgrade dropped the whole section even though the
        # impact is named; AFTER the fix it lands.
        ws = _go_consensus_ws()
        enriched, meta = prebriefing.build_enriched_prompt(
            prompt_text="scaffold a medusa harness that proves the chain halt",
            lane_type="harness",
            severity="CRITICAL",
            workspace_path=ws,
            mcp_caller=_stub_skeleton_unavailable,
            pillar_context_caller=_stub_phase_a,
        )
        self.assertEqual(meta["lane_type"], "filing")
        self.assertEqual(meta["original_lane_type"], "harness")
        self.assertIn(
            prebriefing._IMPACT_METHODOLOGY_SECTION_HEADER, enriched
        )
        self.assertIn(_attach("chain-halt-shutdown"), enriched)
        # Non-vacuity: real playbook structure reached the brief (a matched
        # playbook renders these section sub-headers; the no-match stub does
        # NOT, so this also proves a real playbook attached, not the stub).
        self.assertNotIn("name the exact impact class", enriched)
        self.assertIn("Critical paths", enriched)
        self.assertIn("hacker questions", enriched.lower())

    def test_invariant_lane_go_consensus_contains_chain_halt(self):
        ws = _go_consensus_ws()
        enriched, meta = prebriefing.build_enriched_prompt(
            prompt_text="write invariant properties proving the chain halt",
            lane_type="invariant",
            severity="HIGH",
            workspace_path=ws,
            mcp_caller=_stub_skeleton_unavailable,
            pillar_context_caller=_stub_phase_a,
        )
        self.assertEqual(meta["original_lane_type"], "invariant")
        self.assertIn(_attach("chain-halt-shutdown"), enriched)
        self.assertNotIn("name the exact impact class", enriched)
        self.assertIn("Critical paths", enriched)

    def test_defi_vault_hunt_has_fund_theft_not_chain_halt(self):
        # The partition must hold end-to-end: a DeFi vault hunt brief carries a
        # fund-theft impact methodology and NOT the consensus chain-halt
        # playbook.
        ws = _defi_vault_ws()
        enriched, _meta = prebriefing.build_enriched_prompt(
            prompt_text="hunt direct theft of funds in withdraw()",
            lane_type="hunt",
            severity="HIGH",
            workspace_path=ws,
            mcp_caller=_stub_skeleton_unavailable,
            pillar_context_caller=_stub_phase_a,
        )
        self.assertIn(
            prebriefing._IMPACT_METHODOLOGY_SECTION_HEADER, enriched
        )
        # A real fund-theft impact class attaches (matched playbook, not stub).
        self.assertNotIn("name the exact impact class", enriched)
        self.assertIn(_attach("direct-theft-funds"), enriched)
        # And the consensus chain-halt playbook does NOT attach to a vault.
        self.assertNotIn(_attach("chain-halt-shutdown"), enriched)

    def test_defi_vault_inflation_hunt_attaches_inflation_not_chain_halt(self):
        # Inflation half of the partition: a share-inflation hunt over a vault
        # attaches the share-supply-inflation playbook, not chain-halt.
        ws = _defi_vault_ws()
        enriched, _meta = prebriefing.build_enriched_prompt(
            prompt_text="hunt first-depositor donation share inflation",
            lane_type="hunt",
            severity="HIGH",
            workspace_path=ws,
            mcp_caller=_stub_skeleton_unavailable,
            pillar_context_caller=_stub_phase_a,
        )
        self.assertNotIn("name the exact impact class", enriched)
        self.assertIn(_attach("share-supply-inflation"), enriched)
        self.assertNotIn(_attach("chain-halt-shutdown"), enriched)

    def test_section_still_omitted_for_genuine_filing_lane(self):
        # Regression guard: a real filing lane on a non-impact prompt must NOT
        # get the section (the fix must not over-attach to every brief).
        ws = _defi_vault_ws()
        enriched, meta = prebriefing.build_enriched_prompt(
            prompt_text="refile cantina-202 with the updated paste",
            lane_type="filing",
            severity="HIGH",
            workspace_path=ws,
            mcp_caller=_stub_skeleton_unavailable,
            pillar_context_caller=_stub_phase_a,
        )
        self.assertEqual(meta["original_lane_type"], "filing")
        self.assertNotIn(
            prebriefing._IMPACT_METHODOLOGY_SECTION_HEADER, enriched
        )


class G5SingleSourceOfTruth(unittest.TestCase):
    """G5: dispatch must use the renderer's classify_impact_target as the ONE
    contract-kind classifier (no forked _CONTRACT_KIND_RULES). The renderer is
    importable in this repo, so the two paths must agree.
    """

    def test_renderer_is_imported_not_forked(self):
        rend = prebriefing._renderer()
        self.assertIsNotNone(rend, "renderer must be importable in this repo")
        self.assertTrue(callable(getattr(rend, "classify_impact_target", None)))
        self.assertTrue(callable(getattr(rend, "kind_family", None)))

    def test_dispatch_kind_inference_matches_renderer(self):
        # The exact divergence the fork introduced: amm/amm-dex and
        # zk-circuit/zk-verifier. Dispatch must now emit the renderer's tokens.
        rend = prebriefing._renderer()
        cases = [
            ("uniswap swap pool x*y=k constant product", "amm"),
            ("groth16 plonk verifier nullifier proof circuit", "zk-circuit"),
            ("cometbft finalize block abci consensus", "consensus"),
            ("erc4626 vault converttoshares totalassets", "vault"),
        ]
        for blob, _expected in cases:
            disp_kind = prebriefing._infer_contract_kind(
                prompt_text=blob, scope_text=""
            )
            rend_res = rend.classify_impact_target(blob, "", scope_text="")
            rend_kind = str(rend_res.get("contract_kind") or "").lower()
            self.assertEqual(
                disp_kind,
                rend_kind,
                f"dispatch/renderer kind divergence on {blob!r}: "
                f"{disp_kind!r} vs {rend_kind!r}",
            )

    def test_dispatch_emits_canonical_amm_not_amm_dex(self):
        # Concrete anti-fork assertion: the old fork emitted 'amm-dex'.
        kind = prebriefing._infer_contract_kind(
            prompt_text="uniswap swap liquidity pool", scope_text=""
        )
        self.assertEqual(kind, "amm")
        self.assertNotEqual(kind, "amm-dex")

    def test_dispatch_emits_canonical_zk_circuit_not_zk_verifier(self):
        kind = prebriefing._infer_contract_kind(
            prompt_text="groth16 verifier proof circuit", scope_text=""
        )
        self.assertEqual(kind, "zk-circuit")
        self.assertNotEqual(kind, "zk-verifier")

    def test_family_attach_admits_fine_corpus_kind_via_renderer(self):
        # A coarse inferred 'lending' must admit a playbook authored against a
        # FINE kind in the same family (e.g. cdp-vault), exactly as the renderer
        # does - proving _impact_playbook_attaches uses kind_family, not a
        # literal compare.
        rend = prebriefing._renderer()
        self.assertEqual(rend.kind_family("cdp-vault"), "lending")
        pb = {"applies_to_contract_kinds": ["cdp-vault", "lending-market"]}
        self.assertTrue(
            prebriefing._impact_playbook_attaches(pb, contract_kind="lending")
        )
        # And a genuinely-different family is still excluded (fail-closed).
        pb_consensus = {"applies_to_contract_kinds": ["abci-app", "consensus"]}
        self.assertFalse(
            prebriefing._impact_playbook_attaches(
                pb_consensus, contract_kind="vault"
            )
        )


class LanguageAndKindPartition(unittest.TestCase):
    """The lane-level _format_impact_methodology_section must partition impacts
    by BOTH the workspace language (FAIL-CLOSED: a Solidity ws never gets
    chain-halt / bc-*) AND the renderer's contract-kind family (an SSV
    lending/liquidation ws surfaces the FULL liquidation-abuse + direct-theft +
    permanent-freeze + oracle + reward set, not one keyword hit). This is the
    measured SSV bug: before the fix the lane brief inferred a single impact via
    a prompt keyword and consulted no language, so it could carry chain-halt and
    miss the real DeFi impact set the per-fn renderer attaches.
    """

    def test_workspace_language_scan_resolves_solidity(self):
        ws = _ssv_solidity_ws()
        self.assertEqual(
            prebriefing._infer_workspace_language(ws), "solidity"
        )

    def test_workspace_language_scan_resolves_go(self):
        ws = _go_consensus_src_ws()
        self.assertEqual(prebriefing._infer_workspace_language(ws), "go")

    def test_workspace_language_scan_empty_for_no_source(self):
        # No in-scope source on disk -> "" (admit-all; never over-drop).
        self.assertEqual(prebriefing._infer_workspace_language(_defi_vault_ws()), "")
        self.assertEqual(prebriefing._infer_workspace_language(None), "")

    def test_ssv_solidity_section_has_full_defi_impact_set_no_chain_halt(self):
        # THE load-bearing SSV case. Prompt names liquidation/balance/withdraw;
        # the ws is Solidity lending/liquidation. The section MUST contain the
        # renderer-aligned impact set and MUST NOT contain chain-halt or any
        # go/rust-only bc-* consensus impact.
        ws = _ssv_solidity_ws()
        sec = prebriefing._format_impact_methodology_section(
            lane_type="hunt",
            prompt_text="hunt cluster liquidation balance withdraw",
            workspace_path=ws,
        )
        self.assertTrue(sec)
        txt = "\n".join(sec)
        self.assertIn(prebriefing._IMPACT_METHODOLOGY_SECTION_HEADER, txt)
        # Renderer-aligned DeFi impact set present (non-vacuous: not the stub).
        self.assertNotIn("name the exact impact class", txt)
        self.assertIn(_attach("liquidation-abuse"), txt)
        self.assertIn(_attach("direct-theft-funds"), txt)
        self.assertIn(_attach("permanent-freeze-funds"), txt)
        # FAIL-CLOSED language + kind partition: NO consensus / bc-* impacts.
        self.assertNotIn(_attach("chain-halt-shutdown"), txt)
        self.assertNotIn(_attach("chain-split-fork"), txt)
        self.assertNotIn(_attach("bc-consensus-transient-failure"), txt)
        self.assertNotIn(_attach("bc-permanent-freeze-hardfork"), txt)
        self.assertNotIn("BeginBlock", txt)

    def test_go_consensus_src_section_has_chain_halt_not_solidity_defi(self):
        # The other half of the partition: a Go/consensus ws (language scan -> go)
        # whose prompt names the chain halt must contain chain-halt and MUST NOT
        # carry the solidity-only DeFi impacts (reentrancy/share-supply-inflation
        # are [solidity,...]-only without go in their language list, or are
        # kind-excluded for consensus).
        ws = _go_consensus_src_ws()
        sec = prebriefing._format_impact_methodology_section(
            lane_type="hunt",
            prompt_text="prove the chain halt on FinalizeBlock",
            workspace_path=ws,
        )
        self.assertTrue(sec)
        txt = "\n".join(sec)
        self.assertNotIn("name the exact impact class", txt)
        self.assertIn(_attach("chain-halt-shutdown"), txt)
        # Solidity-only DeFi impacts must NOT attach to a Go consensus target.
        self.assertNotIn(_attach("share-supply-inflation"), txt)
        self.assertNotIn(_attach("reentrancy"), txt)
        self.assertNotIn(_attach("liquidation-abuse"), txt)

    def test_reverting_language_guard_makes_no_chain_halt_assertion_fail(self):
        # Non-vacuity proof: if the language partition is removed (language="")
        # AND the prompt names a consensus verb, the chain-halt playbook is no
        # longer excluded by language. Over the SSV Solidity ws the kind guard
        # still excludes it (a lending kind is not consensus), so to isolate the
        # LANGUAGE arm we use the selector directly with a consensus kind: with
        # language='solidity' chain-halt is dropped; with language='' it is NOT.
        playbooks = prebriefing.load_impact_playbooks()
        with_lang = {
            str(p.get("impact_id"))
            for p in prebriefing.select_lane_impact_playbooks(
                playbooks,
                prompt_text="prove the chain halt",
                language="solidity",
                contract_kind="consensus",
            )
        }
        without_lang = {
            str(p.get("impact_id"))
            for p in prebriefing.select_lane_impact_playbooks(
                playbooks,
                prompt_text="prove the chain halt",
                language="",
                contract_kind="consensus",
            )
        }
        # FAIL-CLOSED: the language guard removes chain-halt for a solidity ws.
        self.assertNotIn("chain-halt-shutdown", with_lang)
        # Reverting the guard (no language) re-admits it - so the no-chain-halt
        # assertion would FAIL, which is exactly the mutation-kill witness.
        self.assertIn("chain-halt-shutdown", without_lang)

    def test_selector_does_not_over_attach_on_unknown_kind(self):
        # FAIL-OPEN guard: an unclassified target ("" kind) must NOT pull every
        # DeFi impact - only the prompt-keyword-inferred id (if language-admitted)
        # is returned.
        playbooks = prebriefing.load_impact_playbooks()
        sel = prebriefing.select_lane_impact_playbooks(
            playbooks,
            prompt_text="hunt direct theft of funds",
            language="solidity",
            contract_kind="",
        )
        ids = {str(p.get("impact_id")) for p in sel}
        self.assertEqual(ids, {"direct-theft-funds"})

    def test_selector_surfaces_multiple_for_known_kind(self):
        # Non-vacuity: a known DeFi kind surfaces MORE than one impact (the whole
        # point of the renderer-aligned selection).
        playbooks = prebriefing.load_impact_playbooks()
        sel = prebriefing.select_lane_impact_playbooks(
            playbooks,
            prompt_text="hunt cluster liquidation balance withdraw",
            language="solidity",
            contract_kind="lending",
        )
        self.assertGreaterEqual(len(sel), 3)
        ids = {str(p.get("impact_id")) for p in sel}
        self.assertIn("liquidation-abuse", ids)
        self.assertIn("direct-theft-funds", ids)
        self.assertNotIn("chain-halt-shutdown", ids)


if __name__ == "__main__":
    unittest.main()
