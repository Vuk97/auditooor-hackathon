#!/usr/bin/env python3
"""capability-v3 iter-002 T5 — scope-reasoner regression tests.

No network. No external dependencies. All fixtures are generated in
tempdirs on the fly so tests are hermetic.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "scope-reasoner.py"


def _run_tool(draft: Path, scope: Path | None = None, patterns: Path | None = None) -> dict:
    cmd = [sys.executable, str(TOOL), "--draft", str(draft)]
    if scope is not None:
        cmd += ["--scope", str(scope)]
    if patterns is not None:
        cmd += ["--oos-patterns", str(patterns)]
    proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return json.loads(proc.stdout)


class ScopeReasonerTests(unittest.TestCase):
    def test_snow_r67_f001_would_have_flagged(self) -> None:
        """Snow R67-F001 lookalike draft + SCOPE with Polkadot OOS clause.

        Expectation: risk_level = likely-OOS AND a cross_chain_atomicity
        flag is present. If this test fails, we've regressed the exact
        miss that motivated the tool.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            scope = ws / "SCOPE.md"
            scope.write_text(
                textwrap.dedent(
                    """
                    # Snowbridge Scope

                    ## Critical operator guidance (program page)

                    > Submissions should contain analysis for both the Polkadot and
                    > Ethereum side of the bridge. Cross-chain atomicity is out of
                    > scope when it does not arise from destination-chain state.

                    > **Do NOT submit reports about missing message.origin checks**
                    > for V2 Message Handlers in the Gateway contract.
                    """
                ).strip()
                + "\n"
            )

            draft = ws / "source-draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    ## Finding: SnowbridgeL1Adaptor pre-fund theft

                    The attack requires a Polkadot-origin tx that pre-funds the
                    adaptor before the deposit. The adaptor's depositToken then
                    sweeps the full balance. Attack path assumes an atomic
                    prefund from the Polkadot side of the bridge.

                    Cross-chain atomicity is relied upon for the exploit window.
                    """
                ).strip()
                + "\n"
            )

            out = _run_tool(draft)
            self.assertEqual(out["risk_level"], "likely-OOS", out)
            names = [f["pattern_name"] for f in out["flags"]]
            self.assertIn("cross_chain_atomicity", names, out)

            ccx = next(f for f in out["flags"] if f["pattern_name"] == "cross_chain_atomicity")
            self.assertEqual(ccx["severity"], "likely-OOS")
            self.assertTrue(ccx["scope_clause_hit"])
            self.assertGreater(len(ccx["matches_found"]), 0)

    def test_draft_with_no_oos_patterns_returns_none_risk(self) -> None:
        """Clean finding (integer-overflow, local state) → risk_level=none."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            scope = ws / "SCOPE.md"
            scope.write_text("# Scope\n\nIn scope: ERC-20 token contract.\n")

            draft = ws / "source-draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    ## Finding: integer overflow in transfer

                    The transfer function permits overflow when amount + balance
                    exceeds 2**256, corrupting the sender balance. Fix: use
                    SafeMath or Solidity 0.8+ checked arithmetic.
                    """
                ).strip()
                + "\n"
            )

            out = _run_tool(draft)
            self.assertEqual(out["risk_level"], "none", out)
            self.assertEqual(out["flags"], [])

    def test_pattern_without_scope_clause_is_advisory_only(self) -> None:
        """Pattern hits but SCOPE.md has no corresponding OOS clause →
        advisory (not likely-OOS)."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            scope = ws / "SCOPE.md"
            # SCOPE.md deliberately does NOT mention centralization / admin.
            scope.write_text("# Scope\n\nIn scope: vault contract.\n")

            draft = ws / "source-draft.md"
            # Fires centralization_risk_admin via "admin can drain".
            draft.write_text(
                textwrap.dedent(
                    """
                    ## Finding: admin can drain vault

                    The owner can drain the vault by calling emergencyWithdraw.
                    This is an admin-key risk: the owner can drain at will.
                    """
                ).strip()
                + "\n"
            )

            out = _run_tool(draft)
            self.assertEqual(out["risk_level"], "advisory", out)
            self.assertEqual(len(out["flags"]), 1)
            flag = out["flags"][0]
            self.assertEqual(flag["pattern_name"], "centralization_risk_admin")
            self.assertEqual(flag["severity"], "advisory")
            self.assertFalse(flag["scope_clause_hit"])

    def test_oos_trap_metadata_line_does_not_create_scope_hit(self) -> None:
        """Machine-readable Impact Contract OOS trap inventories are not
        themselves an exploit dependency and must not trigger scope flags."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            scope = ws / "SCOPE.md"
            scope.write_text(
                textwrap.dedent(
                    """
                    # Scope

                    ## Out of scope
                    - Impacts involving centralization risks
                    - Frontrunning, backrunning, or sandwich attacks
                    """
                ).strip()
                + "\n"
            )

            draft = ws / "source-draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    ## Impact Contract

                    - oos_traps: centralization-risk, privileged-address-required, frontrun-sandwich

                    ## Finding

                    A fresh unprivileged attacker calls a public entrypoint and
                    drains third-party principal through a math bug.
                    """
                ).strip()
                + "\n"
            )

            out = _run_tool(draft, scope=scope)
            self.assertEqual(out["risk_level"], "none", out)
            self.assertEqual(out["flags"], [])

    def test_lack_of_liquidity_clause_does_not_promote_natural_activity(self) -> None:
        """A generic 'lack of liquidity' OOS clause must not promote a
        normal deposit/swap phrase into likely-OOS natural-network activity."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            scope = ws / "SCOPE.md"
            scope.write_text(
                textwrap.dedent(
                    """
                    # Scope

                    ## Out of scope
                    - Lack of liquidity impacts
                    """
                ).strip()
                + "\n"
            )

            draft = ws / "source-draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    ## Finding

                    The victim deposit arrives via normal MsgSwapIn, then a
                    fresh attacker drains principal through an interest math bug.
                    """
                ).strip()
                + "\n"
            )

            out = _run_tool(draft, scope=scope)
            names = [f["pattern_name"] for f in out["flags"]]
            self.assertIn("natural_network_activity_oos", names, out)
            flag = next(f for f in out["flags"] if f["pattern_name"] == "natural_network_activity_oos")
            self.assertEqual(flag["severity"], "advisory", out)
            self.assertFalse(flag["scope_clause_hit"], out)
            self.assertEqual(out["risk_level"], "advisory", out)

    def test_cosmos_persisted_state_repanic_is_not_bad_game_prereq(self) -> None:
        """Poisoned module state that re-panics in FinalizeBlock is
        production-profile restart evidence, not an already-invalid
        proof-game prerequisite."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            scope = ws / "SCOPE.md"
            scope.write_text(
                textwrap.dedent(
                    """
                    # Scope

                    ## Out of scope
                    - Invalid proposals that bypass the proof system.
                    """
                ).strip()
                + "\n"
            )

            draft = ws / "source-draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    ## Finding

                    The poisoned vault state survives a genuine node restart from disk; the restarted node re-panics on its first FinalizeBlock, proving the halt is permanent.
                    """
                ).strip()
                + "\n"
            )

            out = _run_tool(draft, scope=scope)
            names = [f["pattern_name"] for f in out["flags"]]
            self.assertNotIn("unproven_bad_game_prereq", names, out)
            suppressed = [f["pattern_name"] for f in out.get("suppressed_flags", [])]
            self.assertIn("unproven_bad_game_prereq", suppressed, out)

    def test_partitioned_state_cascading_delete_gap_flags_base_azul_shape(self) -> None:
        """Base-Azul Cantina T-1 shape: a parent revocation leaves a
        dependent mapping live. Counter-fixture proves explicit helper
        cleanup does not trip the advisory regex merely because the
        draft describes the same partitioned-state domain.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            scope = ws / "SCOPE.md"
            scope.write_text("# Scope\n\nIn scope: TEE registry state consistency.\n")

            draft = ws / "source-draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    ## Finding: signer state survives revoked image

                    The registry stores partitioned mappings from PCR0 to
                    validity and from signer to PCR0. deregisterPCR0 only
                    removes the primary PCR0 flag without clearing signerPCR0,
                    leaving stale dependent signer mapping entries operational.
                    """
                ).strip()
                + "\n"
            )

            out = _run_tool(draft, scope=scope)
            names = [f["pattern_name"] for f in out["flags"]]
            self.assertIn("partitioned_state_cascading_delete_gap", names, out)
            flag = next(
                f
                for f in out["flags"]
                if f["pattern_name"] == "partitioned_state_cascading_delete_gap"
            )
            self.assertEqual(flag["declared_severity"], "MEDIUM")
            self.assertEqual(flag["severity"], "advisory")

            counter = ws / "counter.md"
            counter.write_text(
                textwrap.dedent(
                    """
                    ## Finding: no stale signer state after image removal

                    removeImage(bytes32 imageId) delegates all teardown to
                    _removeAll(imageId). The helper walks the signer index,
                    clears signerToImage for each signer, and deletes the
                    image validity bit before returning.
                    """
                ).strip()
                + "\n"
            )

            clean = _run_tool(counter, scope=scope)
            clean_names = [f["pattern_name"] for f in clean["flags"]]
            self.assertNotIn("partitioned_state_cascading_delete_gap", clean_names, clean)

    def test_off_chain_params_vs_session_id_desync_flags_kv8_shape(self) -> None:
        """Base-Azul KV-8 shape: an off-chain prover dedupes by session id
        while ignoring parameter-hash equality. A draft that states the
        request parameter digest is checked stays clean for this pattern.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            scope = ws / "SCOPE.md"
            scope.write_text("# Scope\n\nIn scope: on-chain verifier acceptance paths.\n")

            draft = ws / "kv8.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    ## Finding: off-chain prover reuses mismatched proof

                    The gRPC prover service treats session_id as the only idempotency key; the same session id ignores parameter hash equality, so a parameter mismatch can receive a cached proof for another request.
                    """
                ).strip()
                + "\n"
            )

            out = _run_tool(draft, scope=scope)
            names = [f["pattern_name"] for f in out["flags"]]
            self.assertIn("off_chain_params_vs_session_id_desync", names, out)
            flag = next(
                f for f in out["flags"] if f["pattern_name"] == "off_chain_params_vs_session_id_desync"
            )
            self.assertEqual(flag["declared_severity"], "LOW")
            self.assertEqual(flag["severity"], "advisory")

            counter = ws / "kv8_counter.md"
            counter.write_text(
                textwrap.dedent(
                    """
                    ## Finding: session cache binds full request digest

                    The prover accepts a repeated session id only when
                    keccak256(encoded parameters) equals the stored request
                    digest. Any parameter mismatch is rejected before cache
                    reuse, so idempotency cannot replay another request.
                    """
                ).strip()
                + "\n"
            )

            clean = _run_tool(counter, scope=scope)
            clean_names = [f["pattern_name"] for f in clean["flags"]]
            self.assertNotIn("off_chain_params_vs_session_id_desync", clean_names, clean)

    def test_cache_trusts_external_authority_without_cap_flags_kv10_shape(self) -> None:
        """Base-Azul KV-10 shape: an on-chain cache stores an externally
        asserted expiry/value without a local sanity cap. Counter-fixture
        documents a bounded cache write and must stay clean.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            scope = ws / "SCOPE.md"
            scope.write_text("# Scope\n\nIn scope: verifier cache safety.\n")

            draft = ws / "kv10.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    ## Finding: external proof expiry is cached without bounds

                    The on-chain cache stores certificate expiry from the ZK proof output without any sanity cap, so an external authority can make the cached expiry exceed the protocol's intended maximum.
                    """
                ).strip()
                + "\n"
            )

            out = _run_tool(draft, scope=scope)
            names = [f["pattern_name"] for f in out["flags"]]
            self.assertIn("cache_trusts_external_authority_without_cap", names, out)
            flag = next(
                f
                for f in out["flags"]
                if f["pattern_name"] == "cache_trusts_external_authority_without_cap"
            )
            self.assertEqual(flag["declared_severity"], "MEDIUM")
            self.assertEqual(flag["severity"], "advisory")

            counter = ws / "kv10_counter.md"
            counter.write_text(
                textwrap.dedent(
                    """
                    ## Finding: cache write enforces local maximum

                    The verifier reads an oracle expiry and stores it only
                    after applying min(expiry, block.timestamp + MAX_CACHE_AGE).
                    Any external value above the local cap is clipped before
                    it reaches storage.
                    """
                ).strip()
                + "\n"
            )

            clean = _run_tool(counter, scope=scope)
            clean_names = [f["pattern_name"] for f in clean["flags"]]
            self.assertNotIn("cache_trusts_external_authority_without_cap", clean_names, clean)

    def test_base_azul_operator_response_assumption_is_likely_oos(self) -> None:
        """Catch FN-5-style drafts that assume Base will not blacklist,
        dispute, or retire an invalid proposal during the response window.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            scope = ws / "SCOPE.md"
            scope.write_text(
                textwrap.dedent(
                    """
                    ## Out of scope

                    Any report that assumes we will not dispute, blacklist, or
                    retire an invalid proposal within the proof system, unless
                    it can be shown that such an action cannot be taken.
                    """
                ).strip()
                + "\n"
            )

            draft = ws / "fn5.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    ## Finding: invalid game drains the bridge

                    The attack assumes Base will not blacklist the invalid game
                    during the 7-day window, so the descendant later finalizes.
                    """
                ).strip()
                + "\n"
            )

            out = _run_tool(draft, scope=scope)
            names = [f["pattern_name"] for f in out["flags"]]
            self.assertEqual(out["risk_level"], "likely-OOS", out)
            self.assertIn("operator_response_assumption", names, out)

    def test_base_azul_mock_verifier_prereq_is_likely_oos_but_disclaimer_is_clean(self) -> None:
        """Catch FN-5/FN-6-style mock-proof prerequisites without
        punishing a draft that explicitly says proof acceptance is not the bug.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            scope = ws / "SCOPE.md"
            scope.write_text(
                textwrap.dedent(
                    """
                    ## Out of scope

                    Any report relying on an invalid TEE or ZK proof will be
                    downgraded, especially TEE proofs unless it can be shown
                    that key compromise is unnecessary.
                    """
                ).strip()
                + "\n"
            )

            draft = ws / "fn6.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    ## Finding: invalid proposal finalizes

                    Permissionless reachability only succeeds because
                    MockVerifier returns true for any proof. A production path
                    requires a fresh enclave signature or key compromise.
                    """
                ).strip()
                + "\n"
            )

            out = _run_tool(draft, scope=scope)
            names = [f["pattern_name"] for f in out["flags"]]
            self.assertEqual(out["risk_level"], "likely-OOS", out)
            self.assertIn("invalid_proof_or_mock_verifier_prereq", names, out)

            counter = ws / "fn1.md"
            counter.write_text(
                textwrap.dedent(
                    """
                    ## Finding: challenge payout branch overpays

                    This submission does not rely on invalid TEE or ZK proofs.
                    The mock verifier is used only to reach a challenged-game
                    state; proof acceptance is not the bug.
                    """
                ).strip()
                + "\n"
            )

            clean = _run_tool(counter, scope=scope)
            clean_names = [f["pattern_name"] for f in clean["flags"]]
            self.assertNotIn("invalid_proof_or_mock_verifier_prereq", clean_names, clean)

    def test_base_azul_unproven_bad_game_prereq_is_likely_oos(self) -> None:
        """Catch bridge-drain drafts that begin after a fraudulent game has
        already resolved without proving the upstream production primitive.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            scope = ws / "SCOPE.md"
            scope.write_text(
                textwrap.dedent(
                    """
                    ## Out of scope

                    Reports that rely on an invalid proposal without showing
                    why it cannot be disputed, blacklisted, or retired within
                    the proof system will be downgraded. Invalid proof reliance
                    is also downgraded.
                    """
                ).strip()
                + "\n"
            )

            draft = ws / "fn5_bad_game.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    ## Finding: descendant keeps poisoned anchor

                    A fraudulent intermediate game G1 can resolve DEFENDER_WINS;
                    then a descendant G2 finalizes and drains the bridge through
                    the portal.
                    """
                ).strip()
                + "\n"
            )

            out = _run_tool(draft, scope=scope)
            names = [f["pattern_name"] for f in out["flags"]]
            self.assertEqual(out["risk_level"], "likely-OOS", out)
            self.assertIn("unproven_bad_game_prereq", names, out)

    def test_base_azul_current_deployment_config_gap_is_likely_oos(self) -> None:
        """Catch future/mainnet-only or currently-not-vulnerable config
        drafts before they become paste-ready.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            scope = ws / "SCOPE.md"
            scope.write_text(
                textwrap.dedent(
                    """
                    ## Out of scope

                    Base mainnet is not considered to be in scope for the
                    purpose of this competition. Reports that assume a service
                    or program will not restart with different configurations
                    may be downgraded.
                    """
                ).strip()
                + "\n"
            )

            draft = ws / "fn3.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    ## Finding: quorum threshold can be bypassed

                    The current Sepolia deployment is not vulnerable under the
                    N=20 configuration. The issue requires future configuration
                    drift on mainnet.
                    """
                ).strip()
                + "\n"
            )

            out = _run_tool(draft, scope=scope)
            names = [f["pattern_name"] for f in out["flags"]]
            self.assertEqual(out["risk_level"], "likely-OOS", out)
            self.assertIn("current_deployment_config_unproven", names, out)

    def test_base_azul_asset_scope_mismatch_is_likely_oos(self) -> None:
        """Catch drafts whose root cause is primarily in OP Stack or
        non-listed contracts unless a Base-native in-scope modification is
        proven elsewhere.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            scope = ws / "SCOPE.md"
            scope.write_text(
                textwrap.dedent(
                    """
                    ## Out of scope

                    Optimism smart contracts and OP Stack components are out of
                    scope unless Base-native modifications are the affected
                    code. Only assets in scope should anchor the report.
                    """
                ).strip()
                + "\n"
            )

            draft = ws / "fn_b.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    ## Finding: withdrawal path accepts stale state

                    The primary affected contract is AnchorStateRegistry, with
                    OptimismPortal2 as the impact path. The issue is not an
                    explicit asset listed in the competition page.
                    """
                ).strip()
                + "\n"
            )

            out = _run_tool(draft, scope=scope)
            names = [f["pattern_name"] for f in out["flags"]]
            self.assertEqual(out["risk_level"], "likely-OOS", out)
            self.assertIn("asset_scope_mismatch", names, out)

    def test_submission_local_path_leak_is_advisory(self) -> None:
        """Paste-ready drafts should not contain operator-local paths in
        commands triagers cannot run.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            scope = ws / "SCOPE.md"
            scope.write_text("# Scope\n\nIn scope: verifier contracts.\n")

            draft = ws / "local_path.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    ## Reproduction

                    Run forge test --match-path /Users/wolf/audits/base-azul/poc-tests/FN1.t.sol
                    """
                ).strip()
                + "\n"
            )

            out = _run_tool(draft, scope=scope)
            names = [f["pattern_name"] for f in out["flags"]]
            self.assertEqual(out["risk_level"], "advisory", out)
            self.assertIn("submission_local_path_leak", names, out)


if __name__ == "__main__":
    unittest.main()
