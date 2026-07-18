"""Unit tests for Rule 56 Rubric-Fit-At-Program-Level preflight (Check #102)."""

from __future__ import annotations

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tools" / "tests" / "fixtures" / "r56"

_spec = importlib.util.spec_from_file_location(
    "rubric_fit_program_level_check",
    ROOT / "tools" / "rubric-fit-program-level-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _workspace(ws_name: str, copy_scope: bool = True) -> Path:
    root = Path(tempfile.mkdtemp(prefix=f"r56_test_{ws_name}_"))
    # Rename the temp dir so the workspace inference picks up the desired name.
    new_root = root.parent / ws_name
    if new_root.exists():
        shutil.rmtree(new_root)
    root.rename(new_root)
    (new_root / "submissions" / "paste_ready").mkdir(parents=True)
    if copy_scope:
        src = FIXTURES / "workspaces" / ws_name / "SCOPE.md"
        if src.exists():
            shutil.copy(src, new_root / "SCOPE.md")
    return new_root


def _draft_in(ws: Path, body: str, filename: str = "draft-MEDIUM.md") -> Path:
    p = ws / "submissions" / "paste_ready" / filename
    p.write_text(body, encoding="utf-8")
    return p


def _run(draft: Path, workspace: Path | None = None, severity: str | None = None,
         strict: bool = False) -> tuple[int, dict]:
    return mod.run(draft, workspace=workspace, severity_override=severity, strict=strict)


# ---------------------------------------------------------------------------
# Tier 1: trigger discipline
# ---------------------------------------------------------------------------
class TestOutOfScope(unittest.TestCase):
    """LOW severity is below the MEDIUM minimum."""

    def test_low_severity_passes_oos(self) -> None:
        ws = _workspace("dydx")
        draft = _draft_in(
            ws,
            "Severity: Low\n\n- affected_component: x/feegrant\n",
            filename="low-draft.md",
        )
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_no_severity_passes_oos(self) -> None:
        ws = _workspace("dydx")
        draft = _draft_in(
            ws,
            "Some draft with no severity declaration.\n",
            filename="nosev.md",
        )
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")


class TestNoComponentCited(unittest.TestCase):
    """pass-no-component-cited when draft cites no module/pallet/subsystem."""

    def test_no_component(self) -> None:
        ws = _workspace("dydx")
        draft = _draft_in(
            ws,
            "Severity: Medium\n\n## Impact\n\nGeneric impact text with no component.\n",
        )
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-component-cited")


# ---------------------------------------------------------------------------
# Tier 2: per-workspace core vs non-core
# ---------------------------------------------------------------------------
class TestDydxNonCoreFails(unittest.TestCase):
    """dydx x/feegrant -> fail-component-is-non-core-for-program."""

    def test_feegrant_fails(self) -> None:
        ws = _workspace("dydx")
        body = (
            "Severity: Medium\n\n"
            "## Impact\n\nFee allowance destruction.\n\n"
            "- affected_component: x/feegrant\n"
        )
        draft = _draft_in(ws, body)
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-component-is-non-core-for-program")

    def test_gov_fails(self) -> None:
        ws = _workspace("dydx")
        body = (
            "Severity: High\n\n"
            "## Impact\n\nGovernance proposal griefing.\n\n"
            "- affected_component: x/gov\n"
        )
        draft = _draft_in(ws, body, filename="gov-draft.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-component-is-non-core-for-program")


class TestDydxCorePasses(unittest.TestCase):
    """dydx x/clob -> pass-component-is-program-core."""

    def test_clob_passes(self) -> None:
        ws = _workspace("dydx")
        body = (
            "Severity: High\n\n"
            "## Impact\n\nMatching engine degradation.\n\n"
            "- affected_component: x/clob\n"
        )
        draft = _draft_in(ws, body, filename="clob-draft.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-component-is-program-core")

    def test_perpetuals_passes(self) -> None:
        ws = _workspace("dydx")
        body = (
            "Severity: Critical\n\n"
            "## Impact\n\nPerp market settlement.\n\n"
            "- affected_component: x/perpetuals\n"
        )
        draft = _draft_in(ws, body, filename="perp-draft.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-component-is-program-core")


class TestSparkCoreVsNonCore(unittest.TestCase):
    """spark chain-watcher (core) vs logging (non-core)."""

    def test_chain_watcher_passes(self) -> None:
        ws = _workspace("spark")
        body = (
            "Severity: Critical\n\n"
            "## Impact\n\nChain-watcher exit validation gap.\n\n"
            "- subsystem: chain-watcher\n"
        )
        draft = _draft_in(ws, body, filename="cw-draft.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-component-is-program-core")

    def test_logging_fails(self) -> None:
        ws = _workspace("spark")
        body = (
            "Severity: Medium\n\n"
            "## Impact\n\nLog infra failure.\n\n"
            "- subsystem: logging\n"
        )
        draft = _draft_in(ws, body, filename="log-draft.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-component-is-non-core-for-program")


class TestHyperbridgeCoreVsNonCore(unittest.TestCase):
    """hyperbridge ismp-optimism (core) vs call-decompressor (non-core)."""

    def test_ismp_optimism_passes(self) -> None:
        ws = _workspace("hyperbridge")
        body = (
            "Severity: High\n\n"
            "## Impact\n\nState-root acceptance gap.\n\n"
            "- affected_module: ismp-optimism\n"
        )
        draft = _draft_in(ws, body, filename="opt-draft.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-component-is-program-core")

    def test_call_decompressor_fails(self) -> None:
        ws = _workspace("hyperbridge")
        body = (
            "Severity: Medium\n\n"
            "## Impact\n\nCall decompressor edge case.\n\n"
            "- subsystem: call-decompressor\n"
        )
        draft = _draft_in(ws, body, filename="cd-draft.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-component-is-non-core-for-program")


# ---------------------------------------------------------------------------
# Tier 3: override marker + rescue clause
# ---------------------------------------------------------------------------
class TestRebuttalAccepted(unittest.TestCase):
    """ok-rebuttal when r56-rebuttal marker is present."""

    def test_rebuttal_line(self) -> None:
        ws = _workspace("dydx")
        body = (
            "Severity: Medium\n\n"
            "r56-rebuttal: feegrant is integral to fee sponsorship infrastructure for the trading core\n\n"
            "- affected_component: x/feegrant\n"
        )
        draft = _draft_in(ws, body, filename="reb-draft.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_rebuttal_html(self) -> None:
        ws = _workspace("dydx")
        body = (
            "Severity: Medium\n\n"
            "<!-- r56-rebuttal: feegrant rotation flow is part of paymaster product surface -->\n\n"
            "- affected_component: x/feegrant\n"
        )
        draft = _draft_in(ws, body, filename="rebhtml-draft.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")


class TestCoreProductClaimRescue(unittest.TestCase):
    """draft with explicit '## Core Product Claim' section rescues non-core component."""

    def test_core_product_claim_rescues(self) -> None:
        ws = _workspace("dydx")
        body = (
            "Severity: Medium\n\n"
            "## Impact\n\nFeegrant impacts trading paymaster surface.\n\n"
            "- affected_component: x/feegrant\n\n"
            "## Core Product Claim\n\n"
            "Per SCOPE.md, x/feegrant powers paymaster relayed transactions which "
            "are the production fee-sponsorship channel for v4-chain perps users.\n"
        )
        draft = _draft_in(ws, body, filename="cpc-draft.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-component-is-program-core")


# ---------------------------------------------------------------------------
# Tier 4: fallback / warn-grade for uncurated workspaces
# ---------------------------------------------------------------------------
class TestUnknownWorkspaceWarn(unittest.TestCase):
    """component cited in uncurated workspace falls back to warn-grade pass."""

    def test_unknown_ws_with_scope_mention(self) -> None:
        ws = _workspace("custom_target_xyz", copy_scope=False)
        (ws / "SCOPE.md").write_text(
            "Core: pallet-custom-core handles all state.\n",
            encoding="utf-8",
        )
        body = (
            "Severity: Medium\n\n"
            "- pallet: pallet-custom-core\n"
        )
        draft = _draft_in(ws, body, filename="custom-draft.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-component-context-unknown")

    def test_unknown_ws_no_scope_warn(self) -> None:
        ws = _workspace("uncurated_target", copy_scope=False)
        # No SCOPE.md
        body = (
            "Severity: Medium\n\n"
            "- pallet: pallet-uncurated-thing\n"
        )
        draft = _draft_in(ws, body, filename="nopscope-draft.md")
        rc, payload = _run(draft, workspace=ws)
        # No curated list + SCOPE missing means warn-grade pass.
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-component-context-unknown")


# ---------------------------------------------------------------------------
# Tier 5: anchor fixture - real cantina-238 draft
# ---------------------------------------------------------------------------
ANCHOR_238 = Path(
    "/Users/wolf/audits/dydx/submissions/superseded/CLOSED-REJECTED-2026-05/"
    "cantina-238_dydx-cosmos-sdk-feegrant-revoke-queue-orphan-MEDIUM.md"
)
ANCHOR_202 = Path(
    "/Users/wolf/audits/dydx/submissions/paste_ready/filed/"
    "cantina-202_dydx-iavl-legacy-pruning-abba-v2-protocol-CRITICAL.md"
)
ANCHOR_DYDX_WS = Path("/Users/wolf/audits/dydx")


class TestRealAnchors(unittest.TestCase):
    """Real-world anchors from /Users/wolf/audits/dydx — read-only."""

    @unittest.skipUnless(ANCHOR_238.exists(), "cantina-238 anchor not present on disk")
    def test_cantina_238_fails(self) -> None:
        rc, payload = _run(ANCHOR_238, workspace=ANCHOR_DYDX_WS)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-component-is-non-core-for-program")
        # Either x/feegrant or x/auth (cosmos-sdk auth module is also non-core)
        # should be on the classifications.
        comps_lower = {c["component"].lower() for c in payload["evidence"]["classifications"]}
        self.assertTrue(any("feegrant" in c for c in comps_lower))

    @unittest.skipUnless(ANCHOR_202.exists(), "cantina-202 anchor not present on disk")
    def test_cantina_202_passes_core(self) -> None:
        rc, payload = _run(ANCHOR_202, workspace=ANCHOR_DYDX_WS)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-component-is-program-core")
        comps_lower = {c["component"].lower() for c in payload["evidence"]["classifications"]}
        self.assertTrue(
            any(core in c for c in comps_lower for core in ("x/clob", "x/perpetuals", "x/subaccounts")),
        )


# ---------------------------------------------------------------------------
# Tier 6: rebuttal sanity (oversized rejected)
# ---------------------------------------------------------------------------
class TestRebuttalOversizedIgnored(unittest.TestCase):
    """A >200 char rebuttal is ignored; original verdict stands."""

    def test_overlong_rebuttal_ignored(self) -> None:
        ws = _workspace("dydx")
        overlong = "x" * 250
        body = (
            "Severity: Medium\n\n"
            f"r56-rebuttal: {overlong}\n\n"
            "- affected_component: x/feegrant\n"
        )
        draft = _draft_in(ws, body, filename="overlong-draft.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-component-is-non-core-for-program")


# ---------------------------------------------------------------------------
# Tier 7: env override for component lists
# ---------------------------------------------------------------------------
class TestEnvOverride(unittest.TestCase):
    """AUDITOOOR_R56_CORE_COMPONENTS env hook adds core components."""

    def test_env_core_override_promotes(self) -> None:
        import os
        ws = _workspace("custom_ws", copy_scope=False)
        body = (
            "Severity: Medium\n\n"
            "- pallet: pallet-custom-vault\n"
        )
        draft = _draft_in(ws, body, filename="env-core-draft.md")
        old_env = os.environ.get("AUDITOOOR_R56_CORE_COMPONENTS")
        os.environ["AUDITOOOR_R56_CORE_COMPONENTS"] = "custom_ws=pallet-custom-vault"
        try:
            rc, payload = _run(draft, workspace=ws)
            self.assertEqual(rc, 0)
            self.assertEqual(payload["verdict"], "pass-component-is-program-core")
        finally:
            if old_env is None:
                os.environ.pop("AUDITOOOR_R56_CORE_COMPONENTS", None)
            else:
                os.environ["AUDITOOOR_R56_CORE_COMPONENTS"] = old_env

    def test_env_noncore_override_blocks(self) -> None:
        import os
        ws = _workspace("custom_ws2", copy_scope=False)
        body = (
            "Severity: Medium\n\n"
            "- pallet: pallet-custom-utility\n"
        )
        draft = _draft_in(ws, body, filename="env-noncore-draft.md")
        old_env = os.environ.get("AUDITOOOR_R56_NONCORE_COMPONENTS")
        os.environ["AUDITOOOR_R56_NONCORE_COMPONENTS"] = "custom_ws2=pallet-custom-utility"
        try:
            rc, payload = _run(draft, workspace=ws)
            self.assertEqual(rc, 1)
            self.assertEqual(payload["verdict"], "fail-component-is-non-core-for-program")
        finally:
            if old_env is None:
                os.environ.pop("AUDITOOOR_R56_NONCORE_COMPONENTS", None)
            else:
                os.environ["AUDITOOOR_R56_NONCORE_COMPONENTS"] = old_env


# ---------------------------------------------------------------------------
# Tier 8: cross-workspace fixture expansion (R56-FIXTURE-EXPANSION-XWS lane)
# Adds curated core/non-core coverage for polymarket, morpho, base-azul, sei,
# thegraph - the 5 workspaces beyond the original dydx/spark/hyperbridge seed.
# Each workspace gets a PASS (core component) + FAIL (non-core component).
# ---------------------------------------------------------------------------
class TestPolymarketCoreVsNonCore(unittest.TestCase):
    """polymarket CTFExchange (core) vs deployment scripts (non-core)."""

    def test_ctf_exchange_passes(self) -> None:
        ws = _workspace("polymarket")
        body = (
            "Severity: Critical\n\n"
            "## Impact\n\nUnauthorized order matching via signature bypass.\n\n"
            "- affected_component: CTFExchange\n"
        )
        draft = _draft_in(ws, body, filename="ctf-exchange-draft.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-component-is-program-core")

    def test_deployment_scripts_fails(self) -> None:
        ws = _workspace("polymarket")
        body = (
            "Severity: Medium\n\n"
            "## Impact\n\nDeployment script misconfiguration.\n\n"
            "- affected_component: deployment-scripts\n"
        )
        draft = _draft_in(ws, body, filename="polymarket-deploy-draft.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-component-is-non-core-for-program")


class TestMorphoCoreVsNonCore(unittest.TestCase):
    """morpho morpho-blue (core) vs test utilities (non-core)."""

    def test_morpho_blue_passes(self) -> None:
        ws = _workspace("morpho")
        body = (
            "Severity: Critical\n\n"
            "## Impact\n\nMorpho Blue bad-debt accounting underflow.\n\n"
            "- affected_component: morpho-blue\n"
        )
        draft = _draft_in(ws, body, filename="morpho-blue-draft.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-component-is-program-core")

    def test_test_utilities_fails(self) -> None:
        ws = _workspace("morpho")
        body = (
            "Severity: Medium\n\n"
            "## Impact\n\nTest utility helper miscalculates rate.\n\n"
            "- affected_component: test-utilities\n"
        )
        draft = _draft_in(ws, body, filename="morpho-test-util-draft.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-component-is-non-core-for-program")


class TestBaseAzulCoreVsNonCore(unittest.TestCase):
    """base-azul TEE verifier (core) vs devnet tooling (non-core)."""

    def test_tee_verifier_passes(self) -> None:
        ws = _workspace("base-azul")
        body = (
            "Severity: Critical\n\n"
            "## Impact\n\nTEE attestation bypass via NitroEnclaveVerifier.\n\n"
            "- affected_component: NitroEnclaveVerifier\n"
        )
        draft = _draft_in(ws, body, filename="ba-tee-draft.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-component-is-program-core")

    def test_devnet_fails(self) -> None:
        ws = _workspace("base-azul")
        body = (
            "Severity: Medium\n\n"
            "## Impact\n\nDevnet tooling misconfigures local node.\n\n"
            "- affected_component: devnet\n"
        )
        draft = _draft_in(ws, body, filename="ba-devnet-draft.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-component-is-non-core-for-program")


class TestSeiCoreVsNonCore(unittest.TestCase):
    """sei x/evm (core) vs giga (non-core, HARD OOS per SCOPE.md)."""

    def test_evm_module_passes(self) -> None:
        ws = _workspace("sei")
        body = (
            "Severity: High\n\n"
            "## Impact\n\nParallel EVM execution race in OCC scheduler.\n\n"
            "- affected_component: x/evm\n"
        )
        draft = _draft_in(ws, body, filename="sei-evm-draft.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-component-is-program-core")

    def test_giga_fails(self) -> None:
        ws = _workspace("sei")
        body = (
            "Severity: High\n\n"
            "## Impact\n\nGiga-only code path triggers panic.\n\n"
            "- affected_component: giga\n"
        )
        draft = _draft_in(ws, body, filename="sei-giga-draft.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-component-is-non-core-for-program")


class TestThegraphCoreVsNonCore(unittest.TestCase):
    """thegraph horizon (core) vs hardhat-graph-protocol (non-core)."""

    def test_horizon_passes(self) -> None:
        ws = _workspace("thegraph")
        body = (
            "Severity: High\n\n"
            "## Impact\n\nHorizon upgrade staking invariant violation.\n\n"
            "- affected_component: horizon\n"
        )
        draft = _draft_in(ws, body, filename="tg-horizon-draft.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-component-is-program-core")

    def test_hardhat_plugin_fails(self) -> None:
        ws = _workspace("thegraph")
        body = (
            "Severity: Medium\n\n"
            "## Impact\n\nHardhat plugin misformats fixture data.\n\n"
            "- affected_component: hardhat-graph-protocol\n"
        )
        draft = _draft_in(ws, body, filename="tg-hardhat-draft.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-component-is-non-core-for-program")


# ---------------------------------------------------------------------------
# Tier 9: rescue + rebuttal variants in new workspaces
# ---------------------------------------------------------------------------
class TestCoreProductClaimRescueCrossWorkspace(unittest.TestCase):
    """## Core Product Claim section rescues a polymarket non-core component."""

    def test_polymarket_dashboard_rescued_by_claim(self) -> None:
        ws = _workspace("polymarket")
        body = (
            "Severity: High\n\n"
            "## Impact\n\nDashboard surface integrates with CTFExchangeV2 fills.\n\n"
            "- affected_component: dashboard\n\n"
            "## Core Product Claim\n\n"
            "Per SCOPE.md asset table, the dashboard component renders\n"
            "CTFExchangeV2 trade events and is on the user-facing CLOB product surface;\n"
            "incorrect rendering directly impacts settlement display correctness.\n"
        )
        draft = _draft_in(ws, body, filename="polymarket-dashboard-rescue.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-component-is-program-core")


class TestRebuttalCrossWorkspace(unittest.TestCase):
    """r56-rebuttal marker bypasses a sei giga (HARD OOS) classification."""

    def test_sei_giga_rebuttal_accepted(self) -> None:
        ws = _workspace("sei")
        body = (
            "Severity: High\n\n"
            "r56-rebuttal: giga path is also reachable from x/evm parallel exec under default config\n\n"
            "- affected_component: giga\n"
        )
        draft = _draft_in(ws, body, filename="sei-giga-rebuttal.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "ok-rebuttal")


# ---------------------------------------------------------------------------
# Tier 10: kill-pattern fixture - polymarket POLY_1271 wallet-type-restricted
# bug. R48 catches the deployment-topology axis; R56 here verifies that when
# the affected_component is itself a non-core auxiliary (e.g. dashboard /
# webapp surface) the R56 axis fails too. This is the cantina-84 sibling
# axis: cantina-84 was R48-killed for POLY_1271 wallet-type restriction; the
# R56 sibling pattern is "the component is auxiliary to the main CLOB
# product".
# ---------------------------------------------------------------------------
class TestPolymarketKillPatternSibling(unittest.TestCase):
    """R56 sibling-axis kill: auxiliary script cited as affected_component."""

    def test_auxiliary_scripts_fails_for_polymarket(self) -> None:
        ws = _workspace("polymarket")
        body = (
            "Severity: High\n\n"
            "## Impact\n\nAuxiliary script signs an unintended payload via POLY_1271 path.\n\n"
            "- affected_component: auxiliary-scripts\n"
        )
        draft = _draft_in(ws, body, filename="polymarket-aux-scripts.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-component-is-non-core-for-program")


if __name__ == "__main__":
    unittest.main()
