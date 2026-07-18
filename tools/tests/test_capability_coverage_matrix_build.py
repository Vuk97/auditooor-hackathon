#!/usr/bin/env python3
"""Tests for tools/capability-coverage-matrix-build.py."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "capability-coverage-matrix-build.py"
_spec = importlib.util.spec_from_file_location("capability_coverage_matrix_build", _TOOL)
mod = importlib.util.module_from_spec(_spec)
sys.modules["capability_coverage_matrix_build"] = mod
_spec.loader.exec_module(mod)


class TestCapabilityCoverageMatrixBuild(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "ws"
        self.ws.mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()

    def test_scope_parser_ignores_target_and_oos_sections(self):
        (self.ws / "SCOPE.md").write_text(
            "\n".join([
                "# Example - Audit Scope",
                "",
                "## Target",
                "- Repo: https://example.test/protocol",
                "- Audit pin: `abc123`",
                "",
                "## Asset classes",
                "- Smart Contract: all `src/**/*.sol`",
                "",
                "## In scope (src/ only)",
                "- `src/Core.sol` - core protocol",
                "- `src/periphery/` - helper contracts",
                "",
                "## Out of scope",
                "- test/, certora/, lib/",
                "",
                "## Token safety assumptions",
                "- Token must not re-enter.",
            ]) + "\n"
        )

        clusters = mod._parse_scope_clusters(self.ws)

        self.assertEqual(clusters, [
            "Smart Contract: all src/**/*.sol",
            "src/Core.sol",
            "src/periphery/",
        ])

    def test_title_scope_heading_does_not_hide_bullets(self):
        (self.ws / "SCOPE.md").write_text(
            "\n".join([
                "# Audit Scope",
                "- src/Core.sol",
                "- src/periphery/",
            ]) + "\n"
        )

        self.assertEqual(mod._parse_scope_clusters(self.ws), ["src/Core.sol", "src/periphery/"])

    def test_nested_subsections_under_in_scope_section_inherit_scope(self):
        # Product-group subsections (### Vault V2) nested under an in-scope
        # section (## In-scope repos) are still in-scope: their repo bullets
        # MUST be captured. Preamble metadata bullets (Pin policy:) MUST NOT.
        # Regression for the morpho cluster-coverage false-red where every real
        # repo cluster was dropped, leaving only 2 preamble metadata bullets.
        (self.ws / "SCOPE.md").write_text(
            "\n".join([
                "# SCOPE - Morpho",
                "- Pin policy: each repo at its exact commit",
                "- Max reward: $2,500,000",
                "## In-scope repos + pins",
                "### Vault V2",
                "- vault-v2 @ deadbeef",
                "### Morpho Blue",
                "- morpho-blue @ cafe1234",
                "## OUT OF SCOPE",
                "### Known Issues",
                "- documented risks are out of scope",
            ]) + "\n"
        )
        clusters = mod._parse_scope_clusters(self.ws)
        self.assertIn("vault-v2 @ deadbeef", clusters)
        self.assertIn("morpho-blue @ cafe1234", clusters)
        # preamble metadata + OOS subsection bullets excluded
        self.assertFalse(any("pin policy" in c.lower() for c in clusters), clusters)
        self.assertFalse(any("max reward" in c.lower() for c in clusters), clusters)
        self.assertFalse(any("out of scope" in c.lower() for c in clusters), clusters)

    def test_matrix_uses_sidecar_tokens_for_real_in_scope_clusters(self):
        (self.ws / "SCOPE.md").write_text(
            "\n".join([
                "# Scope",
                "",
                "## In scope",
                "- `src/Core.sol` - core protocol",
                "- `src/periphery/` - helper contracts",
            ]) + "\n"
        )
        sidecars = self.ws / "hunt_findings_sidecars"
        sidecars.mkdir()
        (sidecars / "src-core-sol.json").write_text("{}")

        matrix_text, rows = mod.build_matrix(self.ws)

        self.assertIn("| src/Core.sol | COVERED |", matrix_text)
        self.assertIn("| src/periphery/ | DARK |", matrix_text)
        self.assertEqual(rows[0]["status"], "COVERED")
        self.assertEqual(rows[1]["status"], "DARK")

    def test_matrix_credits_existing_curated_coverage_crosswalk(self):
        (self.ws / "SCOPE.md").write_text(
            "\n".join([
                "# Scope",
                "",
                "## In scope",
                "- `src/Core.sol` - core protocol",
                "- `src/periphery/` - helper contracts",
                "",
                "## Out of scope",
                "- test/",
            ]) + "\n"
        )
        (self.ws / "PROJECT_CAPABILITY_COVERAGE_MATRIX.md").write_text(
            "\n".join([
                "| Cluster | Coverage |",
                "|---|---|",
                "| src/core.sol` | coded forge PoC sidecar C01 |",
                "| src/periphery/` | entrypoints probed in sidecars P01-P05 |",
                "| test/ | DARK |",
            ]) + "\n"
        )

        matrix_text, rows = mod.build_matrix(self.ws)

        self.assertIn("| src/Core.sol | COVERED |", matrix_text)
        self.assertIn("| src/periphery/ | COVERED |", matrix_text)
        self.assertEqual([r["status"] for r in rows], ["COVERED", "COVERED"])

    def test_matrix_rejects_external_uncovered_variants(self):
        (self.ws / "SCOPE.md").write_text(
            "\n".join([
                "# Scope",
                "",
                "## In scope",
                "- src/Core.sol",
                "- src/periphery/",
                "- src/libraries/",
                "- src/interfaces/",
            ]) + "\n"
        )
        (self.ws / "PROJECT_CAPABILITY_COVERAGE_MATRIX.md").write_text(
            "\n".join([
                "| Cluster | Coverage |",
                "|---|---|",
                "| src/Core.sol | UNCOVERED |",
                "| src/periphery/ | not covered |",
                "| src/libraries/ | no coverage |",
                "| src/interfaces/ | gap |",
            ]) + "\n"
        )

        matrix_text, rows = mod.build_matrix(self.ws)

        self.assertEqual([r["status"] for r in rows], ["DARK", "DARK", "DARK", "DARK"])
        self.assertEqual(matrix_text.count("| DARK |"), 4)

    def test_numbered_asset_table_uses_asset_column_and_repo_audit_logs(self):
        (self.ws / "SCOPE.md").write_text(
            "\n".join([
                "# dYdX Bug Bounty - Audit Scope",
                "",
                "## In-scope assets",
                "",
                "| # | Asset | Repo |",
                "|---|---|---|",
                "| 1 | v4-chain (protocol) | `dydxprotocol/v4-chain/tree/main/protocol` |",
                "| 5 | v4-native-mobile | `dydxprotocol/v4-native-mobile` |",
            ]) + "\n"
        )
        audit_logs = self.ws / "repos" / ".audit_logs" / "v4-native-mobile"
        audit_logs.mkdir(parents=True)
        (audit_logs / "status.log").write_text("ok\n")

        matrix_text, rows = mod.build_matrix(self.ws)

        self.assertNotIn("| # | DARK |", matrix_text)
        self.assertNotIn("| 5 | DARK |", matrix_text)
        self.assertEqual([r["cluster"] for r in rows], ["v4-chain (protocol)", "v4-native-mobile"])
        self.assertEqual([r["status"] for r in rows], ["DARK", "COVERED"])


class TestScopeMetadataAndImpactSections(unittest.TestCase):
    """Generic fixes (hyperlane): bold-key metadata bullets, "vulnerability
    classes / impacts" sections, and function-coverage crediting."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "ws"
        (self.ws / ".auditooor").mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()

    def test_bold_key_metadata_bullets_excluded(self):
        # Header metadata written as **Key**: value (markdown bold) must not
        # become DARK cluster rows; impact-class section is the rubric axis.
        (self.ws / "SCOPE.md").write_text("\n".join([
            "# SCOPE - Example",
            "- **Program**: https://immunefi.com/bug-bounty/x/scope/#top",
            "- **Platform**: Immunefi",
            "- **Category**: Smart Contract / Solidity",
            "- **Max bounty**: $2,500,000 | PoC required | KYC required",
            "- **Source repo**: https://github.com/x/y",
            "- **Audit PIN**: 644ebcdad9d6482c1ac4a2d65ad2d50029b30806",
            "",
            "## In-scope source",
            "- `Mailbox.sol`",
            "- `client/`",
            "",
            "## In-scope vulnerability classes (mapped to impacts; rubric in SEVERITY.md)",
            "- Replay / double-process of a delivered message (Critical)",
            "- Merkle tree / checkpoint accumulator corruption (Critical/High)",
        ]) + "\n")
        clusters = mod._parse_scope_clusters(self.ws)
        # only the two real code clusters survive
        self.assertEqual(clusters, ["Mailbox.sol", "client/"])
        for leaked in ("Program", "Platform", "Category", "Max bounty",
                       "Source repo", "Audit PIN", "Replay", "Merkle"):
            self.assertFalse(any(leaked.lower() in c.lower() for c in clusters),
                             f"metadata/impact leaked: {leaked}")

    def test_function_coverage_credits_file_level_cluster(self):
        # Mailbox.sol cluster is COVERED via the authoritative function-coverage
        # ledger even though no hunt sidecar token exists (the .sol filename stem
        # was previously dropped by the dot-isalnum filter).
        (self.ws / "SCOPE.md").write_text(
            "# SCOPE\n## In-scope source\n- `Mailbox.sol`\n- `client/`\n", encoding="utf-8")
        (self.ws / ".auditooor" / "function_coverage_completeness.json").write_text(
            '{"functions": ['
            '{"file": "src/solidity/contracts/Mailbox.sol", "name": "dispatch"},'
            '{"file": "src/solidity/contracts/client/GasRouter.sol", "name": "quoteGasPayment"}'
            ']}', encoding="utf-8")
        toks = mod._function_coverage_tokens(self.ws)
        self.assertIn("mailbox", toks)
        self.assertIn("client", toks)
        self.assertTrue(mod._is_covered("Mailbox.sol", toks))
        self.assertTrue(mod._is_covered("client/", toks))

    def test_family_ledger_credits_oz_std_cluster(self):
        # upgrade/ (OZ-std, ruled out by the family ledger) is credited from
        # FAMILY_COVERAGE.md path tokens.
        (self.ws / "FAMILY_COVERAGE.md").write_text(
            "| 10 | PausableIsm + upgrade | isms/PausableIsm.sol, upgrade/ProxyAdmin.sol | "
            "Low/OOS | DONE | OZ-std ruled out |\n", encoding="utf-8")
        toks = mod._family_ledger_tokens(self.ws)
        self.assertIn("upgrade", toks)
        self.assertTrue(mod._is_covered("upgrade/", toks))


class TestDeploymentAddressBulletNotCluster(unittest.TestCase):
    """A SCOPE.md deployed-address annotation bullet must NOT become a phantom DARK
    cluster (axelar-sc 2026-07-12: 'In-scope tokens (deployed): AXL 0x..., axlUSDC on
    Avax/BSC/...' was mis-parsed into a permanently-DARK 'In-scope tokens' cluster)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "ws"
        self.ws.mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()

    def test_helper_flags_deployed_address_annotation(self):
        self.assertTrue(mod._is_deployment_address_bullet(
            "In-scope tokens (deployed): AXL 0x4677..E5f3, axlUSDC on Avax/BSC/Fantom."))
        self.assertTrue(mod._is_deployment_address_bullet(
            "Gateway (deployed): 0xabcdef01 on Ethereum"))

    def test_helper_never_false_drops_real_cluster(self):
        # a genuine code-module cluster carries no on-chain address -> never dropped
        self.assertFalse(mod._is_deployment_address_bullet(
            "interchain-token-service: ITS + Interchain Token Factory"))
        self.assertFalse(mod._is_deployment_address_bullet("`src/Core.sol` - core"))
        # deployment-shaped label but NO address -> not treated as address annotation
        self.assertFalse(mod._is_deployment_address_bullet(
            "In-scope tokens: the wrapped ERC20 set"))

    def test_scope_parser_drops_deployed_token_bullet_keeps_repos(self):
        (self.ws / "SCOPE.md").write_text("\n".join([
            "# Axelar SC Scope",
            "## In-scope repos",
            "- interchain-token-service - ITS + factory",
            "- axelar-cgp-solidity - EVM Gateway",
            "- In-scope tokens (deployed): AXL 0x4677..E5f3, axlUSDC on Avax/BSC.",
        ]), encoding="utf-8")
        clusters = mod._parse_scope_clusters(self.ws)
        self.assertIn("interchain-token-service", clusters)
        self.assertIn("axelar-cgp-solidity", clusters)
        self.assertNotIn("In-scope tokens", clusters)


if __name__ == "__main__":
    unittest.main()


class ProsePlaceholderExclusionTest(unittest.TestCase):
    """NUVA 2026-06-30: a wrapped continuation line of a multi-line SCOPE.md bullet
    (prose sentence) and a literal '... placeholder' bullet must NOT become phantom
    DARK clusters. Real clusters (repos, deployed addresses, prior-audits, paths) stay."""

    def test_prose_fragment_excluded(self):
        self.assertTrue(mod._is_scope_metadata_bullet(
            "backward incomplete-fix), and verify deployed bytecode matches the pin before filing."))

    def test_placeholder_excluded(self):
        self.assertTrue(mod._is_scope_metadata_bullet("Primacy of Impact placeholder"))

    def test_prior_audit_firm_excluded(self):
        for ref in ("Sherlock ProvLabs Collaborative 2025-12-17",
                    "Halborn vault cosmos+evm a53e2b"):
            self.assertTrue(mod._is_scope_metadata_bullet(ref), f"{ref!r} is a prior-audit ref")

    def test_real_clusters_kept(self):
        for keep in ("ProvLabs/vault", "src/vault/keeper",
                     "Ethereum ETH_NVPRIME_VAULT: 0xC360e625F19A7ea47e47810B13E386221d5187D1",
                     "src/vault/keeper"):
            self.assertFalse(mod._is_scope_metadata_bullet(keep), f"{keep!r} must be kept")
