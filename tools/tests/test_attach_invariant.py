#!/usr/bin/env python3
"""PR 110 + PR 203 + PR 203-b — invariant template + attach-invariant CLI smoke tests. Offline."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INVARIANTS_DIR = ROOT / "reference" / "invariants"
TOOL = ROOT / "tools" / "attach-invariant.py"
MANIFEST = INVARIANTS_DIR / "MANIFEST.json"

# PR 203: protocol-family templates
FAMILIES_DIR = ROOT / "tools" / "invariants" / "families"

REQUIRED_SECTIONS = [
    # "# <Title>" is the H1, matched separately
    "## Invariant statement",
    "## Applicability criteria",
    "## Non-applicability warnings",
    "## Candidate witness test",
    "## Attach this invariant to a candidate",
    "## Expected counterexample shape",
    "## Related bug classes",
]

EXPECTED_SLUGS = [
    "conservation",
    "solvency",
    "monotonicity",
    "fee-accrual-bounds",
    "oracle-freshness",
    "access-control-symmetry",
]

# PR 203: each family must ship at least 3 candidate-harness skeletons.
EXPECTED_FAMILY_FILES = {
    "amm": [
        "ConstantProductInvariant.t.sol",
        "DonationAttackResistance.t.sol",
        "LPShareConservation.t.sol",
    ],
    "vault": [
        "SharePriceMonotonicity.t.sol",
        "TotalAssetsMonotonicity.t.sol",
        "RedemptionBounds.t.sol",
    ],
    "lending": [
        "DebtCollateralSolvency.t.sol",
        "OraclePriceDelta.t.sol",
        "LiquidationIncentive.t.sol",
    ],
    # PR 203-b: bridge + governance families close the remaining 2 of 5.
    "bridge": [
        "MessageReplayResistance.t.sol",
        "LockMintBalanceConservation.t.sol",
        "FinalityBeforeWithdraw.t.sol",
    ],
    "governance": [
        "TimelockRespected.t.sol",
        "QuorumEnforced.t.sol",
        "ProposalIdMonotonicity.t.sol",
    ],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(*args):
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
    )


def _write(ws: Path, rel: str, body: str) -> None:
    p = ws / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)


# ---------------------------------------------------------------------------
# PR 110 — generic templates (unchanged)
# ---------------------------------------------------------------------------


class TestInvariantTemplates(unittest.TestCase):
    def test_all_templates_have_required_sections(self):
        for slug in EXPECTED_SLUGS:
            path = INVARIANTS_DIR / f"{slug}.md"
            self.assertTrue(path.exists(), f"missing template: {path}")
            text = path.read_text()
            self.assertRegex(
                text, r"^#\s+\S", f"{slug}.md missing H1 title"
            )
            for section in REQUIRED_SECTIONS:
                self.assertIn(
                    section, text, f"{slug}.md missing section: {section}"
                )

    def test_manifest_parses_and_lists_six(self):
        data = json.loads(MANIFEST.read_text())
        self.assertEqual(data["schema_version"], 1)
        slugs = [t["slug"] for t in data["templates"]]
        self.assertEqual(sorted(slugs), sorted(EXPECTED_SLUGS))
        for t in data["templates"]:
            self.assertIn("title", t)
            self.assertIn("path", t)
            self.assertIn("related_bug_classes", t)
            self.assertTrue((INVARIANTS_DIR / t["path"]).exists())


class TestAttachInvariantCLI(unittest.TestCase):
    def test_happy_path_writes_substituted_file(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            res = _run(str(ws), "--template", "conservation", "--contract", "MyVault")
            self.assertEqual(res.returncode, 0, res.stderr)
            dest = ws / "poc-tests" / "invariants" / "InvariantConservation.t.sol"
            self.assertTrue(dest.exists(), "output file not written")
            body = dest.read_text()
            self.assertIn("MyVault", body)
            self.assertNotIn("{CONTRACT}", body)
            self.assertIn("invariant_", body)
            self.assertIn(f"wrote {dest}", res.stdout)

    def test_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            r1 = _run(str(ws), "--template", "conservation", "--contract", "MyVault")
            self.assertEqual(r1.returncode, 0)
            r2 = _run(str(ws), "--template", "conservation", "--contract", "MyVault")
            self.assertNotEqual(r2.returncode, 0)
            self.assertIn("refusing to overwrite", r2.stderr)

    def test_bad_slug_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as td:
            res = _run(td, "--template", "bogus-slug")
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("unknown template slug", res.stderr)

    def test_help_runs(self):
        res = _run("--help")
        self.assertEqual(res.returncode, 0)
        self.assertIn("--template", res.stdout)


# ---------------------------------------------------------------------------
# PR 203 — protocol-family catalog + CLI
# ---------------------------------------------------------------------------


class TestFamilyCatalog(unittest.TestCase):
    def test_each_family_dir_has_expected_files(self):
        for fam, files in EXPECTED_FAMILY_FILES.items():
            d = FAMILIES_DIR / fam
            self.assertTrue(d.is_dir(), f"missing family dir: {d}")
            for name in files:
                p = d / name
                self.assertTrue(p.exists(), f"missing family file: {p}")

    def test_every_family_template_has_truth_audit_header(self):
        """v2 hard rule: every family skeleton must flag itself as a
        candidate harness, not proof."""
        for fam, files in EXPECTED_FAMILY_FILES.items():
            for name in files:
                p = FAMILIES_DIR / fam / name
                text = p.read_text()
                self.assertIn(
                    "CANDIDATE HARNESS",
                    text,
                    f"{p} missing CANDIDATE HARNESS truth-audit header",
                )
                self.assertIn(
                    "NOT PROOF",
                    text,
                    f"{p} missing NOT PROOF marker",
                )
                self.assertIn(
                    "invariant_",
                    text,
                    f"{p} missing invariant_ function stub",
                )

    def test_every_bridge_template_has_truth_audit_header(self):
        """PR 203-b: dedicated per-family audit so a silently renamed
        or truncated header in any bridge file fails loudly."""
        for name in EXPECTED_FAMILY_FILES["bridge"]:
            p = FAMILIES_DIR / "bridge" / name
            self.assertTrue(p.exists(), f"missing bridge template: {p}")
            text = p.read_text()
            self.assertIn(
                "CANDIDATE HARNESS — NOT PROOF",
                text,
                f"{p} missing full 'CANDIDATE HARNESS — NOT PROOF' header",
            )
            self.assertIn(
                "invariant_",
                text,
                f"{p} missing invariant_ function stub",
            )

    def test_every_governance_template_has_truth_audit_header(self):
        """PR 203-b: same header audit scoped to the governance family."""
        for name in EXPECTED_FAMILY_FILES["governance"]:
            p = FAMILIES_DIR / "governance" / name
            self.assertTrue(p.exists(), f"missing governance template: {p}")
            text = p.read_text()
            self.assertIn(
                "CANDIDATE HARNESS — NOT PROOF",
                text,
                f"{p} missing full 'CANDIDATE HARNESS — NOT PROOF' header",
            )
            self.assertIn(
                "invariant_",
                text,
                f"{p} missing invariant_ function stub",
            )


class TestFamilyAttachCLI(unittest.TestCase):
    def test_family_amm_copies_three_files(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            res = _run(str(ws), "--family", "amm")
            self.assertEqual(res.returncode, 0, res.stderr)
            out = ws / "poc-tests" / "invariants"
            for name in EXPECTED_FAMILY_FILES["amm"]:
                self.assertTrue((out / name).exists(), f"missing {name}")
            # truth-audit header must survive the copy
            body = (out / "ConstantProductInvariant.t.sol").read_text()
            self.assertIn("CANDIDATE HARNESS", body)
            self.assertIn("NOT PROOF", body)

    def test_family_vault_copies_three_files(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            res = _run(str(ws), "--family", "vault")
            self.assertEqual(res.returncode, 0, res.stderr)
            out = ws / "poc-tests" / "invariants"
            for name in EXPECTED_FAMILY_FILES["vault"]:
                self.assertTrue((out / name).exists(), f"missing {name}")

    def test_family_lending_copies_three_files(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            res = _run(str(ws), "--family", "lending")
            self.assertEqual(res.returncode, 0, res.stderr)
            out = ws / "poc-tests" / "invariants"
            for name in EXPECTED_FAMILY_FILES["lending"]:
                self.assertTrue((out / name).exists(), f"missing {name}")

    # --- PR 203-b ----------------------------------------------------

    def test_family_bridge_copies_three_files(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            res = _run(str(ws), "--family", "bridge")
            self.assertEqual(res.returncode, 0, res.stderr)
            out = ws / "poc-tests" / "invariants"
            for name in EXPECTED_FAMILY_FILES["bridge"]:
                self.assertTrue((out / name).exists(), f"missing {name}")
            # truth-audit header must survive the copy
            body = (out / "MessageReplayResistance.t.sol").read_text()
            self.assertIn("CANDIDATE HARNESS", body)
            self.assertIn("NOT PROOF", body)

    def test_family_governance_copies_three_files(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            res = _run(str(ws), "--family", "governance")
            self.assertEqual(res.returncode, 0, res.stderr)
            out = ws / "poc-tests" / "invariants"
            for name in EXPECTED_FAMILY_FILES["governance"]:
                self.assertTrue((out / name).exists(), f"missing {name}")
            body = (out / "TimelockRespected.t.sol").read_text()
            self.assertIn("CANDIDATE HARNESS", body)
            self.assertIn("NOT PROOF", body)

    def test_family_with_contract_substitutes_placeholder(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            res = _run(str(ws), "--family", "amm", "--contract", "MyPair")
            self.assertEqual(res.returncode, 0, res.stderr)
            body = (
                ws
                / "poc-tests"
                / "invariants"
                / "ConstantProductInvariant.t.sol"
            ).read_text()
            self.assertIn("MyPair", body)
            self.assertNotIn("{ContractName}", body)

    def test_family_without_contract_leaves_placeholder(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            res = _run(str(ws), "--family", "vault")
            self.assertEqual(res.returncode, 0, res.stderr)
            body = (
                ws
                / "poc-tests"
                / "invariants"
                / "SharePriceMonotonicity.t.sol"
            ).read_text()
            self.assertIn("{ContractName}", body)

    def test_family_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            r1 = _run(str(ws), "--family", "amm")
            self.assertEqual(r1.returncode, 0, r1.stderr)
            r2 = _run(str(ws), "--family", "amm")
            self.assertNotEqual(r2.returncode, 0)
            self.assertIn("refusing to overwrite", r2.stderr)

    def test_family_unknown_errors_cleanly(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            res = _run(str(ws), "--family", "elephant")
            self.assertEqual(res.returncode, 2)
            self.assertIn("unknown family", res.stderr)
            # Must not silently create the output directory with files.
            out = ws / "poc-tests" / "invariants"
            if out.exists():
                self.assertEqual(
                    list(out.iterdir()), [], "no files should be written"
                )


class TestSuggestFamilyCLI(unittest.TestCase):
    def test_suggest_family_ranks_amm_on_swap_signatures(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(
                ws,
                "src/Pool.sol",
                "pragma solidity ^0.8.0;\n"
                "contract Pool {\n"
                "    uint112 reserve0; uint112 reserve1;\n"
                "    function getReserves() external view "
                "returns (uint112,uint112,uint32){}\n"
                "    function swap(uint a, uint b, address to) external {}\n"
                "    function addLiquidity(uint a, uint b) external {}\n"
                "    function removeLiquidity(uint l) external {}\n"
                "}\n",
            )
            res = _run(str(ws), "--suggest-family")
            self.assertEqual(res.returncode, 0, res.stderr)
            # amm must be listed first in the ranked output
            lines = [
                line.strip()
                for line in res.stdout.splitlines()
                if "score=" in line
            ]
            self.assertTrue(lines, f"no score lines: {res.stdout}")
            self.assertTrue(
                lines[0].startswith("amm"),
                f"amm should rank first, got: {lines}",
            )
            self.assertIn("best guess: amm", res.stdout)

    def test_suggest_family_ranks_vault_on_erc4626(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(
                ws,
                "src/MyVault.sol",
                "pragma solidity ^0.8.0;\n"
                "contract MyVault {\n"
                "    function convertToShares(uint a) external view "
                "returns (uint){}\n"
                "    function convertToAssets(uint s) external view "
                "returns (uint){}\n"
                "    function totalAssets() external view returns (uint){}\n"
                "    function deposit(uint a, address receiver) external "
                "returns (uint){}\n"
                "    function redeem(uint s, address receiver, address owner)"
                " external returns (uint){}\n"
                "}\n",
            )
            res = _run(str(ws), "--suggest-family")
            self.assertEqual(res.returncode, 0, res.stderr)
            lines = [
                line.strip()
                for line in res.stdout.splitlines()
                if "score=" in line
            ]
            self.assertTrue(
                lines[0].startswith("vault"),
                f"vault should rank first, got: {lines}",
            )
            self.assertIn("best guess: vault", res.stdout)

    def test_suggest_family_ranks_bridge_on_bridge_signatures(self):
        """PR 203-b regression: a typo in the bridge scoring patterns
        will stop processMessage-style source from ranking bridge first,
        and this test will catch it."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(
                ws,
                "src/Bridge.sol",
                "pragma solidity ^0.8.0;\n"
                "contract Bridge {\n"
                "    function processMessage(bytes32 id, bytes calldata p)"
                " external {}\n"
                "    function sendMessage(address to, bytes calldata p)"
                " external {}\n"
                "    function bridgeFromChain(uint256 chainId, "
                "bytes calldata p) external {}\n"
                "}\n",
            )
            res = _run(str(ws), "--suggest-family")
            self.assertEqual(res.returncode, 0, res.stderr)
            lines = [
                line.strip()
                for line in res.stdout.splitlines()
                if "score=" in line
            ]
            self.assertTrue(lines, f"no score lines: {res.stdout}")
            self.assertTrue(
                lines[0].startswith("bridge"),
                f"bridge should rank first, got: {lines}",
            )
            self.assertIn("best guess: bridge", res.stdout)

    def test_suggest_family_ranks_governance_on_governor_signatures(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(
                ws,
                "src/Governor.sol",
                "pragma solidity ^0.8.0;\n"
                "contract MyGovernor {\n"
                "    function propose(address[] calldata targets, "
                "bytes[] calldata data) external returns (uint256){}\n"
                "    function castVote(uint256 id, uint8 support)"
                " external {}\n"
                "    function queue(uint256 id) external {}\n"
                "    function quorum(uint256 block_) external view "
                "returns (uint256){}\n"
                "    address public timelock;\n"
                "}\n",
            )
            res = _run(str(ws), "--suggest-family")
            self.assertEqual(res.returncode, 0, res.stderr)
            lines = [
                line.strip()
                for line in res.stdout.splitlines()
                if "score=" in line
            ]
            self.assertTrue(lines, f"no score lines: {res.stdout}")
            self.assertTrue(
                lines[0].startswith("governance"),
                f"governance should rank first, got: {lines}",
            )
            self.assertIn("best guess: governance", res.stdout)

    def test_suggest_family_ranks_lending_on_borrow_liquidate(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(
                ws,
                "src/Comptroller.sol",
                "pragma solidity ^0.8.0;\n"
                "contract Comptroller {\n"
                "    uint public collateralFactorMantissa;\n"
                "    uint public borrowIndex;\n"
                "    function borrow(uint a) external {}\n"
                "    function repayBorrow(uint a) external {}\n"
                "    function liquidateBorrow(address b, uint a, "
                "address c) external {}\n"
                "    function accrueInterest() external {}\n"
                "    function getAccountLiquidity(address a) external view"
                " returns (uint,uint,uint){}\n"
                "}\n",
            )
            res = _run(str(ws), "--suggest-family")
            self.assertEqual(res.returncode, 0, res.stderr)
            lines = [
                line.strip()
                for line in res.stdout.splitlines()
                if "score=" in line
            ]
            self.assertTrue(
                lines[0].startswith("lending"),
                f"lending should rank first, got: {lines}",
            )

    def test_suggest_family_no_confident_match_on_empty_src(self):
        """Cannot-judge behavior: every family scores zero → no pick."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            # Create an empty src/ with a contract that has no family hooks
            _write(
                ws,
                "src/Plain.sol",
                "pragma solidity ^0.8.0;\n"
                "contract Plain { uint public x; "
                "function set(uint v) external { x = v; } }\n",
            )
            res = _run(str(ws), "--suggest-family")
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("no confident suggestion", res.stdout)
            # must still list every family so the user sees scores
            for fam in ("amm", "vault", "lending", "bridge", "governance"):
                self.assertIn(fam, res.stdout)

    def test_list_families_works_without_workspace(self):
        res = _run("--list-families")
        self.assertEqual(res.returncode, 0, res.stderr)
        for fam in ("amm", "vault", "lending", "bridge", "governance"):
            self.assertIn(fam, res.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
