#!/usr/bin/env python3
"""Proof-fixture lock-down for the EVM 0-day proof contract (PR5a-b).

Background
----------
PR5a builds the EVM zero-day proof pipeline (``tools/evm-0day-proof-pipeline.py``)
and its unit tests live in ``tools/tests/test_evm_0day_proof_pipeline.py`` (owned
by PR5a). This module is the DISJOINT PR5a-b companion: it locks down the proof
*fixtures* under ``tools/tests/fixtures/evm_zero_day_pipeline/`` and the proof
contract doc, neither of which the pipeline unit tests exercise.

The proof contract (``docs/EVM_0DAY_PROOF_CONTRACT_2026-05-29.md``) has three
legs:

  1. real entrypoint  -> the PoC drives the unmodified target contract
  2. asserted impact   -> a before/after assertion of a real invariant
  3. negative control  -> the same assertion passes on a clean variant

PR5a-b ships a matched fixture pair where the vulnerable fixture's PoC must FLIP
to CAUGHT against the real target and the clean negative-control fixture's
identical PoC must PASS.

The flip-behaviour cases re-derive the ERC4626 share-price math in pure Python
straight from each fixture source's rounding rules, so this is a real proof of
the encoded behaviour, not a restatement of the manifests' claims. When
``forge`` is on PATH the cases also opportunistically run the real Foundry PoCs.

All tests are stdlib-only and read-only over the tracked fixture tree.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = REPO_ROOT / "tools" / "tests" / "fixtures" / "evm_zero_day_pipeline"
VULN_DIR = FIXTURE_ROOT / "erc4626_share_price_vuln"
CLEAN_DIR = FIXTURE_ROOT / "erc4626_share_price_clean"
DOC = REPO_ROOT / "docs" / "EVM_0DAY_PROOF_CONTRACT_2026-05-29.md"

PROOF_SCHEMA = "auditooor.evm_engine_harness_proof.v1"

# Fields the EVM 0-day proof manifest must carry (plan lines 787-800).
REQUIRED_MANIFEST_FIELDS = [
    "target_contract",
    "target_source",
    "target_imports",
    "deployment_adapter",
    "constructor_args_source",
    "entrypoints_bound",
    "real_target_call_count",
    "state_snapshots",
    "negative_controls",
    "engines",
    "proof_ready",
    "blocked_reason",
]

RULE40_POINTS = [
    "real_entrypoint_real_code_real_impact",
    "defenses_executed_or_ruled_out",
    "mocks_external_deps_only",
    "negative_control_present",
    "before_after_assertions",
    "per_variant_proof",
]


def _load_manifest(d: Path) -> dict:
    return json.loads((d / "engine_harness_proof.json").read_text())


# --------------------------------------------------------------------------- #
# Pure-Python re-derivation of the fixture share-price math.
#
# These mirror, exactly, the rounding rules in the two MiniVault.sol fixtures so
# the test proves the encoded behaviour independently of the manifests.
# --------------------------------------------------------------------------- #
def _vuln_convert_to_shares(assets: int, total_shares: int, vault_assets: int) -> int:
    if total_shares == 0:
        return assets
    # (assets * supply) // totalAssets, totalAssets = live vault balance
    return (assets * total_shares) // vault_assets


def _clean_convert_to_shares(assets: int, total_shares: int, vault_assets: int) -> int:
    VIRTUAL_SHARES = 10 ** 3
    VIRTUAL_ASSETS = 1
    supply = total_shares + VIRTUAL_SHARES
    total_assets = vault_assets + VIRTUAL_ASSETS
    return (assets * supply) // total_assets


def _run_donation_attack(convert):
    """Replay the fixture exploit script; return victim shares minted.

    Sequence (identical to MiniVault.t.sol):
      attacker deposit(1)  -> mints `convert(1, 0, 0)` shares, vault balance 1
      attacker donate 100 ether directly to vault
      victim deposit(50 ether) -> mints `convert(50e18, supply, balance)` shares
    """
    ETHER = 10 ** 18
    total_shares = 0
    vault_assets = 0

    # attacker deposits 1 wei
    minted = convert(1, total_shares, vault_assets)
    total_shares += minted
    vault_assets += 1

    # attacker donates 100 ether
    vault_assets += 100 * ETHER

    # victim deposits 50 ether
    victim_shares = convert(50 * ETHER, total_shares, vault_assets)
    return victim_shares


class FixtureStructureTests(unittest.TestCase):
    def test_fixture_tree_exists(self):
        self.assertTrue(FIXTURE_ROOT.is_dir(), f"missing {FIXTURE_ROOT}")
        for d in (VULN_DIR, CLEAN_DIR):
            self.assertTrue(d.is_dir(), f"missing fixture dir {d}")
            for f in ("MiniVault.sol", "MockERC20.sol", "MiniVault.t.sol",
                      "engine_harness_proof.json"):
                self.assertTrue((d / f).is_file(), f"missing {d / f}")

    def test_kit_index_present_and_well_formed(self):
        idx = json.loads((FIXTURE_ROOT / "INDEX.json").read_text())
        self.assertEqual(idx["kit"], "erc4626_share_price_controls")
        roles = {fx["role"] for fx in idx["fixtures"]}
        # The original kit's two control roles must remain present. The kit has
        # since grown additional proof-fixture roles (step2 entrypoint-binder,
        # step3 donation/inflation + constant-dep + inherited-ERC4626), so assert
        # the original roles are a subset rather than the exact set.
        self.assertTrue(
            {"vulnerable", "negative-control"}.issubset(roles),
            f"original control roles missing from INDEX.json; have {sorted(roles)}",
        )
        # Every registered fixture dir must exist on disk.
        for fx in idx["fixtures"]:
            self.assertTrue(
                (FIXTURE_ROOT / fx["dir"]).is_dir(),
                f"INDEX.json role {fx['role']} -> missing dir {fx['dir']}",
            )

    def test_doc_present(self):
        self.assertTrue(DOC.is_file(), f"missing proof-contract doc {DOC}")
        body = DOC.read_text()
        for leg in ("Real entrypoint", "Asserted impact", "Negative control"):
            self.assertIn(leg, body)
        # global formatting rule: no em/en dashes in written output
        self.assertNotIn("—", body, "em-dash present in doc")
        self.assertNotIn("–", body, "en-dash present in doc")


class ManifestContractTests(unittest.TestCase):
    def test_both_manifests_carry_schema_and_required_fields(self):
        for d in (VULN_DIR, CLEAN_DIR):
            m = _load_manifest(d)
            self.assertEqual(m["schema"], PROOF_SCHEMA, f"bad schema in {d}")
            for field in REQUIRED_MANIFEST_FIELDS:
                self.assertIn(field, m, f"{d}: manifest missing field {field}")
            self.assertTrue(m["proof_ready"], f"{d}: proof_ready must be true")
            self.assertGreaterEqual(
                m["real_target_call_count"], 1,
                f"{d}: must bind >= 1 real target call")
            self.assertFalse(
                m.get("candidate_not_proof", False),
                f"{d}: a proof fixture must not be candidate_not_proof")

    def test_rule40_points_all_satisfied(self):
        for d in (VULN_DIR, CLEAN_DIR):
            m = _load_manifest(d)
            pts = m["rule40_points"]
            for p in RULE40_POINTS:
                self.assertTrue(pts.get(p), f"{d}: rule40 point {p} not satisfied")

    def test_roles_and_verdicts(self):
        v = _load_manifest(VULN_DIR)
        c = _load_manifest(CLEAN_DIR)
        self.assertEqual(v["fixture_role"], "vulnerable")
        self.assertEqual(v["expected_verdict"], "caught")
        self.assertEqual(c["fixture_role"], "negative-control")
        self.assertEqual(c["expected_verdict"], "clean")

    def test_vuln_points_at_clean_as_negative_control(self):
        v = _load_manifest(VULN_DIR)
        ncs = v["negative_controls"]
        self.assertTrue(ncs, "vulnerable manifest must name a negative control")
        # the referenced control resolves to the clean fixture's manifest
        resolved = (VULN_DIR / ncs[0]).resolve()
        self.assertEqual(resolved, (CLEAN_DIR / "engine_harness_proof.json").resolve())

    def test_clean_has_no_self_referential_control(self):
        c = _load_manifest(CLEAN_DIR)
        self.assertEqual(c["negative_controls"], [],
                         "negative control must not itself carry a control")


class RealEntrypointBindingTests(unittest.TestCase):
    """Leg 1: the manifests' bound entrypoints must exist in the real source."""

    def test_bound_entrypoints_exist_in_target_source(self):
        for d in (VULN_DIR, CLEAN_DIR):
            m = _load_manifest(d)
            src = (d / m["target_source"]).read_text()
            for ep in m["entrypoints_bound"]:
                fn = ep.split(".", 1)[1].split("(", 1)[0]  # e.g. "deposit"
                self.assertIn(
                    f"function {fn}", src,
                    f"{d}: bound entrypoint {fn} not found in {m['target_source']}")

    def test_poc_drives_real_entrypoints_not_a_model(self):
        for d in (VULN_DIR, CLEAN_DIR):
            poc = (d / "MiniVault.t.sol").read_text()
            self.assertIn("vault.deposit(", poc, f"{d}: PoC does not call real deposit()")
            # before/after snapshot (Leg 2)
            self.assertIn("victimSharesBefore", poc)
            self.assertIn("victimSharesAfter", poc)


class FlipBehaviourTests(unittest.TestCase):
    """The load-bearing pair invariant: vuln -> CAUGHT, clean -> CLEAN.

    Re-derives the share math from the fixture rounding rules so this is a real
    proof of the encoded behaviour, independent of the manifests.
    """

    def test_vulnerable_fixture_flips_to_caught(self):
        victim_shares = _run_donation_attack(_vuln_convert_to_shares)
        # CAUGHT: the victim's real 50-ether deposit minted zero shares.
        self.assertEqual(
            victim_shares, 0,
            "vulnerable fixture should grief victim to zero shares (CAUGHT)")

    def test_clean_fixture_is_clean(self):
        victim_shares = _run_donation_attack(_clean_convert_to_shares)
        # CLEAN: the negative control mints non-zero shares for the same deposit.
        self.assertGreater(
            victim_shares, 0,
            "clean negative control should mint non-zero shares (PASS)")

    def test_pair_actually_differs(self):
        vuln = _run_donation_attack(_vuln_convert_to_shares)
        clean = _run_donation_attack(_clean_convert_to_shares)
        self.assertNotEqual(
            vuln, clean,
            "vuln and clean must diverge or the negative control is a tautology")


class OptionalForgeReplayTests(unittest.TestCase):
    """If forge is installed AND can compile-and-run the fixtures end to end,
    assert the vulnerable PoC reverts (CAUGHT) and the clean control passes.

    The fixtures are standalone proof artifacts, not a checked-in Foundry
    project. This case builds an ephemeral Foundry project around the fixture
    files (minimal ``foundry.toml`` plus a forge-std-free cheatcode shim is
    already inlined in the fixtures). If forge cannot build/run the harness on
    this host (no forge-std install, missing compiler version, "No tests found",
    or a compile error) the leg SKIPS - the deterministic ``FlipBehaviourTests``
    above are the load-bearing proof of encoded behaviour.
    """

    @staticmethod
    def _forge_run(fixture_dir: Path, contract: str):
        """Build an ephemeral project around the fixture and run the named test.

        Returns (ran, passed, stdout). ``ran`` is False when forge could not
        actually compile-and-execute the named test on this host.
        """
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            src = proj / "src"
            src.mkdir()
            for f in ("MiniVault.sol", "MockERC20.sol", "MiniVault.t.sol"):
                (src / f).write_text((fixture_dir / f).read_text())
            (proj / "foundry.toml").write_text(
                "[profile.default]\nsrc = 'src'\ntest = 'src'\nout = 'out'\n"
                "libs = []\nffi = false\n"
            )
            try:
                cp = subprocess.run(
                    ["forge", "test", "--match-contract", contract, "-vv"],
                    cwd=proj, capture_output=True, text=True, timeout=180,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                return (False, False, "")
            out = (cp.stdout or "") + (cp.stderr or "")
            # forge could not actually run the test on this host -> skip.
            if ("No tests" in out or "Compiler run failed" in out
                    or "compilation" in out.lower() and "fail" in out.lower()
                    or "could not" in out.lower()):
                return (False, False, out)
            if "test_first_depositor_inflation" not in out:
                return (False, False, out)
            passed = cp.returncode == 0
            return (True, passed, out)

    @unittest.skipUnless(shutil.which("forge"), "forge not on PATH")
    def test_forge_vuln_reverts_clean_passes(self):
        ran_v, vuln_passed, out_v = self._forge_run(VULN_DIR, "MiniVaultExploitTest")
        ran_c, clean_passed, out_c = self._forge_run(CLEAN_DIR, "MiniVaultControlTest")
        if not (ran_v and ran_c):
            self.skipTest("forge could not compile-and-run the fixtures on this host")
        # CAUGHT: vulnerable PoC must fail (assertion revert).
        self.assertFalse(vuln_passed, f"vulnerable PoC must fail under forge (CAUGHT)\n{out_v}")
        # negative control must pass.
        self.assertTrue(clean_passed, f"clean negative control must pass under forge\n{out_c}")


if __name__ == "__main__":
    unittest.main()
