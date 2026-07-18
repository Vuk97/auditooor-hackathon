#!/usr/bin/env python3
"""GEN-4A - vault max/preview-helper vs paired-exit rounding-consistency screen.

Non-vacuous: every POSITIVE asserts a specific (group, deviating-fn,
paired-fn, opposite-direction) hit and every NEGATIVE asserts the ABSENCE. The
mutation-witness pair proves the cross-function consistency predicate has TEETH
on REAL fleet code:

  OpenZeppelin ERC4626.sol (morpho fleet): the real `maxWithdraw`,
  `previewRedeem`, and `redeem` all compute assets<-shares and round
  `Math.Rounding.Floor` (DOWN). The CONSISTENT original is SILENT; the same file
  with ONLY `maxWithdraw` flipped Floor->Ceil (the recipient-favoring direction)
  FIRES - it now rounds UP against previewRedeem's DOWN on the SAME conserved
  pair. An equivalent mutant that kept the direction would leave the positive
  un-fired, so the consistency predicate is not vacuous.

Covered axes:
  (i)   preview vs exit that INDEPENDENTLY round opposite on the same conserved
        pair -> FIRES (the core two-function join).
  (ii)  the OZ shape where the exit DELEGATES to its preview (single detectable
        direction in the group) -> SILENT (cannot be inconsistent).
  (iii) both members round the SAME direction -> SILENT (consistent).
  (iv)  a lone helper with no paired member in the group -> SILENT.
  (v)   REAL-FLEET mutation pair (OZ maxWithdraw Floor silent vs flipped Ceil
        fire), byte-identical restore.
  (vi)  Rust / Go vault analogs (max_withdraw / preview vs the exit).
  (vii) advisory-first: exit 0 by default, non-zero only under --strict/env.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "vault-maxexit-rounding-screen.py"
# Real OZ 4626 on the morpho fleet (mutation-witness target).
_OZ = Path("/Users/wolf/audits/morpho/src/metamorpho/lib/openzeppelin-contracts"
           "/contracts/token/ERC20/extensions/ERC4626.sol")


def _load():
    spec = importlib.util.spec_from_file_location("gen_4a_screen", TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["gen_4a_screen"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load()


def _scan(body: str, name: str = "Vault.sol"):
    return MOD.scan_file(Path(name), name, file_text=textwrap.dedent(body))


class Gen4ATests(unittest.TestCase):
    # ------------------------------------------------------------------
    # (i) POSITIVE - preview vs exit rounding OPPOSITE on the same pair.
    # ------------------------------------------------------------------
    def test_preview_vs_exit_opposite_fires(self):
        rows = _scan("""
            contract V {
                function previewWithdraw(uint256 a) public view returns (uint256) {
                    return _toShares(a, Math.Rounding.Ceil);
                }
                function withdraw(uint256 a) public returns (uint256) {
                    uint256 shares = _toShares(a, Math.Rounding.Floor);
                    _burn(msg.sender, shares);
                    return shares;
                }
            }
            """)
        self.assertTrue(rows, "opposite preview/withdraw rounding must fire")
        r = rows[0]
        self.assertEqual(r["capability"], "GEN_4A")
        self.assertEqual(r["schema"],
                         "auditooor.vault_maxexit_rounding_hypotheses.v1")
        self.assertEqual(r["conserved_pair"], "shares<-assets")
        self.assertEqual({r["helper_rounding"], r["paired_rounding"]},
                         {"up", "down"})
        self.assertEqual({r["helper_fn"], r["paired_fn"]},
                         {"previewWithdraw", "withdraw"})
        # withdraw is a state-changing exit carrying an explicit token, and the
        # deviating side is a helper -> high candidate.
        self.assertEqual(r["severity"], "high")

    # ------------------------------------------------------------------
    # (ii) NEGATIVE - exit DELEGATES to preview (single detectable dir).
    # ------------------------------------------------------------------
    def test_exit_delegates_to_preview_silent(self):
        rows = _scan("""
            contract V {
                function previewWithdraw(uint256 a) public view returns (uint256) {
                    return _toShares(a, Math.Rounding.Ceil);
                }
                function withdraw(uint256 a) public returns (uint256) {
                    uint256 shares = previewWithdraw(a);
                    _burn(msg.sender, shares);
                    return shares;
                }
            }
            """)
        self.assertEqual(rows, [],
                         "delegating exit (single detectable dir) is silent")

    # ------------------------------------------------------------------
    # (iii) NEGATIVE - both members round the SAME direction -> consistent.
    # ------------------------------------------------------------------
    def test_consistent_same_direction_silent(self):
        rows = _scan("""
            contract V {
                function previewWithdraw(uint256 a) public view returns (uint256) {
                    return _toShares(a, Math.Rounding.Ceil);
                }
                function withdraw(uint256 a) public returns (uint256) {
                    uint256 shares = _toShares(a, Math.Rounding.Ceil);
                    _burn(msg.sender, shares);
                    return shares;
                }
            }
            """)
        self.assertEqual(rows, [], "same-direction rounding must be silent")

    # ------------------------------------------------------------------
    # (iv) NEGATIVE - a lone helper with no paired group member -> silent.
    # ------------------------------------------------------------------
    def test_lone_helper_no_pair_silent(self):
        rows = _scan("""
            contract V {
                function maxWithdraw(address o) public view returns (uint256) {
                    return _toAssets(balanceOf(o), Math.Rounding.Ceil);
                }
            }
            """)
        self.assertEqual(rows, [], "lone helper with no paired member is silent")

    # ------------------------------------------------------------------
    # NEGATIVE - non-vault rounding math (no vault fns) -> silent.
    # ------------------------------------------------------------------
    def test_non_vault_math_silent(self):
        rows = _scan("""
            contract Price {
                function quote(uint256 a) public view returns (uint256) {
                    return a.mulDivUp(rate, 1e18);
                }
                function unit(uint256 a) public view returns (uint256) {
                    return a.mulDivDown(rate, 1e18);
                }
            }
            """)
        self.assertEqual(rows, [], "non-vault rounding math must be silent")

    # ------------------------------------------------------------------
    # NEGATIVE - masking: an opposite token inside a comment/string ignored.
    # ------------------------------------------------------------------
    def test_masking_ignores_comment_and_string(self):
        rows = _scan("""
            contract V {
                function previewRedeem(uint256 s) public view returns (uint256) {
                    // could use Math.Rounding.Ceil here but we do not
                    string memory note = "Math.Rounding.Ceil";
                    return _toAssets(s, Math.Rounding.Floor);
                }
                function redeem(uint256 s) public returns (uint256) {
                    uint256 a = _toAssets(s, Math.Rounding.Floor);
                    return a;
                }
            }
            """)
        self.assertEqual(rows, [], "masked opposite token must not fire")

    # ------------------------------------------------------------------
    # POSITIVE - maxWithdraw (assets<-shares) UP vs previewRedeem DOWN.
    # ------------------------------------------------------------------
    def test_maxwithdraw_vs_previewredeem_fires(self):
        rows = _scan("""
            contract V {
                function maxWithdraw(address o) public view returns (uint256) {
                    return _toAssets(balanceOf(o), Math.Rounding.Ceil);
                }
                function previewRedeem(uint256 s) public view returns (uint256) {
                    return _toAssets(s, Math.Rounding.Floor);
                }
            }
            """)
        self.assertTrue(rows, "maxWithdraw up vs previewRedeem down must fire")
        r = rows[0]
        self.assertEqual(r["conserved_pair"], "assets<-shares")
        self.assertEqual(r["function"], "maxWithdraw")  # deviating anchor
        self.assertEqual(r["helper_rounding"], "up")
        self.assertEqual(r["canonical_direction"], "down")

    # ------------------------------------------------------------------
    # NEGATIVE - two DIFFERENT contracts in one file are not cross-matched.
    # ------------------------------------------------------------------
    def test_two_contracts_not_cross_matched(self):
        rows = _scan("""
            contract A {
                function previewWithdraw(uint256 a) public view returns (uint256) {
                    return _toShares(a, Math.Rounding.Ceil);
                }
            }
            contract B {
                function withdraw(uint256 a) public returns (uint256) {
                    return _toShares(a, Math.Rounding.Floor);
                }
            }
            """)
        self.assertEqual(rows, [],
                         "helper in A and exit in B are different vaults")

    # ------------------------------------------------------------------
    # (vi) Rust vault analog: preview_redeem down vs redeem up -> fire.
    # ------------------------------------------------------------------
    def test_rust_analog_fires(self):
        rows = _scan("""
            impl Vault {
                pub fn preview_redeem(&self, shares: u128) -> u128 {
                    mul_div_floor(shares, self.total_assets, self.total_shares)
                }
                pub fn redeem(&mut self, shares: u128) -> u128 {
                    let a = mul_div_ceil(shares, self.total_assets, self.total_shares);
                    a
                }
            }
            """, name="vault.rs")
        self.assertTrue(rows, "rust preview/redeem opposite rounding must fire")
        self.assertEqual(rows[0]["lang"], "rust")

    def test_go_analog_fires(self):
        rows = _scan("""
            func (v *Vault) PreviewRedeem(shares uint64) uint64 {
                return MulDivDown(shares, v.totalAssets, v.totalShares)
            }
            func (v *Vault) Redeem(shares uint64) uint64 {
                return MulDivUp(shares, v.totalAssets, v.totalShares)
            }
            """, name="vault.go")
        self.assertTrue(rows, "go preview/redeem opposite rounding must fire")
        self.assertEqual(rows[0]["lang"], "go")

    # ------------------------------------------------------------------
    # (v) REAL-FLEET MUTATION WITNESS - OZ ERC4626 maxWithdraw.
    # ------------------------------------------------------------------
    @unittest.skipUnless(_OZ.exists(), "OZ fleet 4626 not present")
    def test_real_fleet_original_silent_mutant_fires(self):
        original = _OZ.read_text()
        # consistent original: all assets<-shares helpers round Floor -> SILENT.
        rows0 = MOD.scan_file(_OZ, _OZ.name, file_text=original)
        self.assertEqual(rows0, [], "consistent OZ original must be silent")
        # flip ONLY maxWithdraw Floor -> Ceil.
        mutant = original.replace(
            "return _convertToAssets(balanceOf(owner), Math.Rounding.Floor);",
            "return _convertToAssets(balanceOf(owner), Math.Rounding.Ceil);", 1)
        self.assertNotEqual(mutant, original, "mutation must alter the source")
        rows1 = MOD.scan_file(_OZ, _OZ.name, file_text=mutant)
        self.assertTrue(rows1, "flipped maxWithdraw must newly fire")
        r = rows1[0]
        self.assertEqual(r["function"], "maxWithdraw")
        self.assertEqual(r["helper_rounding"], "up")
        self.assertEqual(r["paired_fn"], "previewRedeem")
        self.assertEqual(r["paired_rounding"], "down")
        self.assertEqual(r["conserved_pair"], "assets<-shares")
        # byte-identical restore is guaranteed - we never wrote to disk.
        self.assertEqual(_OZ.read_text(), original)

    # ------------------------------------------------------------------
    # (vii) advisory-first exit-code contract via the CLI.
    # ------------------------------------------------------------------
    def test_cli_advisory_first_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "src"
            src.mkdir()
            (src / "V.sol").write_text(textwrap.dedent("""
                contract V {
                    function previewWithdraw(uint256 a) public view returns (uint256) {
                        return _toShares(a, Math.Rounding.Ceil);
                    }
                    function withdraw(uint256 a) public returns (uint256) {
                        uint256 s = _toShares(a, Math.Rounding.Floor);
                        return s;
                    }
                }
                """), encoding="utf-8")
            p = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws)],
                capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            summ = json.loads(p.stdout)
            self.assertGreaterEqual(summ["fired"], 1)
            side = ws / ".auditooor" / \
                "vault_maxexit_rounding_hypotheses.jsonl"
            self.assertTrue(side.exists(), "sidecar must be emitted")
            p2 = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws), "--strict"],
                capture_output=True, text=True)
            self.assertEqual(p2.returncode, 1, "strict must elevate on fire")
            env = dict(os.environ)
            env["AUDITOOOR_VAULT_MAXEXIT_ROUNDING_STRICT"] = "1"
            p3 = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws)],
                capture_output=True, text=True, env=env)
            self.assertEqual(p3.returncode, 1, "env strict must elevate")

    def test_check_mode_reads_sidecar(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "V.sol").write_text(textwrap.dedent("""
                contract V {
                    function previewWithdraw(uint256 a) public view returns (uint256) {
                        return _toShares(a, Math.Rounding.Ceil);
                    }
                    function withdraw(uint256 a) public returns (uint256) {
                        uint256 s = _toShares(a, Math.Rounding.Floor);
                        return s;
                    }
                }
                """), encoding="utf-8")
            subprocess.run([sys.executable, str(TOOL), "--workspace", str(ws)],
                           capture_output=True, text=True)
            p = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws), "--check"],
                capture_output=True, text=True)
            summ = json.loads(p.stdout)
            self.assertEqual(summ["source"], "sidecar")
            self.assertGreaterEqual(summ["fired"], 1)


if __name__ == "__main__":
    unittest.main()
