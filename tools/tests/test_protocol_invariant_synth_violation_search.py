#!/usr/bin/env python3
"""Tests for protocol-invariant-synth-violation-search.py (PISVS).

Non-vacuity guarantee: the fixtures below produce a POSITIVE derivation (the
dual-accounting ratio invariant + a NOVEL corpus verdict) AND a NEGATIVE control
(a division whose numerator is NOT an external balance read yields no D1 row).
"""
import importlib.util
import json
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "protocol-invariant-synth-violation-search.py"
_spec = importlib.util.spec_from_file_location("pisvs", TOOL)
pisvs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pisvs)


def _mk_ws(tmp: Path, vmf: dict, src_files: dict[str, str]) -> Path:
    ws = tmp
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    (ws / ".auditooor" / "value_moving_functions.json").write_text(json.dumps(vmf))
    for rel, body in src_files.items():
        p = ws / "src" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body))
    return ws


# A dual-accounting fixture mirroring NUVA valuation_engine.go: numerator (tvv)
# is an external balance read; denominator (TotalShares.Amount) is an internally
# tracked ledger field.
_DUAL_VMF = {
    "functions": [
        {"file": "src/vault/keeper/msg_server.go", "function": "SwapIn",
         "language": "go", "transfer_hit": True, "ledger_write_evidence": ["TotalShares"],
         "authz_write_hit": False},
    ]
}
_DUAL_SRC = {
    "vault/keeper/valuation_engine.go": """
        func (k Keeper) NavPerShare(ctx sdk.Context, vault VaultAccount) math.Int {
            balances := k.BankKeeper.GetAllBalances(ctx, vault.PrincipalMarkerAddress())
            tvv := sumUnderlying(balances)
            // share price = total value / recorded share supply
            return tvv.Quo(vault.TotalShares.Amount)
        }
    """,
}

# NEGATIVE control: numerator is an internal constant, not an external balance
# read -> must NOT produce a D1 ratio-authority row.
_CLEAN_SRC = {
    "vault/keeper/valuation_engine.go": """
        func (k Keeper) NavPerShare(ctx sdk.Context, vault VaultAccount) math.Int {
            tvv := k.recordedDeposits(ctx, vault)
            // share price from internally tracked deposits only
            return tvv.Quo(vault.TotalShares.Amount)
        }
    """,
}


class TestPISVS(unittest.TestCase):
    def _run(self, vmf, src):
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        ws = _mk_ws(tmp, vmf, src)
        return pisvs.synthesise(ws, None, None)

    def test_dual_accounting_derived_and_novel(self):
        """POSITIVE: the ratio-authority (dual-accounting) invariant is DERIVED
        from code, and because the builtin corpus has no matching class it is
        labelled NOVEL - the generated-not-matched proof."""
        res = self._run(_DUAL_VMF, _DUAL_SRC)
        self.assertTrue(res["ok"], res)
        d1 = [d for d in res["derived"] if d["form"] == "D1_RATIO_AUTHORITY_CONSISTENCY"]
        self.assertEqual(len(d1), 1, f"expected exactly one D1 ratio invariant, got {d1}")
        self.assertEqual(d1[0]["numerator"], "tvv")
        self.assertIn("TotalShares", d1[0]["denominator"])
        # the numerator source must be traced to the external balance read
        self.assertRegex(d1[0]["numerator_external_source"], r"GetAllBalances")
        # corpus verdict must be NOVEL (builtin corpus has no dual-accounting class)
        obs = [o for o in res["obligations"]
               if o["invariant_form"] == "D1_RATIO_AUTHORITY_CONSISTENCY"]
        self.assertEqual(obs[0]["corpus_verdict"], "NOVEL")
        # flywheel: a novel-class proposal is emitted
        self.assertGreaterEqual(res["manifest"]["novel_count"], 1)

    def test_negative_control_no_false_ratio(self):
        """NEGATIVE: a ratio fed by internal state only yields NO D1 row (guards
        against a vacuous always-fires detector)."""
        res = self._run(_DUAL_VMF, _CLEAN_SRC)
        self.assertTrue(res["ok"])
        d1 = [d for d in res["derived"] if d["form"] == "D1_RATIO_AUTHORITY_CONSISTENCY"]
        self.assertEqual(d1, [], f"expected no D1 row for internal-only ratio, got {d1}")

    def test_escrow_liability_derived(self):
        """D2 fires on a transfer+ledger-write function."""
        res = self._run(_DUAL_VMF, _DUAL_SRC)
        d2 = [d for d in res["derived"] if d["form"] == "D2_ESCROW_EQUALS_LIABILITY"]
        self.assertEqual(len(d2), 1)
        self.assertIn("TotalShares", d2[0]["liability_fields"])

    def test_novel_obligation_schema_grounded(self):
        """SCHEMA: every emitted NOVEL obligation carries a real file:line, an
        invariant_id, invariant_text, a violating function, source_refs, an explicit
        verdict=NOVEL and corpus_class=null (no None-cited rows) - and the
        novelty_obligations.jsonl ledger is published at the .auditooor root for the
        logic-obligation-resolution gate + exploit-queue consumer."""
        import json as _json
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        ws = _mk_ws(tmp, _DUAL_VMF, _DUAL_SRC)
        res = pisvs.synthesise(ws, None, None)
        novel = [o for o in res["obligations"] if o["corpus_verdict"] == "NOVEL"]
        self.assertTrue(novel, "expected at least one NOVEL obligation")
        for o in novel:
            self.assertTrue(o["file"], o)
            self.assertIsInstance(o["line"], int)
            self.assertTrue(o["invariant_id"].startswith("pisvs-"), o)
            self.assertTrue(o["invariant_text"], o)
            self.assertEqual(o["verdict"], "NOVEL", o)
            self.assertIsNone(o["corpus_class"], o)
            self.assertEqual(o["attack_class"], "novel-protocol-invariant-violation")
            self.assertEqual(o["proof_status"], "open", o)
            self.assertTrue(o["source_refs"] and ":" in o["source_refs"][0], o)
        # ledger published at the workspace .auditooor root
        ledger = ws / ".auditooor" / "novelty_obligations.jsonl"
        self.assertTrue(ledger.is_file(), "novelty_obligations.jsonl must be emitted")
        rows = [_json.loads(l) for l in ledger.read_text().splitlines() if l.strip()]
        self.assertEqual(len(rows), len(res["obligations"]))

    def test_ungroundable_invariant_dropped(self):
        """HONEST DROP: an escrow-liability derived from a function whose file is not
        on disk cannot be cited to file:line, so it must NOT be emitted None-cited -
        it is dropped and tallied in dropped_ungrounded."""
        vmf = {"functions": [
            {"file": "src/does_not_exist.sol", "function": "ghostFn", "language": "sol",
             "transfer_hit": True, "ledger_write_evidence": ["liability"],
             "authz_write_hit": False},
        ]}
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        ws = _mk_ws(tmp, vmf, {})
        res = pisvs.synthesise(ws, None, None)
        emitted_fns = [o.get("function") for o in res["obligations"]]
        self.assertNotIn("ghostFn", emitted_fns)
        self.assertGreaterEqual(res["manifest"]["dropped_ungrounded_count"], 1)

    # ---- D4-D8: new derived-invariant forms (each non-vacuous) --------------

    def test_d4_authority_monotonicity_derived_and_drop(self):
        """D4: a privileged field guarded in one writer but written unguarded in
        another fires; when every writer is guarded it DROPS (trivially satisfied)."""
        vmf = {"functions": []}
        pos = {"gov/Config.sol": """
            contract Config {
                address public owner;
                function setOwnerGuarded(address a) external onlyOwner { owner = a; }
                function rescue(address a) external { owner = a; }
            }
        """}
        res = self._run(vmf, pos)
        d4 = [d for d in res["derived"] if d["form"] == "D4_AUTHORITY_MONOTONICITY"]
        self.assertEqual(len(d4), 1, d4)
        self.assertEqual(d4[0]["field"], "owner")
        self.assertEqual(d4[0]["function"], "rescue")
        self.assertTrue(isinstance(d4[0]["line"], int))
        # DROP control: both writers guarded -> no D4 row
        neg = {"gov/Config.sol": """
            contract Config {
                address public owner;
                function setOwnerA(address a) external onlyOwner { owner = a; }
                function setOwnerB(address a) external onlyRole(ADMIN) { owner = a; }
            }
        """}
        res2 = self._run(vmf, neg)
        self.assertEqual([d for d in res2["derived"]
                          if d["form"] == "D4_AUTHORITY_MONOTONICITY"], [])

    def test_d5_temporal_ordering_derived_and_drop(self):
        """D5: a stored price read without a same-tx update fires; when the reader
        also updates the field it DROPS (fresh this tx)."""
        vmf = {"functions": []}
        pos = {"amm/Oracle.sol": """
            contract Oracle {
                uint256 public price;
                function poke() external { price = fetch(); }
                function quote(uint256 amt) external view returns (uint256) {
                    return amt * price;
                }
            }
        """}
        res = self._run(vmf, pos)
        d5 = [d for d in res["derived"] if d["form"] == "D5_TEMPORAL_ORDERING"]
        self.assertEqual(len(d5), 1, d5)
        self.assertEqual(d5[0]["field"], "price")
        self.assertEqual(d5[0]["function"], "quote")
        # DROP: reader updates the field in the same body -> fresh
        neg = {"amm/Oracle.sol": """
            contract Oracle {
                uint256 public price;
                function poke() external { price = fetch(); }
                function quote(uint256 amt) external returns (uint256) {
                    price = fetch();
                    return amt * price;
                }
            }
        """}
        res2 = self._run(vmf, neg)
        self.assertEqual([d for d in res2["derived"]
                          if d["form"] == "D5_TEMPORAL_ORDERING"], [])

    def test_d6_sum_conservation_derived_and_drop(self):
        """D6: an aggregate total + a related per-account part mapping fires; an
        aggregate with no per-part ledger DROPS (conservation unstatable)."""
        vmf = {"functions": []}
        pos = {"vault/Ledger.sol": """
            contract Ledger {
                uint256 public totalShares;
                mapping(address => uint256) public shares;
                function mint(address a, uint256 x) external {
                    shares[a] += x;
                    totalShares += x;
                }
            }
        """}
        res = self._run(vmf, pos)
        d6 = [d for d in res["derived"] if d["form"] == "D6_SUM_CONSERVATION"]
        self.assertEqual(len(d6), 1, d6)
        self.assertEqual(d6[0]["field"], "totalShares")
        self.assertEqual(d6[0]["part_symbol"], "shares")
        # DROP: aggregate written but no per-account part mapping
        neg = {"vault/Ledger.sol": """
            contract Ledger {
                uint256 public totalShares;
                function mint(uint256 x) external { totalShares += x; }
            }
        """}
        res2 = self._run(vmf, neg)
        self.assertEqual([d for d in res2["derived"]
                          if d["form"] == "D6_SUM_CONSERVATION"], [])

    def test_d7_uniqueness_nonce_derived_and_drop(self):
        """D7: a consumed-marker write without a replay guard fires; the same write
        with a require(!used[x]) guard DROPS (trivially satisfied)."""
        vmf = {"functions": []}
        pos = {"bridge/Relay.sol": """
            contract Relay {
                mapping(bytes32 => bool) public used;
                function execute(bytes32 id) external {
                    used[id] = true;
                    _run(id);
                }
            }
        """}
        res = self._run(vmf, pos)
        d7 = [d for d in res["derived"] if d["form"] == "D7_UNIQUENESS_NONCE"]
        self.assertEqual(len(d7), 1, d7)
        self.assertEqual(d7[0]["field"], "used")
        # DROP: replay guard present
        neg = {"bridge/Relay.sol": """
            contract Relay {
                mapping(bytes32 => bool) public used;
                function execute(bytes32 id) external {
                    require(!used[id], "replay");
                    used[id] = true;
                    _run(id);
                }
            }
        """}
        res2 = self._run(vmf, neg)
        self.assertEqual([d for d in res2["derived"]
                          if d["form"] == "D7_UNIQUENESS_NONCE"], [])

    def test_d8_bound_invariant_derived_and_drop(self):
        """D8: a field compared against a MAX/CAP-named bound fires; a MAX/CAP
        constant declared but never compared DROPS (no enforced field)."""
        vmf = {"functions": []}
        pos = {"fee/Fees.sol": """
            contract Fees {
                uint256 constant MAX_FEE = 1000;
                uint256 public feeBps;
                function setFee(uint256 f) external {
                    require(f <= MAX_FEE, "too high");
                    feeBps = f;
                }
            }
        """}
        res = self._run(vmf, pos)
        d8 = [d for d in res["derived"] if d["form"] == "D8_BOUND_INVARIANT"]
        self.assertEqual(len(d8), 1, d8)
        self.assertEqual(d8[0]["field"], "f")
        self.assertEqual(d8[0]["bound"], "MAX_FEE")
        # DROP: bound constant declared but never used in a comparison
        neg = {"fee/Fees.sol": """
            contract Fees {
                uint256 constant MAX_FEE = 1000;
                uint256 public feeBps;
                function setFee(uint256 f) external { feeBps = f; }
            }
        """}
        res2 = self._run(vmf, neg)
        self.assertEqual([d for d in res2["derived"]
                          if d["form"] == "D8_BOUND_INVARIANT"], [])

    def test_missing_backend_errors(self):
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        (tmp / ".auditooor").mkdir(parents=True)
        res = pisvs.synthesise(tmp, None, None)
        self.assertFalse(res["ok"])

    def test_cli_smoke(self):
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        ws = _mk_ws(tmp, _DUAL_VMF, _DUAL_SRC)
        r = subprocess.run([sys.executable, str(TOOL), str(ws)],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DERIVED FROM CODE", r.stdout)
        self.assertIn("NOVEL", r.stdout)


if __name__ == "__main__":
    unittest.main()
