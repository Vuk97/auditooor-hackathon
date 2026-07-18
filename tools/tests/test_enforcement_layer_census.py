#!/usr/bin/env python3
"""Non-vacuous tests for enforcement-layer-census.py (ELC, B3).

Cases (fixture ws, so the flag predicate is exercised directly):
  1. present layer + 0 mapped sidecar        -> flagged
  2. present layer + >=1 mapped sidecar       -> NOT flagged
  3. absent layer (no source cue)             -> NOT flagged
Mutating the "present AND source_hits>=MIN AND sidecar_count==0" predicate
breaks at least one case (see test_predicate_is_load_bearing).
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_H = Path(__file__).resolve().parent
_s = importlib.util.spec_from_file_location(
    "elc", _H.parent / "enforcement-layer-census.py")
_m = importlib.util.module_from_spec(_s)
sys.modules["elc"] = _m
_s.loader.exec_module(_m)


def _mk_ws(with_sidecar_for=None):
    ws = Path(tempfile.mkdtemp())
    src = ws / "src"
    src.mkdir(parents=True)
    au = ws / ".auditooor"
    au.mkdir(parents=True)
    # access-control PRESENT (MsgServer cue), conservation PRESENT (totalSupply).
    (src / "keeper.go").write_text(
        "package k\nfunc (m MsgServer) Do() {}\n", encoding="utf-8")
    (src / "Vault.sol").write_text(
        "contract V { function t() public view returns (uint){"
        " return totalSupply; } }\n", encoding="utf-8")
    inscope = [
        {"file": "src/keeper.go", "lang": "go"},
        {"file": "src/Vault.sol", "lang": "solidity"},
    ]
    (au / "inscope_units.jsonl").write_text(
        "\n".join(json.dumps(r) for r in inscope), encoding="utf-8")
    scd = au / "hunt_findings_sidecars"
    scd.mkdir(parents=True)
    if with_sidecar_for == "conservation":
        (scd / "s1.json").write_text(
            json.dumps({"unit": "x", "impact": "conservation"}), encoding="utf-8")
    return ws


def _mk_crypto_ws(sidecars=None):
    """A ws where ONLY the crypto layer is present in source (ecrecover cue).

    ``sidecars`` = list of (filename, dict) written into hunt_findings_sidecars.
    Lets the MIMO-credit path be exercised in isolation: crypto is flag-eligible
    (present, source_hits>=1) so a hunt sidecar either credits it (not flagged)
    or it stays flagged."""
    ws = Path(tempfile.mkdtemp())
    src = ws / "src"
    src.mkdir(parents=True)
    au = ws / ".auditooor"
    au.mkdir(parents=True)
    (src / "Sig.sol").write_text(
        "contract Sig {\n"
        "  function v(bytes32 h, uint8 x, bytes32 r, bytes32 s)\n"
        "      public pure returns (address) { return ecrecover(h, x, r, s); }\n"
        "}\n", encoding="utf-8")
    (au / "inscope_units.jsonl").write_text(
        json.dumps({"file": "src/Sig.sol", "lang": "solidity"}) + "\n",
        encoding="utf-8")
    scd = au / "hunt_findings_sidecars"
    scd.mkdir(parents=True)
    for name, rec in (sidecars or []):
        (scd / name).write_text(json.dumps(rec), encoding="utf-8")
    return ws


class MimoCredit(unittest.TestCase):
    """The MIMO/haiku schema carries NO class token; its layer signal is the
    anchored function_anchor.fn + verbatim code_excerpt. These cases prove the
    fallback credit FIRES for a real crypto hunt yet STAYS flagged for an
    unrelated one (serving-join false-red fix)."""

    def test_crypto_flagged_without_any_sidecar(self):
        # Baseline: crypto present in source, zero sidecars -> flagged.
        ws = _mk_crypto_ws()
        cr = _m.build_census(ws, min_hits=1)["layers"]["crypto"]
        self.assertTrue(cr["present"])
        self.assertEqual(cr["sidecar_count"], 0)
        self.assertTrue(cr["flagged"])

    def test_mimo_string_anchor_stringified_result_fires(self):
        # THE task shape: function_anchor "X.sol::_verifyAML:1" + a stringified
        # result. The excerpt is BENIGN (no cue) so the credit comes purely from
        # the anchored crypto function name (b2). Sidecar FIRES -> not flagged.
        rec = {
            "task_id": "t1",
            "function_anchor": "src/Sig.sol::_verifyAML:1",
            "result": json.dumps({
                "applies_to_target": "no",
                "candidate_finding": "signature checks look complete",
                "code_excerpt": "if (used[h]) revert Used(); used[h] = true;",
            }),
        }
        ws = _mk_crypto_ws([("hunt__Sig.sol___verifyAML__batch1.json", rec)])
        c = _m.build_census(ws, min_hits=1)
        cr = c["layers"]["crypto"]
        self.assertGreaterEqual(cr["sidecar_count"], 1)     # FIRES
        self.assertFalse(cr["flagged"])
        self.assertNotIn("crypto", c["flagged_layers"])

    def test_mimo_stringified_result_excerpt_fires(self):
        # b1: the crypto cue (ecrecover) is in the stringified result's verbatim
        # code_excerpt; the anchored fn name is NOT crypto, so the excerpt arm
        # alone must credit crypto.
        rec = {
            "function_anchor": {"file": "src/Sig.sol", "fn": "check",
                                "start_line": 1},
            "result": json.dumps({
                "applies_to_target": "no",
                "code_excerpt": "address a = ecrecover(hash, v, r, s);",
            }),
        }
        ws = _mk_crypto_ws([("hunt__Sig.sol__check__x.json", rec)])
        cr = _m.build_census(ws, min_hits=1)["layers"]["crypto"]
        self.assertGreaterEqual(cr["sidecar_count"], 1)
        self.assertFalse(cr["flagged"])

    def test_mimo_dict_anchor_fires(self):
        # Batch schema: function_anchor dict {fn:_verifyAML}, benign excerpt.
        rec = {
            "function_anchor": {"file": "src/Sig.sol", "fn": "_verifyAML",
                                "start_line": 1, "end_line": 9},
            "result": json.dumps({"applies_to_target": "no",
                                   "code_excerpt": "used[h] = true;"}),
        }
        ws = _mk_crypto_ws([("hunt__Sig.sol___verifyAML__batch2.json", rec)])
        cr = _m.build_census(ws, min_hits=1)["layers"]["crypto"]
        self.assertGreaterEqual(cr["sidecar_count"], 1)
        self.assertFalse(cr["flagged"])

    def test_mimo_unrelated_sidecar_leaves_layer_flagged(self):
        # Over-credit guard: an unrelated hunt (non-cue fn name, benign excerpt)
        # that only MENTIONS crypto in the PROSE fields does NOT credit crypto -
        # the layer STAYS flagged. Proves prose is never a credit input and a
        # non-cue function name does not falsely green.
        rec = {
            "function_anchor": "src/Sig.sol::transfer:1",
            "result": json.dumps({
                "applies_to_target": "no",
                "candidate_finding": "verify() is safe, no keccak256 issue here",
                "falsification_attempt": "checked ecrecover usage - fine",
                "code_excerpt": "balances[to] += amount;",
            }),
        }
        ws = _mk_crypto_ws([("hunt__Sig.sol__transfer__x.json", rec)])
        c = _m.build_census(ws, min_hits=1)
        cr = c["layers"]["crypto"]
        self.assertEqual(cr["sidecar_count"], 0)            # no credit
        self.assertTrue(cr["flagged"])                      # STAYS flagged
        self.assertIn("crypto", c["flagged_layers"])

    def test_class_token_path_unchanged_by_mimo_arms(self):
        # Dedup/superset invariant: a sidecar carrying a real class token routes
        # via LAYER_MAP EXACTLY as before; the MIMO arms are not reached. Its
        # code_excerpt mentions totalSupply (a conservation b1 cue) but because
        # the class token short-circuits, conservation is NOT credited from it.
        rec = {"unit": "x", "impact": "signature-replay",
               "function_anchor": "src/Sig.sol::whatever:1",
               "code_excerpt": "totalSupply += 1;"}
        ws = _mk_crypto_ws([("s_classtok.json", rec)])
        c = _m.build_census(ws, min_hits=1)
        self.assertGreaterEqual(c["layers"]["crypto"]["sidecar_count"], 1)
        self.assertEqual(c["layers"]["conservation"]["sidecar_count"], 0)


def _mk_upgrade_ws(sidecars=None, extra_inscope=None):
    """A mixed Go+EVM ws where the EVM-only ``upgrade`` layer is PRESENT.

    UUPSVault.sol carries the loose upgrade cue (_authorizeUpgrade) AND ecrecover
    (crypto present); a Cosmos Go app.go mentions 'proxy' (also a loose upgrade
    cue). Both are IN-CUT so the not-in-CUT guard does not confound the b1
    tight-cue / EVM-gate guards under test. ``sidecars`` = list of (name, dict)."""
    ws = Path(tempfile.mkdtemp())
    src = ws / "src"
    src.mkdir(parents=True)
    au = ws / ".auditooor"
    au.mkdir(parents=True)
    (src / "UUPSVault.sol").write_text(
        "contract UUPSVault {\n"
        "  function _authorizeUpgrade(address) internal {}\n"
        "  function v(bytes32 h, uint8 x, bytes32 r, bytes32 s)\n"
        "      public pure returns (address) { return ecrecover(h, x, r, s); }\n"
        "}\n", encoding="utf-8")
    (src / "app.go").write_text(
        "package app\n"
        "func createProxyConn() { p := proxy.NewMultiAppConn(cc); _ = p }\n",
        encoding="utf-8")
    inscope = [
        {"file": "src/UUPSVault.sol", "lang": "solidity"},
        {"file": "src/app.go", "lang": "go"},
    ]
    inscope += (extra_inscope or [])
    (au / "inscope_units.jsonl").write_text(
        "\n".join(json.dumps(r) for r in inscope), encoding="utf-8")
    scd = au / "hunt_findings_sidecars"
    scd.mkdir(parents=True)
    for name, rec in (sidecars or []):
        (scd / name).write_text(json.dumps(rec), encoding="utf-8")
    return ws


def _sidecar(anchor, excerpt="", applies="no", **result_extra):
    """Build a MIMO/haiku sidecar with a stringified result blob."""
    res = {"applies_to_target": applies, "code_excerpt": excerpt}
    res.update(result_extra)
    return {"function_anchor": anchor, "result": json.dumps(res)}


class B1OverCreditGuards(unittest.TestCase):
    """The b1 excerpt arm reused the LOOSE present-detection cues for CREDIT, so
    a bare 'proxy' (pervasive in Cosmos/cometbft Go), a bodyless interface, an
    OOS fixture, or a not-in-CUT anchor false-credited the EVM-only ``upgrade``
    layer (measured: sei/upgrade flipped flagged->unflagged off 9 spurious
    creditors). These cases pin the three fleet-safety guards: tight credit cues,
    OOS/not-in-CUT/bodyless exclusion, and EVM-only gating - while a genuine
    in-scope .sol initialize/verifyAML/UUPS hunt STILL credits."""

    def test_upgrade_flagged_baseline(self):
        # upgrade present in .sol source, zero sidecars -> flagged.
        ws = _mk_upgrade_ws()
        up = _m.build_census(ws, min_hits=1)["layers"]["upgrade"]
        self.assertTrue(up["present"])
        self.assertEqual(up["sidecar_count"], 0)
        self.assertTrue(up["flagged"])

    def test_go_bare_proxy_excerpt_does_not_credit_upgrade(self):
        # guard 1+3: a Cosmos Go hunt whose excerpt mentions 'proxy' (the loose
        # cue) does NOT credit upgrade - the tight cue drops bare 'proxy' AND the
        # anchor is a .go file (EVM-only gate). Layer STAYS flagged.
        sc = _sidecar("src/app.go::createProxyConn:1",
                      excerpt="p := proxy.NewMultiAppConn(clientCreator)")
        ws = _mk_upgrade_ws([("hunt__app.go__createProxyConn__x.json", sc)])
        c = _m.build_census(ws, min_hits=1)
        self.assertEqual(c["layers"]["upgrade"]["sidecar_count"], 0)
        self.assertTrue(c["layers"]["upgrade"]["flagged"])

    def test_sol_bare_proxy_excerpt_does_not_credit_upgrade(self):
        # guard 1 in isolation: an in-scope .sol hunt whose excerpt has bare
        # 'proxy' (no anchored upgrade primitive) does NOT credit - EVM gate
        # passes, so ONLY the tight cue stops the old over-credit.
        sc = _sidecar("src/UUPSVault.sol::route:1",
                      excerpt="IProxy proxy = registry.proxyFor(id);")
        ws = _mk_upgrade_ws([("hunt__UUPSVault.sol__route__x.json", sc)])
        c = _m.build_census(ws, min_hits=1)
        self.assertEqual(c["layers"]["upgrade"]["sidecar_count"], 0)
        self.assertTrue(c["layers"]["upgrade"]["flagged"])

    def test_go_initialize_fn_does_not_credit_upgrade(self):
        # guard 3: a Go InitializePrecompiles hunt (fn-name matches the b2 upgrade
        # cue) does NOT credit upgrade because UUPS/proxy-upgrade is EVM-only.
        sc = _sidecar("src/app.go::InitializePrecompiles:1",
                      excerpt="k.setupModules(ctx)")
        ws = _mk_upgrade_ws([("hunt__app.go__InitializePrecompiles__x.json", sc)])
        c = _m.build_census(ws, min_hits=1)
        self.assertEqual(c["layers"]["upgrade"]["sidecar_count"], 0)
        self.assertTrue(c["layers"]["upgrade"]["flagged"])

    def test_bodyless_interface_decl_does_not_credit(self):
        # guard 2a: a bodyless interface signature (no body to hunt) does NOT
        # credit even though the fn name + a tight-ish token appear - it is a
        # declaration, not enforcement code.
        sc = _sidecar("src/UUPSVault.sol::upgradeTo:1",
                      excerpt="function upgradeTo(address newImplementation) external;")
        ws = _mk_upgrade_ws([("hunt__UUPSVault.sol__upgradeTo__x.json", sc)])
        c = _m.build_census(ws, min_hits=1)
        self.assertEqual(c["layers"]["upgrade"]["sidecar_count"], 0)
        self.assertTrue(c["layers"]["upgrade"]["flagged"])

    def test_oos_negative_fixture_does_not_credit(self):
        # guard 2c: a NEGATIVE hunt that self-labels the WHOLE target a non-CUT
        # artifact (reference mirror / not in the CUT) did not cover in-scope
        # enforcement -> no credit.
        sc = _sidecar(
            "src/UUPSVault.sol::initialize:1",
            excerpt="inited = true;", applies="no",
            candidate_finding="this file is a reference mirror, not in the CUT")
        ws = _mk_upgrade_ws([("hunt__UUPSVault.sol__initialize__oos.json", sc)])
        c = _m.build_census(ws, min_hits=1)
        self.assertEqual(c["layers"]["upgrade"]["sidecar_count"], 0)
        self.assertTrue(c["layers"]["upgrade"]["flagged"])

    def test_incidental_oos_mention_still_credits(self):
        # over-exclusion guard (morpho FP class): a GENUINE in-scope hunt whose
        # reasoning merely NOTES prior OOS clauses / a tangential OOS sub-point
        # is NOT excluded - bare "OOS"/"out of scope" must not fire guard 2c.
        sc = _sidecar(
            "src/UUPSVault.sol::initialize:1",
            excerpt="require(!inited); inited = true;", applies="no",
            notes="Prior OOS clauses noted but extension-distinct; core "
                  "invariant is OOS per SCOPE.md yet this handler is in-scope")
        ws = _mk_upgrade_ws([("hunt__UUPSVault.sol__initialize__note.json", sc)])
        c = _m.build_census(ws, min_hits=1)
        self.assertGreaterEqual(c["layers"]["upgrade"]["sidecar_count"], 1)
        self.assertFalse(c["layers"]["upgrade"]["flagged"])

    def test_not_in_cut_anchor_does_not_credit(self):
        # guard 2b: an anchor OUTSIDE the CUT (a fixture .sol not in
        # inscope_units) does NOT credit - even with an upgrade fn name.
        sc = _sidecar("src/ReferenceMirror.sol::initialize:1",
                      excerpt="inited = true;")
        ws = _mk_upgrade_ws([("hunt__ReferenceMirror.sol__initialize__x.json", sc)])
        c = _m.build_census(ws, min_hits=1)
        self.assertEqual(c["layers"]["upgrade"]["sidecar_count"], 0)
        self.assertTrue(c["layers"]["upgrade"]["flagged"])

    def test_genuine_sol_initialize_credits_upgrade(self):
        # POSITIVE (b2): a genuine in-scope .sol initialize hunt DOES credit
        # upgrade - EVM gate passes, not bodyless, in-CUT, not OOS.
        sc = _sidecar("src/UUPSVault.sol::initialize:1",
                      excerpt="require(!inited); inited = true;")
        ws = _mk_upgrade_ws([("hunt__UUPSVault.sol__initialize__ok.json", sc)])
        c = _m.build_census(ws, min_hits=1)
        self.assertGreaterEqual(c["layers"]["upgrade"]["sidecar_count"], 1)
        self.assertFalse(c["layers"]["upgrade"]["flagged"])

    def test_genuine_sol_uups_excerpt_credits_upgrade(self):
        # POSITIVE (b1): an anchored upgrade primitive in a real .sol body DOES
        # credit upgrade via the tight cue.
        sc = _sidecar(
            "src/UUPSVault.sol::_authorizeUpgrade:1",
            excerpt="function _authorizeUpgrade(address newImpl) internal override onlyOwner {}")
        ws = _mk_upgrade_ws([("hunt__UUPSVault.sol___authorizeUpgrade__ok.json", sc)])
        c = _m.build_census(ws, min_hits=1)
        self.assertGreaterEqual(c["layers"]["upgrade"]["sidecar_count"], 1)
        self.assertFalse(c["layers"]["upgrade"]["flagged"])

    def test_genuine_sol_verifyaml_credits_crypto(self):
        # POSITIVE (b2, non-EVM-gated): a genuine in-scope .sol _verifyAML hunt
        # DOES credit crypto (crypto is not EVM-only, but the guards still pass).
        sc = _sidecar("src/UUPSVault.sol::_verifyAML:1",
                      excerpt="require(kyc[user], \"aml\");")
        ws = _mk_upgrade_ws([("hunt__UUPSVault.sol___verifyAML__ok.json", sc)])
        c = _m.build_census(ws, min_hits=1)
        self.assertGreaterEqual(c["layers"]["crypto"]["sidecar_count"], 1)
        self.assertFalse(c["layers"]["crypto"]["flagged"])


class T(unittest.TestCase):
    def test_present_zero_sidecar_flags(self):
        ws = _mk_ws(with_sidecar_for=None)
        c = _m.build_census(ws, min_hits=1)
        ac = c["layers"]["access-control"]
        self.assertTrue(ac["present"])
        self.assertEqual(ac["sidecar_count"], 0)
        self.assertTrue(ac["flagged"])            # case 1
        self.assertIn("access-control", c["flagged_layers"])

    def test_present_with_mapped_sidecar_not_flagged(self):
        ws = _mk_ws(with_sidecar_for="conservation")
        c = _m.build_census(ws, min_hits=1)
        cons = c["layers"]["conservation"]
        self.assertTrue(cons["present"])
        self.assertGreaterEqual(cons["sidecar_count"], 1)
        self.assertFalse(cons["flagged"])         # case 2
        self.assertNotIn("conservation", c["flagged_layers"])

    def test_absent_layer_not_flagged(self):
        ws = _mk_ws(with_sidecar_for=None)
        c = _m.build_census(ws, min_hits=1)
        orc = c["layers"]["oracle"]               # no oracle cue in fixture
        self.assertFalse(orc["present"])
        self.assertEqual(orc["source_hits"], 0)
        self.assertFalse(orc["flagged"])          # case 3
        self.assertNotIn("oracle", c["flagged_layers"])

    def test_min_hits_gates_flag(self):
        # source_hits==1 present layer is NOT flag-eligible when MIN=2.
        ws = _mk_ws(with_sidecar_for=None)
        c = _m.build_census(ws, min_hits=2)
        ac = c["layers"]["access-control"]
        self.assertTrue(ac["present"])
        self.assertEqual(ac["source_hits"], 1)
        self.assertFalse(ac["flagged"])

    def test_predicate_is_load_bearing(self):
        # Prove the conjunction matters: recompute each layer's flag from the
        # real predicate and confirm it distinguishes case 1 from case 2.
        ws = _mk_ws(with_sidecar_for="conservation")
        c = _m.build_census(ws, min_hits=1)
        for ly, d in c["layers"].items():
            expect = bool(d["present"] and d["source_hits"] >= 1
                          and d["sidecar_count"] == 0)
            self.assertEqual(d["flagged"], expect, ly)
        self.assertTrue(c["layers"]["access-control"]["flagged"])
        self.assertFalse(c["layers"]["conservation"]["flagged"])

    def test_legacy_mode_remains_advisory(self):
        ws = _mk_ws(with_sidecar_for=None)
        c = _m.build_census(ws, min_hits=1)
        self.assertEqual(c["mode"], "legacy-advisory")
        self.assertTrue(c["advisory"])
        self.assertTrue(c["strict_ok"])

    def test_strict_requires_canonical_prerequisites(self):
        ws = _mk_ws(with_sidecar_for=None)
        c = _m.build_census(ws, min_hits=1, strict=True)
        self.assertEqual(c["mode"], "canonical-strict")
        self.assertFalse(c["strict_ok"])
        self.assertIn("unresolved-applicable-census-gaps",
                      c["strict_blockers"])
        self.assertTrue(c["unresolved_gaps"])
        self.assertFalse(c["advisory"])

        (ws / ".auditooor" / "inscope_units.jsonl").unlink()
        (ws / ".auditooor" / "enforcement_layer_census_dispositions.jsonl").unlink(missing_ok=True)
        c_missing = _m.build_census(ws, min_hits=1, strict=True)
        self.assertIn("missing-inscope-inventory", c_missing["strict_blockers"])

    def test_strict_exact_typed_dispositions_close_only_matching_gaps(self):
        ws = _mk_ws(with_sidecar_for=None)
        raw = _m.build_census(ws, min_hits=1)
        flagged = raw["flagged_layers"]
        self.assertGreaterEqual(len(flagged), 2)
        # A prose role/name and a non-terminal disposition do not close the
        # applicable layer.  Exact stable IDs are required for closure.
        (ws / ".auditooor" / "enforcement_layer_census_dispositions.jsonl").write_text(
            json.dumps({"layer": flagged[0], "disposition": "resolved"}) + "\n"
            + json.dumps({"stable_id": "ELC-missing", "disposition": "resolved"}) + "\n"
            + json.dumps({"stable_id": _m.layer_stable_id(ws, flagged[0]),
                          "disposition": "not-applicable"}) + "\n",
            encoding="utf-8")
        dispositions, invalid = _m.load_typed_dispositions(ws)
        self.assertIn(_m.layer_stable_id(ws, flagged[0]), dispositions)
        self.assertEqual(len(invalid), 1)
        c = _m.build_census(ws, min_hits=1, strict=True,
                            dispositions=dispositions)
        self.assertIn(_m.layer_stable_id(ws, flagged[0]),
                      c["dispositioned_gaps"])
        self.assertEqual(
            [row["layer"] for row in c["unresolved_gaps"]], flagged[1:])
        self.assertFalse(c["strict_ok"])

    def test_strict_allows_clean_canonical_census(self):
        ws = _mk_ws(with_sidecar_for=None)
        # Remove access-control from the CUT so the fixture has one applicable
        # layer and the exact disposition below can close it.
        (ws / "src" / "keeper.go").unlink()
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps({"file": "src/Vault.sol", "lang": "solidity"}) + "\n",
            encoding="utf-8")
        raw = _m.build_census(ws, min_hits=1)
        sid = _m.layer_stable_id(ws, "conservation")
        (ws / ".auditooor" / "enforcement_layer_census_dispositions.jsonl").write_text(
            json.dumps({"stable_id": sid, "disposition": "covered"}) + "\n",
            encoding="utf-8")
        dispositions, _invalid = _m.load_typed_dispositions(ws)
        c = _m.build_census(ws, min_hits=1, strict=True,
                            dispositions=dispositions)
        self.assertEqual(raw["flagged_layers"], ["conservation"])
        self.assertTrue(c["strict_ok"])
        self.assertEqual(c["status"], "strict-pass")

    def test_main_strict_returns_failure_for_unresolved_gap(self):
        ws = _mk_ws(with_sidecar_for=None)
        rc = _m.main(["--workspace", str(ws), "--min", "1", "--strict"])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
