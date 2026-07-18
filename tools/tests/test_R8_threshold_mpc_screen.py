#!/usr/bin/env python3
# <!-- gap55-rebuttal: R8-threshold-mpc-screen conditional exploit-class gate -->
"""Guard: R8-threshold-mpc-screen - the surface-gated conditional
`threshold-mpc-ceremony` exploit class in exploit-class-coverage.py.

NON-VACUITY (the load-bearing pair): with an in-scope threshold/MPC ceremony
surface present, a MISSING ceremony disposition FIRES the gate under STRICT
(test_a); the SAME surface with a backed not-applicable disposition is SILENT
(test_b). A generic-consensus / generic-DeFi surface (bare `threshold`, a
`schnorr` comment, no scheme token) does NOT fire - the anti-fleet-RED guard
(test_d / test_e). Off-strict, a present-but-undispositioned surface is an
advisory WARN, never a fail (test_c).
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_TOOLS = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ecc_mpc", str(_TOOLS / "exploit-class-coverage.py"))
m = importlib.util.module_from_spec(spec)
sys.modules["ecc_mpc"] = m
spec.loader.exec_module(m)

_FUZZ_REF = ".auditooor/deep-engine-findings/X-fuzz.md"


def _ws() -> Path:
    ws = Path(tempfile.mkdtemp()).resolve()
    (ws / ".auditooor" / "deep-engine-findings").mkdir(parents=True)
    (ws / ".auditooor" / "deep-engine-findings" / "X-fuzz.md").write_text(
        "medusa 2M calls invariant fuzz, 0 violations")
    (ws / "src").mkdir()
    return ws


def _canonical_rows():
    return [{"class": c, "status": "covered-by-fuzz", "evidence_ref": _FUZZ_REF,
             "rationale": f"{c} addressed"} for c in m.CANONICAL_CLASSES]


def _write_ledger(ws: Path, rows):
    (ws / ".auditooor" / "exploit_class_coverage.json").write_text(
        json.dumps({"schema": m.SCHEMA, "classes": rows}))


def _plant_mpc_source(ws: Path):
    # real code that fires the scheme anchor (frost:: + GeneralizedXmss); the
    # //! doc-comment mention of "threshold signature" is comment-stripped, so the
    # FIRE comes from live code - proving comment-strip does not suppress a real hit.
    (ws / "src" / "scheme.rs").write_text(
        "//! FROST threshold signature ceremony module\n"
        "use frost::round1;\n"
        "pub fn generate() -> GeneralizedXmss { round1::commit() }\n")


def _plant_consensus_source(ws: Path, n_threshold: int = 50):
    # near-core-like: bare `threshold` x50 (consensus/quorum) + a `schnorr`
    # mention ONLY in a comment. Neither is a scheme anchor -> must NOT fire.
    body = "\n".join(f"    let voting_threshold_{i} = quorum({i});" for i in range(n_threshold))
    (ws / "src" / "consensus.rs").write_text(
        "// schnorr is referenced only in this comment, never in code\n"
        "pub fn tally(votes: u64) -> bool {\n" + body + "\n"
        "    votes >= quorum(0)\n}\n")


class TestMpcSurfaceGate(unittest.TestCase):
    def setUp(self):
        if m._scope_authority is not None:
            m._scope_authority.clear_cache()

    # (a) MPC surface + no ceremony row + STRICT -> FIRES (fail)
    def test_a_missing_disposition_fires_under_strict(self):
        ws = _ws(); _plant_mpc_source(ws); _write_ledger(ws, _canonical_rows())
        with mock.patch.dict("os.environ", {"AUDITOOOR_L37_STRICT": "1"}):
            r = m.evaluate(ws)
        self.assertTrue(r["mpc_surface_present"], "scheme anchor should fire on scheme.rs")
        self.assertEqual(r["verdict"], "fail-exploit-class-undispositioned")
        self.assertTrue(any(m.MPC_CEREMONY_CLASS in g for g in r["gaps"]))
        self.assertTrue(r["conditional_gaps"])

    # (b) same surface + a BACKED not-applicable ceremony row -> SILENT (pass)
    def test_b_backed_not_applicable_passes_under_strict(self):
        ws = _ws(); _plant_mpc_source(ws)
        rows = _canonical_rows()
        rows.append({"class": m.MPC_CEREMONY_CLASS, "status": "not-applicable",
                     "evidence_ref": "src/scheme.rs",
                     "rationale": "single-signer hash-based scheme; no multi-party "
                                  "threshold ceremony / round-proof / FS transcript"})
        _write_ledger(ws, rows)
        with mock.patch.dict("os.environ", {"AUDITOOOR_L37_STRICT": "1"}):
            r = m.evaluate(ws)
        self.assertTrue(r["mpc_surface_present"])
        self.assertEqual(r["verdict"], "pass-exploit-class-covered", r.get("reason"))
        self.assertEqual(r["conditional_gaps"], [])

    # (c) same undispositioned surface OFF-strict -> WARN not fail (pass + conditional_gaps)
    def test_c_off_strict_is_advisory_warn(self):
        ws = _ws(); _plant_mpc_source(ws); _write_ledger(ws, _canonical_rows())
        with mock.patch.dict("os.environ", {"AUDITOOOR_L37_STRICT": "0"}):
            r = m.evaluate(ws)
        self.assertTrue(r["mpc_surface_present"])
        self.assertEqual(r["verdict"], "pass-exploit-class-covered")
        self.assertTrue(r["conditional_gaps"], "off-strict must still record the advisory gap")
        self.assertFalse(any(m.MPC_CEREMONY_CLASS in g for g in r["gaps"]))

    # (d) near-core-like consensus surface (bare threshold + schnorr comment) -> NO fire
    def test_d_consensus_threshold_true_negative(self):
        ws = _ws(); _plant_consensus_source(ws); _write_ledger(ws, _canonical_rows())
        with mock.patch.dict("os.environ", {"AUDITOOOR_L37_STRICT": "1"}):
            r = m.evaluate(ws)
        self.assertFalse(r["mpc_surface_present"], "bare threshold / comment schnorr must not fire")
        self.assertEqual(r["verdict"], "pass-exploit-class-covered")
        self.assertEqual(r["conditional_gaps"], [])

    # (e) generic-DeFi surface (no scheme token) -> NO fire
    def test_e_generic_defi_no_fire(self):
        ws = _ws()
        (ws / "src" / "Vault.sol").write_text(
            "contract Vault { function deposit(uint a) external { bal += a; } }")
        _write_ledger(ws, _canonical_rows())
        with mock.patch.dict("os.environ", {"AUDITOOOR_L37_STRICT": "1"}):
            r = m.evaluate(ws)
        self.assertFalse(r["mpc_surface_present"])
        self.assertEqual(r["verdict"], "pass-exploit-class-covered")


class TestMpcInScopeOnly(unittest.TestCase):
    """Anti-fleet-RED: with the scope manifest present, a vendored/OOS crypto lib
    is NOT scanned, so it never demands a disposition; an in-scope crypto file
    does fire."""

    def setUp(self):
        if m._scope_authority is not None:
            m._scope_authority.clear_cache()

    def _manifest(self, ws: Path, files):
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            "\n".join(json.dumps({"file": f, "function": "run"}) for f in files))

    def test_oos_crypto_lib_does_not_demand(self):
        ws = _ws()
        (ws / "src" / "app.rs").write_text("pub fn run() { let bal = 1; }")
        (ws / "vendor").mkdir()
        (ws / "vendor" / "frost.rs").write_text("use frost::round1; // OOS vendored lib")
        self._manifest(ws, ["src/app.rs"])  # crypto lib NOT in scope
        m._scope_authority.clear_cache()
        _write_ledger(ws, _canonical_rows())
        with mock.patch.dict("os.environ", {"AUDITOOOR_L37_STRICT": "1"}):
            r = m.evaluate(ws)
        self.assertFalse(r["mpc_surface_present"], "OOS crypto lib must not trigger a demand")
        self.assertEqual(r["verdict"], "pass-exploit-class-covered")

    def test_inscope_crypto_file_does_demand(self):
        ws = _ws(); _plant_mpc_source(ws)
        self._manifest(ws, ["src/scheme.rs"])  # crypto file IS in scope
        m._scope_authority.clear_cache()
        _write_ledger(ws, _canonical_rows())
        with mock.patch.dict("os.environ", {"AUDITOOOR_L37_STRICT": "1"}):
            r = m.evaluate(ws)
        self.assertTrue(r["mpc_surface_present"])
        self.assertEqual(r["verdict"], "fail-exploit-class-undispositioned")


class TestMpcAdvisoryArm(unittest.TestCase):
    def setUp(self):
        if m._scope_authority is not None:
            m._scope_authority.clear_cache()

    def test_scaffold_appends_ceremony_row_only_when_surface_present(self):
        ws = _ws(); _plant_mpc_source(ws)
        d = json.loads(m.scaffold(ws).read_text())
        classes = {r["class"] for r in d["classes"]}
        self.assertIn(m.MPC_CEREMONY_CLASS, classes)
        self.assertEqual(classes - {m.MPC_CEREMONY_CLASS}, set(m.CANONICAL_CLASSES))

    def test_scaffold_omits_ceremony_row_on_non_mpc_ws(self):
        ws = _ws()  # no anchor planted
        d = json.loads(m.scaffold(ws).read_text())
        self.assertEqual({r["class"] for r in d["classes"]}, set(m.CANONICAL_CLASSES))

    def test_ceremony_rows_emit_needs_fuzz_no_auto_credit(self):
        src = ("fn sign() {\n"
               "    let challenge = fiat_shamir(transcript);\n"
               "    let hiding_nonce = derive_nonce(seed);\n"
               "    verify_share(partial);\n"
               "}\n")
        rows = m.mpc_ceremony_rows(src, "src/scheme.rs")
        self.assertTrue(rows)
        kinds = {r["point_kind"] for r in rows}
        self.assertTrue({"fiat-shamir-transcript", "nonce-randomness-derivation",
                         "round-proof-verify"} & kinds)
        for r in rows:
            self.assertEqual(r["hypothesis_verdict"], "needs-fuzz")
            self.assertEqual(r["probe_verdict"], "")
            self.assertTrue(r["advisory"])

    def test_comment_only_scheme_mention_is_true_negative(self):
        # scheme token ONLY in a comment must not register a surface
        ws = _ws()
        (ws / "src" / "note.rs").write_text("// TODO: consider frost / xmss later\npub fn f() {}\n")
        self.assertEqual(m._mpc_scheme_files(ws), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
