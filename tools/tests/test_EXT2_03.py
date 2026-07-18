#!/usr/bin/env python3
"""EXT2-03 fail-open-classifier default-arm screen - non-vacuous regression.

Pins tools/failopen-classifier-default-arm-screen.py: the kora-lib class
(GHSA-x442-m7cc-hr92). A parser/classifier maps untrusted input to known variants;
its DEFAULT / catch-all arm constructs a PERMISSIVE EMPTY stub (empty set / zero /
nil-no-error / Default::default) that a separate downstream policy checker reads as
compliant - "I do not recognise this" silently collapses into "this is allowed".
The fire signal is the EMPTY-STUB ASYMMETRY: >=1 enumerated arm CONSTRUCTS a
non-empty value while the default constructs emptiness.

Non-vacuity (all three legs REQUIRED by the build spec):
  (1) PLANTED POSITIVE fires  - a Rust `match` on an instruction variant whose known
      arms build a HashSet of touched accounts and whose `_ =>` returns
      HashSet::new(); and a Go type/value `switch` whose known cases build a struct
      and whose `default:` returns nil,nil. Both flag (permissive_empty default +
      substantive siblings).
  (2) COVERED/benign NEGATIVE silent - the SAME dispatch whose default REJECTS
      (Err / fmt.Errorf), a default that is a REAL fallback (substantive), a
      side-effect-only `match` (no value), and a conditionless Go `switch {}`
      guard-chain, do not flag.
  (3) NEUTRALIZE the core predicate - monkeypatch `_default_arm_fails_open` to a
      constant False; the planted positives must then STOP firing. Proves the
      empty-stub-asymmetry predicate is load-bearing, not decoration.
Plus: the advisory contract (verdict/advisory/auto_credit) holds on every row; the
mandated synthetic/codegen/test exclusions are honoured; a REAL fleet file (near
trie node encoding, whose unknown-discriminant default PANICS = fails closed) stays
silent - no FP-spray - and a byte-level fail-open weakening of that same real default
FIRES (embedded mutation-verify).
"""
from __future__ import annotations

import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
_TOOL = TOOLS / "failopen-classifier-default-arm-screen.py"
_FLEET_ENCODING = pathlib.Path(
    "/Users/wolf/audits/near/src/core/store/src/trie/mem/node/encoding.rs")


def _load():
    spec = importlib.util.spec_from_file_location("ext2_03_screen", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


MOD = _load()


def _rows(src: str, rel: str):
    return MOD.scan_file(pathlib.Path(rel), rel, file_text=src)


def _fired(rows):
    return [r for r in rows if r["fires"]]


# --- fixtures ---------------------------------------------------------------
# POSITIVE (Rust): the kora shape. Known Solana programs -> the set of touched
# accounts; UNKNOWN program -> empty set, which a fee-payer policy reads as
# "nothing to forbid" and approves.
POS_RUST = """
fn touched_accounts(ix: &Instruction) -> HashSet<Pubkey> {
    match ix.program_id {
        SYSTEM_PROGRAM => HashSet::from([ix.from, ix.to]),
        TOKEN_PROGRAM  => HashSet::from([ix.owner, ix.mint]),
        _ => HashSet::new(),
    }
}
"""

# POSITIVE (Go): known message codes build a handler; unknown -> nil, nil (no error).
POS_GO = """
func parseInstruction(code uint8) (*Handler, error) {
    switch code {
    case 1:
        return &Handler{Name: "transfer", Accounts: two}, nil
    case 2:
        return &Handler{Name: "approve", Accounts: one}, nil
    default:
        return nil, nil
    }
}
"""

# POSITIVE (Go type-switch): the real-geth shape - unknown dynamic type -> zero value.
POS_GO_TYPESWITCH = """
func addrOf(a net.Addr) netip.Addr {
    switch v := a.(type) {
    case *net.IPAddr:
        return ipToAddr(v.IP)
    case *net.TCPAddr:
        return ipToAddr(v.IP)
    default:
        return netip.Addr{}
    }
}
"""

# NEGATIVE (Rust reject): the sound original - unknown variant REJECTED.
NEG_RUST_REJECT = """
fn touched_accounts(ix: &Instruction) -> Result<HashSet<Pubkey>, Error> {
    match ix.program_id {
        SYSTEM_PROGRAM => Ok(HashSet::from([ix.from, ix.to])),
        TOKEN_PROGRAM  => Ok(HashSet::from([ix.owner])),
        _ => Err(Error::UnknownProgram),
    }
}
"""

# NEGATIVE (Rust real fallback): default returns a genuine non-empty value, not a
# permissive empty stub - not fail-open, must not fire.
NEG_RUST_FALLBACK = """
fn weights(kind: u8) -> Vec<u8> {
    match kind {
        1 => vec![10, 20],
        2 => vec![30, 40],
        _ => vec![99, 99, 99],
    }
}
"""

# NEGATIVE (Rust statement match): side-effect arms, no value produced - not a
# value classifier, must not be an enforcement point at all.
NEG_RUST_STMT = """
fn handle(&mut self, e: Event) {
    match e {
        Event::A => { self.on_a(); }
        Event::B => { self.on_b(); }
        _ => {}
    }
}
"""

# NEGATIVE (Go reject): default returns an error.
NEG_GO_REJECT = """
func parseInstruction(code uint8) (*Handler, error) {
    switch code {
    case 1:
        return &Handler{Name: "transfer"}, nil
    case 2:
        return &Handler{Name: "approve"}, nil
    default:
        return nil, fmt.Errorf("unknown instruction code %d", code)
    }
}
"""

# NEGATIVE (Go conditionless switch): `switch {}` guard-chain with a safe 0 fallback
# is NOT an untrusted-variant classifier - must not be an enforcement point.
NEG_GO_CONDITIONLESS = """
func maxBlobs(cfg *ChainConfig) int {
    switch {
    case cfg.Osaka != nil:
        return cfg.Osaka.Max
    case cfg.Prague != nil:
        return cfg.Prague.Max
    default:
        return 0
    }
}
"""

# Rust lifetime torture: `'a` / `'static` lifetimes and a string near a `match` must
# NOT be masked as char literals (which would eat newlines and mis-shift line
# numbers - the masker regression this pins). The default REJECTS so it stays silent,
# but is still an enumerated point (substantive Config{} arms) at the CORRECT line.
LIFETIME_MASK = """
fn borrow<'a>(&'a self, k: u8) -> Result<Config, Error> {
    let s: &'static str = "unused";
    match k {
        1 => Ok(Config { a: 1, b: 2 }),
        2 => Ok(Config { a: 3, b: 4 }),
        _ => Err(Error::Unknown),
    }
}
"""


class Ext2_03Screen(unittest.TestCase):
    # ---- leg 1: planted positives fire ----
    def test_positive_rust_fires(self):
        rows = _rows(POS_RUST, "instruction.rs")
        fired = _fired(rows)
        self.assertEqual(len(fired), 1, rows)
        r = fired[0]
        self.assertEqual(r["dispatch_kind"], "match")
        self.assertEqual(r["default_disposition"], "permissive_empty")
        self.assertGreaterEqual(r["substantive_siblings"], 1)
        self.assertTrue(r["classifier_context"])
        self.assertTrue(r["severity_eligible"])

    def test_positive_go_fires(self):
        rows = _rows(POS_GO, "parser.go")
        fired = _fired(rows)
        self.assertEqual(len(fired), 1, rows)
        self.assertEqual(fired[0]["dispatch_kind"], "switch")
        self.assertEqual(fired[0]["default_disposition"], "permissive_empty")

    def test_positive_go_typeswitch_fires(self):
        rows = _rows(POS_GO_TYPESWITCH, "addr.go")
        fired = _fired(rows)
        self.assertEqual(len(fired), 1, rows)
        self.assertEqual(fired[0]["default_disposition"], "permissive_empty")

    # ---- leg 2: benign negatives silent ----
    def test_negative_rust_reject_silent(self):
        rows = _rows(NEG_RUST_REJECT, "instruction.rs")
        self.assertEqual(_fired(rows), [])
        # still enumerated as a sound (fail-closed) enforcement point.
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["default_disposition"], "reject")

    def test_negative_rust_real_fallback_no_row(self):
        # default is substantive -> not a fail-open candidate -> no row emitted.
        self.assertEqual(_rows(NEG_RUST_FALLBACK, "w.rs"), [])

    def test_negative_rust_statement_match_no_row(self):
        # side-effect-only match, no value -> not a value classifier.
        self.assertEqual(_rows(NEG_RUST_STMT, "h.rs"), [])

    def test_negative_go_reject_silent(self):
        rows = _rows(NEG_GO_REJECT, "parser.go")
        self.assertEqual(_fired(rows), [])
        self.assertEqual(rows[0]["default_disposition"], "reject")

    def test_negative_go_conditionless_no_row(self):
        # `switch {}` guard-chain is not an untrusted-variant classifier.
        self.assertEqual(_rows(NEG_GO_CONDITIONLESS, "blobs.go"), [])

    # ---- leg 3: neutralize the core predicate -> positives stop firing ----
    def test_neutralize_core_predicate_kills_positives(self):
        orig = MOD._default_arm_fails_open
        try:
            MOD._default_arm_fails_open = lambda disp, sib: False
            self.assertEqual(_fired(_rows(POS_RUST, "instruction.rs")), [],
                             "rust positive still fired after neutralizing predicate")
            self.assertEqual(_fired(_rows(POS_GO, "parser.go")), [])
            self.assertEqual(_fired(_rows(POS_GO_TYPESWITCH, "addr.go")), [])
        finally:
            MOD._default_arm_fails_open = orig
        # sanity: restored predicate fires again
        self.assertEqual(len(_fired(_rows(POS_RUST, "instruction.rs"))), 1)

    # ---- masker regression: lifetimes must not shift line numbers ----
    def test_lifetime_does_not_shift_lines(self):
        rows = _rows(LIFETIME_MASK, "borrow.rs")
        # the match rejects (Err default) -> silent, and its default line must be the
        # actual `_ => Err(...)` line (7, 1-indexed), not shifted by lifetime masking.
        self.assertEqual(_fired(rows), [])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["default_disposition"], "reject")
        self.assertEqual(rows[0]["default_arm_line"], 7)

    # ---- advisory contract on every row ----
    def test_advisory_contract(self):
        for src, rel in ((POS_RUST, "a.rs"), (POS_GO, "b.go"),
                         (NEG_RUST_REJECT, "c.rs"), (NEG_GO_REJECT, "d.go")):
            for r in _rows(src, rel):
                self.assertEqual(r["capability"], "EXT2_03")
                self.assertTrue(r["advisory"])
                self.assertFalse(r["auto_credit"])
                self.assertEqual(r["verdict"], "needs-fuzz")
                self.assertIn("question", r)
                self.assertIn(r["default_disposition"],
                              ("permissive_empty", "reject", "other"))

    # ---- mandated exclusions: test / codegen / chimera dropped ----
    def test_synthetic_exclusions_applied(self):
        import tempfile
        import os
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "prod.rs").write_text(POS_RUST)
            (root / "prod_test.rs").write_text(POS_RUST)          # test file
            (root / "gen.pb.go").write_text(POS_GO)               # codegen suffix
            gen = root / "stringer.go"
            gen.write_text("// Code generated by stringer. DO NOT EDIT.\n" + POS_GO)
            os.makedirs(root / "chimera_harnesses", exist_ok=True)
            (root / "chimera_harnesses" / "M.rs").write_text(POS_RUST)
            yielded = {p.name for p in MOD._iter_source_files(root)}
        self.assertIn("prod.rs", yielded)
        self.assertNotIn("prod_test.rs", yielded)
        self.assertNotIn("gen.pb.go", yielded)
        self.assertNotIn("stringer.go", yielded)
        self.assertNotIn("M.rs", yielded)

    # ---- real fleet file: unknown-discriminant PANIC default stays silent ----
    def test_real_fleet_reject_default_no_false_positive(self):
        if not _FLEET_ENCODING.exists():
            self.skipTest("fleet file absent")
        rows = MOD.scan_file(_FLEET_ENCODING, _FLEET_ENCODING.name)
        vk = [r for r in rows if r["function"] == "view_kind"]
        self.assertTrue(vk, "view_kind dispatch not enumerated")
        # the real default is `_ => panic!("unknown node type")` = fail-closed.
        self.assertEqual(vk[0]["default_disposition"], "reject")
        self.assertFalse(vk[0]["fires"])

    # ---- embedded mutation-verify: fail-open weakening of the SAME real default ----
    def test_real_fleet_failopen_mutation_fires(self):
        if not _FLEET_ENCODING.exists():
            self.skipTest("fleet file absent")
        raw = _FLEET_ENCODING.read_text()
        needle = '_ => panic!("unknown node type"),'
        self.assertEqual(raw.count(needle), 1, "mutation anchor not unique")
        mutant = raw.replace(needle, "_ => Default::default(),")
        rows = MOD.scan_file(_FLEET_ENCODING, _FLEET_ENCODING.name, file_text=mutant)
        vk = [r for r in rows if r["function"] == "view_kind"][0]
        self.assertEqual(vk["default_disposition"], "permissive_empty")
        self.assertTrue(vk["fires"], "fail-open mutation of a real classifier not caught")


if __name__ == "__main__":
    unittest.main()
