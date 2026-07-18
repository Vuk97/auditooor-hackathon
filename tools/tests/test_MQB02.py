#!/usr/bin/env python3
"""MQ-B02 declared-control -> complete-mutator-set screen - non-vacuous regression.

Pins tools/declared-control-mutator-completeness-screen.py: for a declared global
control (a cap/ceiling/limit "bound", or a pause/allowlist "gate") protecting a
quantity Q, it enumerates the COMPLETE mutator-set of Q and flags an UNDER-BROAD
control = a mutator (admin/rescue/migration/alt-entrypoint) that writes Q WITHOUT
the control guard while a sibling writer DOES enforce it. This is the under-broad
dual of authority-blast-radius (A3). Every row is advisory verdict="needs-fuzz".

Non-vacuity (all three legs REQUIRED by the build spec):
  (1) PLANTED POSITIVE fires  - an un-covered migration writer past a cap flags;
      an un-gated mutator under a pause control flags.
  (2) COVERED NEGATIVE silent  - the SAME mutator, guarded by the cap check / the
      pause modifier, does not flag (the control covers the whole writer-set).
  (3) NEUTRALIZE the core predicate - monkeypatch `has_bound_guard` to a constant
      True (guard "always present"); the planted bound positive must then STOP
      firing. Proves the guard predicate is load-bearing, not decoration.
Plus: a pure DECREASE writer never needs a cap (no FP); a LOCAL/param scalar
bounded by maxShares is not a persistent cap breach (no FP); a Go struct-field
fixture fires; the advisory contract holds on every row.
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
_TOOL = TOOLS / "declared-control-mutator-completeness-screen.py"


def _load():
    spec = importlib.util.spec_from_file_location("mqb02_screen", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


MQ = _load()


def _rows(src: str, rel: str = "T.sol"):
    return MQ.scan_file(pathlib.Path(rel), rel, file_text=src)


def _fired(rows):
    return [r for r in rows if r["fires"]]


# A declared cap control (supplyCap) protecting quantity `allocation`. allocate()
# is the intended, cap-checked mutator. migrate() is the ATTACK: an alt-entrypoint
# that sets `allocation` with NO cap check - under-broad control.
SOL_POSITIVE = """
contract Vault {
    struct M { uint256 allocation; uint128 supplyCap; }
    mapping(bytes32 => M) internal caps;

    function allocate(bytes32 id, uint256 amt) external {
        caps[id].allocation += amt;
        require(caps[id].allocation <= caps[id].supplyCap, "cap");   // COVERED
    }

    function migrate(bytes32 id, uint256 amt) external {
        caps[id].allocation = amt;                                   // UN-COVERED -> FIRES
    }
}
"""

# Same object, but migrate() now re-checks the cap: the control covers the whole
# mutator-set -> nothing fires.
SOL_GUARDED = """
contract Vault {
    struct M { uint256 allocation; uint128 supplyCap; }
    mapping(bytes32 => M) internal caps;

    function allocate(bytes32 id, uint256 amt) external {
        caps[id].allocation += amt;
        require(caps[id].allocation <= caps[id].supplyCap, "cap");
    }

    function migrate(bytes32 id, uint256 amt) external {
        caps[id].allocation = amt;
        require(caps[id].allocation <= caps[id].supplyCap, "cap");   // COVERED -> SILENT
    }
}
"""

# A pure DECREASE writer never needs a cap (it cannot exceed one) -> no FP.
SOL_DECREASE = """
contract Vault {
    struct M { uint256 allocation; uint128 supplyCap; }
    mapping(bytes32 => M) internal caps;

    function allocate(bytes32 id, uint256 amt) external {
        caps[id].allocation += amt;
        require(caps[id].allocation <= caps[id].supplyCap, "cap");
    }

    function deallocate(bytes32 id, uint256 amt) external {
        caps[id].allocation -= amt;                                  // decrease - SILENT
    }
}
"""

# ERC4626-style preview math: `assets` is a LOCAL/return scalar bounded by
# maxShares. A transient stack write is not a persistent cap breach -> no row.
SOL_LOCAL = """
contract Vault {
    function previewMint(uint256 shares, uint256 maxShares) public pure
        returns (uint256 assets)
    {
        assets = shares * 2;
        require(assets <= maxShares, "max");
    }
}
"""

# Go: a struct-field counter `stored` bounded by `datacap`. insert() enforces the
# cap; forceStore() is an un-covered alt-entrypoint -> FIRES.
GO_POSITIVE = """
package pool
func (p *Pool) insert(size uint64) error {
    p.stored += size
    if p.stored > p.datacap {
        return errCapExceeded
    }
    return nil
}
func (p *Pool) forceStore(size uint64) {
    p.stored = size
}
"""

# Go slice-reset FP guard: a batch buffer `batch` bounded by `batchCap` in add()
# (the guarded sibling that appends). flush() resets the slice with `b.batch =
# b.batch[:0]` (truncate-to-empty) - a RESET that can never exceed the cap, so it
# must NOT fire. Mirrors sei dump_flatkv.go flush() (the real fleet FP).
GO_SLICE_RESET = """
package pool
func (b *Bucket) add(k, v []byte) {
    b.batch = append(b.batch, kv{k, v})
    if len(b.batch) >= batchCap {
        b.flush()
    }
}
func (b *Bucket) flush() {
    compute(b.batch)
    b.batch = b.batch[:0]
}
"""

# Go nil-reset variant: a map/slice field `pending` set back to nil (drop the
# whole container) is a reset, never a cap breach -> must NOT fire.
GO_NIL_RESET = """
package pool
func (b *Bucket) add(x item) {
    b.pending = append(b.pending, x)
    if len(b.pending) >= pendingCap {
        b.commit()
    }
}
func (b *Bucket) reset() {
    b.pending = nil
}
"""

# A declared PAUSE gate protecting `totalSupply`. mint()/deposit() are gated;
# rescueMint() is an un-gated mutator -> under-broad gate -> FIRES.
SOL_GATE_POSITIVE = """
contract Token {
    bool public paused;
    uint256 public totalSupply;

    modifier whenNotPaused() { require(!paused, "paused"); _; }

    function mint(uint256 a) external whenNotPaused { totalSupply += a; }
    function deposit(uint256 a) external whenNotPaused { totalSupply += a; }
    function rescueMint(uint256 a) external { totalSupply += a; }     // UN-GATED -> FIRES
}
"""

# Same, but rescueMint() is gated too -> the gate covers the writer-set -> SILENT.
SOL_GATE_GUARDED = """
contract Token {
    bool public paused;
    uint256 public totalSupply;

    modifier whenNotPaused() { require(!paused, "paused"); _; }

    function mint(uint256 a) external whenNotPaused { totalSupply += a; }
    function deposit(uint256 a) external whenNotPaused { totalSupply += a; }
    function rescueMint(uint256 a) external whenNotPaused { totalSupply += a; }
}
"""


class TestBoundPositiveFires(unittest.TestCase):
    def test_uncovered_migrate_fires(self):
        fired = _fired(_rows(SOL_POSITIVE))
        self.assertTrue(fired, "an un-covered cap mutator must fire")
        got = {(r["function"], r["protected_quantity"], r["control_kind"])
               for r in fired}
        self.assertIn(("migrate", "allocation", "bound"), got)

    def test_covered_mutator_silent(self):
        rows = _rows(SOL_POSITIVE)
        alloc = [r for r in rows if r["function"] == "allocate"]
        self.assertTrue(alloc, "the guarded mutator must still be enumerated")
        self.assertFalse(any(r["fires"] for r in alloc),
                         "the cap-checked mutator must NOT fire")


class TestCoveredNegativeSilent(unittest.TestCase):
    def test_full_coverage_silences(self):
        self.assertFalse(_fired(_rows(SOL_GUARDED)),
                         "when every mutator carries the cap check nothing fires")


class TestDecreaseExempt(unittest.TestCase):
    def test_pure_decrease_never_fires(self):
        rows = _rows(SOL_DECREASE)
        self.assertFalse(_fired(rows),
                         "a pure decrease writer can never exceed a cap")


class TestLocalNotFlagged(unittest.TestCase):
    def test_local_scalar_is_not_a_controlled_quantity(self):
        rows = _rows(SOL_LOCAL)
        self.assertEqual(
            [r for r in rows if r["protected_quantity"] == "assets"], [],
            "a transient local/return scalar is not a persistent cap breach")
        self.assertFalse(_fired(rows))


class TestGoPositiveFires(unittest.TestCase):
    def test_go_forcestore_fires(self):
        fired = _fired(_rows(GO_POSITIVE, rel="pool.go"))
        self.assertTrue(
            any(r["function"] == "forceStore" and r["protected_quantity"] == "stored"
                for r in fired),
            "an un-covered Go struct-field mutator past a cap must fire")


class TestGoSliceResetExempt(unittest.TestCase):
    """A Go slice truncation-to-empty (`b.batch = b.batch[:0]`) or nil-reset is a
    RESET direction, never a cap-exceeding SET -> must not fire (fleet FP:
    sei dump_flatkv.go flush())."""

    def test_classifier_treats_truncate_and_nil_as_decrease(self):
        # the direction primitive: `Q[:0]` and `nil` are resets, an arbitrary set
        # is still a cap-exceeding SET (fix is non-vacuous on the classifier).
        self.assertEqual(
            MQ._classify_direction("flush", "h.batch", "=", "h.batch[:0]", "batch"),
            "decrease")
        self.assertEqual(
            MQ._classify_direction("reset", "b.pending", "=", "nil", "pending"),
            "decrease")
        self.assertEqual(
            MQ._classify_direction("forceStore", "p.stored", "=", "size", "stored"),
            "set", "a genuine unguarded arbitrary set must still be a SET")

    def test_slice_truncate_to_empty_does_not_fire(self):
        rows = _rows(GO_SLICE_RESET, rel="pool.go")
        self.assertFalse(_fired(rows),
                         "a slice truncate-to-empty reset can never exceed a cap")
        # the reset writer is a decrease -> not enumerated as a needs-cover row;
        # only the guarded appender (`add`) is present, and it is silent.
        self.assertFalse(any(r["function"] == "flush" and r["fires"] for r in rows))

    def test_nil_reset_does_not_fire(self):
        rows = _rows(GO_NIL_RESET, rel="pool.go")
        self.assertFalse(_fired(rows),
                         "a nil reset drops the container - never a cap breach")


class TestGateArm(unittest.TestCase):
    def test_ungated_mutator_fires(self):
        fired = _fired(_rows(SOL_GATE_POSITIVE))
        self.assertTrue(
            any(r["function"] == "rescueMint" and r["control_kind"] == "gate"
                for r in fired),
            "an un-gated mutator of a pause-protected quantity must fire")

    def test_fully_gated_silent(self):
        self.assertFalse(
            any(r["fires"] and r["control_kind"] == "gate"
                for r in _rows(SOL_GATE_GUARDED)),
            "when every mutator is gated the pause control is complete -> SILENT")


class TestNeutralizeCorePredicate(unittest.TestCase):
    """Neutralizing the core bound-guard predicate makes the planted positive STOP
    firing -> the predicate is load-bearing (build-spec leg 3)."""

    def test_guard_always_true_kills_the_finding(self):
        orig = MQ.has_bound_guard
        try:
            MQ.has_bound_guard = lambda *a, **k: True
            self.assertFalse(
                _fired(_rows(SOL_POSITIVE)),
                "with the bound-guard predicate neutralized (always present) the "
                "under-broad finding must vanish - proves it is load-bearing")
        finally:
            MQ.has_bound_guard = orig

    def test_predicate_restored_fires_again(self):
        # sanity: after restore the positive fires again (no global mutation leak)
        self.assertTrue(_fired(_rows(SOL_POSITIVE)))


class TestAdvisoryContract(unittest.TestCase):
    def test_every_row_advisory_needs_fuzz(self):
        for r in _rows(SOL_POSITIVE):
            self.assertEqual(r["verdict"], "needs-fuzz")
            self.assertTrue(r["advisory"])
            self.assertFalse(r["auto_credit"])
            self.assertEqual(r["capability"], "MQB02")
            self.assertIn("file", r)
            self.assertIn("line", r)
            self.assertIn("function", r)
            self.assertIn("complete_mutator_set", r)


class TestGeneratedFileExclusion(unittest.TestCase):
    """Machine-generated source (protobuf .pulsar.go / `Code generated ... DO NOT
    EDIT`) is NOT the audited attack surface - attackers reach protobuf state via
    msg-server handlers, never the raw reflection Set/Clear plumbing. It must be
    excluded from the file walk so it never emits advisory-corpus noise. Regression:
    nuva vault.pulsar.go fired 6 codegen FPs (all 6 on the protobuf setters) before
    this exclusion; the M3 nuva-verify caught it."""

    def _tmp(self):
        import tempfile
        return pathlib.Path(tempfile.mkdtemp())

    def test_is_generated_source_classifies(self):
        d = self._tmp()
        (d / "vault.pulsar.go").write_text("package v\n")
        (d / "tx.pb.go").write_text("package v\n")
        hdr = d / "types.go"  # non-suffix name, codegen header
        hdr.write_text("// Code generated by protoc-gen-go. DO NOT EDIT.\npackage v\n")
        hand = d / "keeper.go"
        hand.write_text("package v\nfunc Do() {}\n")
        self.assertTrue(MQ._is_generated_source(d / "vault.pulsar.go"))
        self.assertTrue(MQ._is_generated_source(d / "tx.pb.go"))
        self.assertTrue(MQ._is_generated_source(hdr))
        self.assertFalse(MQ._is_generated_source(hand))

    def test_iter_source_skips_codegen_keeps_handwritten(self):
        d = self._tmp()
        (d / "vault.pulsar.go").write_text("package v\nfunc (x *V) SetTotalShares() {}\n")
        (d / "keeper.go").write_text("package v\nfunc Mutate() {}\n")
        names = {p.name for p in MQ._iter_source_files(d)}
        self.assertIn("keeper.go", names)
        self.assertNotIn("vault.pulsar.go", names)


if __name__ == "__main__":
    unittest.main()
