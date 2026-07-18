#!/usr/bin/env python3
"""MQ-B01 lifecycle-transition-graph screen - non-vacuous regression.

Pins tools/lifecycle-transition-graph-screen.py: it harvests writes to a
persisted lifecycle/status field and flags an OUT-OF-GRAPH transition = an
un-guarded status write that re-activates a terminal object, skips a mandatory
phase, or re-opens a finalized record, when the same field is a guarded state
machine (or the value re-activates). Every row is advisory verdict="needs-fuzz".

Non-vacuity (all three legs REQUIRED by the build spec):
  (1) PLANTED POSITIVE fires  - an un-guarded reopen/re-activate write flags.
  (2) GUARDED NEGATIVE silent  - the SAME write, gated by a from-status guard,
      does not flag (the trusted enforcement is present).
  (3) NEUTRALIZE the core predicate - monkeypatch `has_from_status_guard` to a
      constant True (guard "always present"); the planted positive must then STOP
      firing. This proves the guard predicate is load-bearing, not decoration.
Plus: the value gate rejects a computed (non-literal) write (timestamp) so a
non-transition field write is never a false positive; and a Go fixture fires.
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def _load():
    spec = importlib.util.spec_from_file_location(
        "lifecycle_transition_graph_screen_t",
        TOOLS / "lifecycle-transition-graph-screen.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


MQ = _load()


def _rows(src: str, rel: str = "T.sol"):
    return MQ.scan_file(pathlib.Path(rel), rel, file_text=src)


def _fired(rows):
    return [r for r in rows if r["fires"]]


# A guarded state machine: resolve() is the intended terminal edge (guarded by
# the from-status precondition). reopen() is the ATTACK edge: it re-activates a
# settled object with NO from-status guard.
SOL_POSITIVE = """
contract Escrow {
    enum Status { Open, Settled, Cancelled }
    Status public status;

    function settle() external {
        require(status == Status.Open, "not open");
        status = Status.Settled;                 // guarded terminal edge - SILENT
    }

    function reopen() external {
        status = Status.Open;                    // UN-GUARDED re-activate - FIRES
    }
}
"""

# Same object, but reopen() now asserts the from-status: the trusted enforcement
# is present, so the state machine is sound and nothing fires.
SOL_GUARDED = """
contract Escrow {
    enum Status { Open, Settled, Cancelled }
    Status public status;

    function settle() external {
        require(status == Status.Open, "not open");
        status = Status.Settled;
    }

    function reopen() external {
        require(status == Status.Cancelled, "only from cancelled");
        status = Status.Open;                    // guarded - SILENT
    }
}
"""

# A field WRITE whose value is a computed timestamp, not a status literal: must
# NOT be treated as a lifecycle edge (value-gate rejects it -> no FP row).
SOL_COMPUTED_VALUE = """
contract Game {
    enum Status { InProgress, Resolved }
    Status public status;
    uint256 public resolvedAt;

    function resolve() external {
        resolvedAt = block.timestamp;            // NOT a status edge - no row
        status = Status.Resolved;
    }
}
"""

# Go fixture: an un-guarded write flipping a settled order back to Open, while
# the field is guarded elsewhere.
GO_POSITIVE = """
package order
func (o *Order) Fill() error {
    if o.Status != StatusOpen {
        return errBadState
    }
    o.Status = StatusFilled
    return nil
}
func (o *Order) ForceOpen() {
    o.Status = StatusOpen
}
"""


class TestPositiveFires(unittest.TestCase):
    def test_unguarded_reopen_fires(self):
        rows = _rows(SOL_POSITIVE)
        fired = _fired(rows)
        self.assertTrue(fired, "un-guarded re-activate write must fire")
        got = {(r["function"], r["status_field"]) for r in fired}
        self.assertIn(("reopen", "status"), got)

    def test_guarded_terminal_edge_silent(self):
        rows = _rows(SOL_POSITIVE)
        settle = [r for r in rows if r["function"] == "settle"]
        self.assertTrue(settle, "settle() status write should be enumerated")
        self.assertFalse(any(r["fires"] for r in settle),
                         "the guarded terminal edge must NOT fire")

    def test_go_forceopen_fires(self):
        rows = _rows(GO_POSITIVE, rel="order.go")
        fired = _fired(rows)
        self.assertTrue(any(r["function"] == "ForceOpen" for r in fired),
                        "un-guarded Go re-open must fire")


class TestGuardedNegativeSilent(unittest.TestCase):
    def test_from_status_guard_silences(self):
        rows = _rows(SOL_GUARDED)
        self.assertFalse(_fired(rows),
                         "a from-status-guarded reopen must be SILENT")


class TestValueGate(unittest.TestCase):
    def test_computed_value_not_a_lifecycle_edge(self):
        rows = _rows(SOL_COMPUTED_VALUE)
        # resolvedAt <- block.timestamp is a computed value, never an edge
        bad = [r for r in rows if r["status_field"] == "resolvedAt"]
        self.assertEqual(bad, [], "a timestamp write must not be a status edge")


class TestNeutralizeCorePredicate(unittest.TestCase):
    """Neutralizing the core guard predicate makes the planted positive STOP
    firing -> the predicate is load-bearing (build-spec leg 3)."""

    def test_guard_always_true_kills_the_finding(self):
        orig = MQ.has_from_status_guard
        try:
            MQ.has_from_status_guard = lambda *a, **k: True
            rows = _rows(SOL_POSITIVE)
            self.assertFalse(
                _fired(rows),
                "with the guard predicate neutralized (always present) the "
                "out-of-graph finding must vanish - proves it is load-bearing")
        finally:
            MQ.has_from_status_guard = orig

    def test_predicate_restored_fires_again(self):
        # sanity: after restore the positive fires again (no global mutation leak)
        rows = _rows(SOL_POSITIVE)
        self.assertTrue(_fired(rows))


# --- delegated-guard / init FP regressions (fleet-observed false positives) ---
# (a) delegated from-status guard: the write is preceded by a call passing a
#     status enum-member to a private reverting helper (`_checkState(self,
#     State.Opened)`) - lido WithdrawalsBatchesQueue open()/close().
SOL_DELEGATED_CHECKSTATE = """
library Queue {
    enum State { NotInitialized, Opened, Closed }
    struct Ctx { State state; }
    function open(Ctx storage self) internal {
        _checkState(self, State.NotInitialized);
        self.state = State.Opened;
    }
    function close(Ctx storage self) internal {
        _checkState(self, State.Opened);
        self.state = State.Closed;
    }
    function _checkState(Ctx storage self, State expected) private view {
        if (self.state != expected) revert("bad state");
    }
}
"""

# (a) delegated transition: the to-status is the OUTPUT of a state-transition
#     helper, so legality is delegated - lido DualGovernanceStateMachine
#     activateNextState().
SOL_DELEGATED_TRANSITION = """
contract DG {
    enum State { NotInitialized, Normal, VetoSignalling, RageQuit }
    State state;
    function activateNextState() internal {
        (State currentState, State newState) = getStateTransition();
        if (currentState == newState) { return; }
        state = newState;
    }
    function getStateTransition() internal view returns (State, State) {}
}
"""

# (b) fresh-slot init: the status write targets a just-incremented index slot
#     (`id = ++count; slot = coll[id]; slot.status = ...`) - creating a new
#     record, not re-activating one - lido ExecutableProposals submit().
SOL_FRESH_SLOT = """
library Proposals {
    enum Status { NotExist, Submitted, Executed }
    struct Data { Status status; }
    struct Proposal { Data data; }
    struct Ctx { uint256 proposalsCount; mapping(uint256 => Proposal) proposals; }
    function submit(Ctx storage self) internal returns (uint256 newProposalId) {
        newProposalId = ++self.proposalsCount;
        Proposal storage newProposal = self.proposals[newProposalId];
        newProposal.data.status = Status.Submitted;
    }
}
"""


class TestDelegatedGuardSilent(unittest.TestCase):
    def test_checkstate_helper_silences(self):
        rows = _rows(SOL_DELEGATED_CHECKSTATE)
        self.assertFalse(_fired(rows),
                         "an enum-member arg passed to a reverting helper is a "
                         "delegated from-status guard - must be SILENT")
        # both writes must still be enumerated (non-vacuous coverage)
        got = {r["function"] for r in rows}
        self.assertIn("open", got)
        self.assertIn("close", got)

    def test_transition_output_silences(self):
        rows = _rows(SOL_DELEGATED_TRANSITION)
        self.assertFalse(_fired(rows),
                         "a to-status that is the output of a state-transition "
                         "helper has delegated legality - must be SILENT")
        self.assertTrue([r for r in rows if r["function"] == "activateNextState"],
                        "the delegated write must still be enumerated")


class TestFreshSlotInit(unittest.TestCase):
    def test_fresh_index_slot_is_init(self):
        rows = _rows(SOL_FRESH_SLOT)
        submit = [r for r in rows if r["function"] == "submit"]
        self.assertTrue(submit, "submit() status write must be enumerated")
        self.assertTrue(all(r["is_init_fn"] for r in submit),
                        "a write to a freshly-incremented index slot is INIT")
        self.assertFalse(_fired(rows),
                         "creating a new record is not an out-of-graph edge")


class TestGenuinelyUnguardedStillFires(unittest.TestCase):
    """The FP fix must NOT swallow a real unguarded re-activation: a helper call
    with NO status-enum arg and no transition output leaves the write exposed."""

    def test_unrelated_helper_call_does_not_suppress(self):
        src = """
        contract C {
            enum Status { Open, Settled }
            Status public status;
            function settle() external {
                require(status == Status.Open);
                status = Status.Settled;
            }
            function reopen() external {
                _log(msg.sender, 42);      // helper, NO status-enum arg
                status = Status.Open;      // still UN-guarded -> FIRES
            }
            function _log(address a, uint256 n) private {}
        }
        """
        fired = _fired(_rows(src))
        self.assertTrue(any(r["function"] == "reopen" for r in fired),
                        "an unrelated helper call must not suppress a real finding")


class TestAdvisoryContract(unittest.TestCase):
    def test_every_row_advisory_needs_fuzz(self):
        rows = _rows(SOL_POSITIVE)
        for r in rows:
            self.assertEqual(r["verdict"], "needs-fuzz")
            self.assertTrue(r["advisory"])
            self.assertFalse(r["auto_credit"])
            self.assertEqual(r["capability"], "MQB01")
            self.assertIn("file", r)
            self.assertIn("line", r)
            self.assertIn("function", r)


class TestGeneratedFileExclusion(unittest.TestCase):
    """Machine-generated source (protobuf .pulsar.go / `Code generated ... DO NOT
    EDIT`) is NOT the audited attack surface - attackers reach protobuf state via
    msg-server handlers, never the raw reflection Set/Clear plumbing. It must be
    excluded from the file walk so it never emits advisory-corpus noise. Regression:
    nuva vault.pulsar.go fired lifecycle-transition FPs on the protobuf Clear/Set
    setters before this exclusion; the M3 nuva-verify caught it."""

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
        (d / "vault.pulsar.go").write_text("package v\nfunc (x *V) Clear() {}\n")
        (d / "keeper.go").write_text("package v\nfunc Mutate() {}\n")
        names = {p.name for p in MQ._iter_source_files(d)}
        self.assertIn("keeper.go", names)
        self.assertNotIn("vault.pulsar.go", names)


if __name__ == "__main__":
    unittest.main()
