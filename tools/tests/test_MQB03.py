#!/usr/bin/env python3
"""test_MQB03.py - deferred-execution param-binding screen (MQ-B03).

Covers tools/deferred-execution-param-binding-screen.py, an advisory-first,
NO-AUTO-CREDIT (verdict='needs-fuzz') GENERAL enforcement screen for the two-phase
authorize-then-execute trust boundary. The private invariant: an execute-phase
function that is gated on a COMMITTED request R (readiness-field check, or a
hash/proof/signature-verified struct) must REPLAY R's security-relevant params
into its sinks - never RE-READ amount/recipient/target/value/price from mutable
state that an attacker can move between the two phases.

Non-vacuity / mutation-kill:
  - PLANTED positives (execute path re-reads a mutable state var / live getter /
    block.timestamp into a security-relevant sink) FIRE;
  - GUARDED negatives (execute path replays R.<field>; no bound handle; sink arg
    is inert) stay SILENT;
  - neutralising the CORE predicate (_classify_arg no longer distinguishes a
    mutable-state re-read) makes the PLANTED positive test FAIL - proving the
    re-derivation predicate is load-bearing, not decorative.

Natural fleet instances (read-only, temp copy only, verified in the build):
  - morpho MetaMorpho.acceptTimelock `_setTimelock(pendingTimelock.value)` is
    SILENT; mutating the replay to `_setTimelock(timelock)` (re-read the current
    mutable state var) FIRES.
  - optimism OptimismPortal2.finalizeWithdrawalTransactionExternalProof
    `callWithMinGas(_tx.target, ...)` is SILENT; mutating `_tx.target` to the
    mutable `l2Sender` state var FIRES.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "deferred-execution-param-binding-screen.py"


def _load():
    spec = importlib.util.spec_from_file_location("mqb03_screen", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["mqb03_screen"] = mod
    spec.loader.exec_module(mod)
    return mod


# --- synthetic Solidity fixtures ------------------------------------------------ #

# POSITIVE 1: execute path (accept*, gated on pending.validAt) re-reads the CURRENT
# mutable `feeRate` state var into the setter instead of replaying pending.value.
POS_STATE_REREAD = """
contract Timelocked {
    uint256 public feeRate;
    PendingUint public pending;
    modifier afterTimelock(uint256 v) { require(block.timestamp >= v); _; }
    function submit(uint256 newRate) external { pending.value = newRate; pending.validAt = block.timestamp + 1 days; }
    function acceptFee() external afterTimelock(pending.validAt) {
        _setFee(feeRate);            // VIOLATOR: re-reads live feeRate, not pending.value
    }
    function _setFee(uint256 v) internal { feeRate = v; }
}
"""

# POSITIVE 2: hash-committed withdrawal, but the low-level call target is re-read from
# a mutable `router` state var instead of the bound `_tx.target`.
POS_HASHBOUND_TARGET = """
contract Portal {
    address public router;
    mapping(bytes32 => bool) public finalized;
    function finalize(WithdrawalTx memory _tx) external {
        bytes32 h = keccak256(abi.encode(_tx));
        require(!finalized[h]);
        finalized[h] = true;
        SafeCall.callWithMinGas(router, _tx.gasLimit, _tx.value, _tx.data);  // VIOLATOR: router re-read
    }
}
"""

# POSITIVE 3: execute path re-reads a live external getter for the amount.
POS_LIVE_GETTER = """
contract Queue {
    IERC20 public token;
    mapping(uint256 => Req) public requests;
    function claim(uint256 id) external {
        Req memory r = requests[id];
        require(block.timestamp >= r.readyAt);
        token.safeTransfer(r.recipient, token.balanceOf(address(this)));  // VIOLATOR: live balanceOf amount
    }
}
"""

# NEGATIVE 1: correct replay - the setter receives pending.value (the bound param).
NEG_REPLAY = """
contract Timelocked {
    uint256 public feeRate;
    PendingUint public pending;
    modifier afterTimelock(uint256 v) { require(block.timestamp >= v); _; }
    function acceptFee() external afterTimelock(pending.validAt) {
        _setFee(pending.value);      // SAFE: replays the bound value
    }
    function _setFee(uint256 v) internal { feeRate = v; }
}
"""

# NEGATIVE 2: correct replay of the hash-bound tx fields.
NEG_HASHBOUND_REPLAY = """
contract Portal {
    address public router;
    mapping(bytes32 => bool) public finalized;
    function finalize(WithdrawalTx memory _tx) external {
        bytes32 h = keccak256(abi.encode(_tx));
        require(!finalized[h]);
        finalized[h] = true;
        SafeCall.callWithMinGas(_tx.target, _tx.gasLimit, _tx.value, _tx.data);  // SAFE
    }
}
"""

# NEGATIVE 3: NOT a two-phase flow - no bound handle (no readiness check, no verify).
# A plain setter re-reading state is out of class and must stay silent.
NEG_NO_BOUND_HANDLE = """
contract Plain {
    uint256 public feeRate;
    function setFee() external {
        _setFee(feeRate);            // no committed request -> not an enforcement point
    }
    function _setFee(uint256 v) internal { feeRate = v; }
}
"""

# NEGATIVE 4: bound handle present, but the sink arg is inert (msg.sender / constant).
NEG_INERT_ARG = """
contract Timelocked {
    PendingAddr public pending;
    modifier afterTimelock(uint256 v) { require(block.timestamp >= v); _; }
    function acceptGuardian() external afterTimelock(pending.validAt) {
        _setGuardian(pending.value);
        emit Accepted(msg.sender, address(this));  // inert args, not a value-mover sink
    }
    function _setGuardian(address v) internal {}
}
"""

# NEGATIVE 5 (FP regression - immutable): a hash-committed withdrawal whose transfer TOKEN
# is an `immutable` state var. An immutable cannot move between authorize and execute, so a
# read of it is inert, NOT an attacker-drivable re-derivation. (reserve-governor
# UnstakingManager.claimLock: `safeTransfer(targetToken, lock.user, lock.amount)` with
# `IERC20 public immutable targetToken`.)
NEG_IMMUTABLE_SINK = """
contract UnstakingManager {
    IERC20 public immutable targetToken;
    mapping(uint256 => Lock) public locks;
    function claimLock(uint256 lockId) external {
        Lock memory lock = locks[lockId];
        require(block.timestamp >= lock.unlockTime);
        SafeERC20.safeTransfer(targetToken, lock.user, lock.amount);  // targetToken immutable -> inert
    }
}
"""

# NEGATIVE 6 (FP regression - bogus block handle): a plain single-phase function whose ONLY
# `.timestamp`/`.number` read is on the EVM builtin `block`. `block.*` must never fabricate a
# committed request R, so re-reading a mutable state var here is out of class -> silent.
# (polygon PolygonRollupBaseEtrogPrevious.sequenceForceBatches / PolygonZkEVM path.)
NEG_BLOCK_HANDLE = """
contract Rollup {
    uint256 public feeRate;
    function poke() external {
        require(block.timestamp > 0);            // block is NOT a stored request
        _setFee(feeRate);                        // no committed request -> not an enforcement point
    }
    function _setFee(uint256 v) internal { feeRate = v; }
}
"""

# NEGATIVE 7 (FP regression - input-derived local): a loop copies each element of a function
# INPUT array into a local (`currentBatch = batches[i]`) and reads `currentBatch.timestamp`.
# That local is the FRESH single-phase input being validated, NOT a previously-committed
# stored request, so its bind-field read must not fabricate a two-phase handle. Re-reading the
# mutable `batchFee` here is correct single-phase behaviour. (polygon PolygonZkEVM.sequenceBatches.)
NEG_INPUT_LOCAL_HANDLE = """
contract ZkEVM {
    uint256 public batchFee;
    IERC20 public matic;
    function sequenceBatches(BatchData[] calldata batches, address coinbase) external {
        uint256 n = batches.length;
        for (uint256 i = 0; i < n; i++) {
            BatchData memory currentBatch = batches[i];
            require(currentBatch.timestamp <= block.timestamp);
        }
        matic.safeTransferFrom(msg.sender, address(this), batchFee * n);  // single-phase fee, not a re-derive
    }
}
"""

# POSITIVE 4 (immutable present but the re-read is a genuine MUTABLE storage var): proves the
# immutable exclusion is surgical - an immutable elsewhere in the contract does not suppress a
# real re-derivation of a mutable state var across a committed request.
POS_MUTABLE_REREAD_WITH_IMMUTABLE = """
contract Timelocked {
    address public immutable admin;      // immutable present but irrelevant to the sink
    uint256 public feeRate;              // MUTABLE - attacker-movable between phases
    PendingUint public pending;
    modifier afterTimelock(uint256 v) { require(block.timestamp >= v); _; }
    function acceptFee() external afterTimelock(pending.validAt) {
        _setFee(feeRate);                // VIOLATOR: re-reads mutable feeRate, not pending.value
    }
    function _setFee(uint256 v) internal { feeRate = v; }
}
"""

# Go POSITIVE: execute-phase keeper re-reads a live balance getter for the send amount.
GO_POS = """
package keeper
func (k Keeper) ExecuteWithdrawal(ctx Context, id uint64) error {
    req := k.GetWithdrawal(ctx, id)
    amt := k.GetBalance(ctx, req.Recipient)
    return k.bankKeeper.SendCoins(ctx, req.Recipient, amt)  // VIOLATOR: live GetBalance amount
}
"""

# Go NEGATIVE: replays the bound request amount.
GO_NEG = """
package keeper
func (k Keeper) ExecuteWithdrawal(ctx Context, id uint64) error {
    req := k.GetWithdrawal(ctx, id)
    return k.bankKeeper.SendCoins(ctx, req.Recipient, req.Amount)  // SAFE: replays bound amount
}
"""


class TestMQB03(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _sol(self, text):
        return self.m.scan_file_sol(Path("X.sol"), "X.sol", file_text=text)

    def _go(self, text):
        return self.m.scan_file_go(Path("X.go"), "X.go", file_text=text)

    # ---- planted positives fire ------------------------------------------- #
    def test_pos_state_reread_fires(self):
        rows = self._sol(POS_STATE_REREAD)
        self.assertTrue(rows, "re-read of mutable state var into setter must fire")
        r = rows[0]
        self.assertEqual(r["verdict"], "needs-fuzz")
        self.assertFalse(r["auto_credit"])
        self.assertTrue(r["advisory"])
        self.assertEqual(r["capability"], "MQB03-deferred-execution-param-binding")
        self.assertIn("feeRate", r["re_derived_arg"])
        self.assertIn("pending", r["bound_handle"])

    def test_pos_hashbound_target_fires(self):
        rows = self._sol(POS_HASHBOUND_TARGET)
        self.assertTrue(rows, "hash-committed tx with re-read call target must fire")
        self.assertTrue(any(r["re_derived_arg"] == "router" for r in rows))
        self.assertTrue(any("_tx" in r["bound_handle"] for r in rows))

    def test_pos_live_getter_fires(self):
        rows = self._sol(POS_LIVE_GETTER)
        self.assertTrue(rows, "live balanceOf() amount in a claim must fire")
        self.assertTrue(any("balanceOf" in r["re_derived_arg"] for r in rows))

    # ---- guarded negatives stay silent ------------------------------------ #
    def test_neg_replay_silent(self):
        self.assertEqual(self._sol(NEG_REPLAY), [])

    def test_neg_hashbound_replay_silent(self):
        self.assertEqual(self._sol(NEG_HASHBOUND_REPLAY), [])

    def test_neg_no_bound_handle_silent(self):
        self.assertEqual(self._sol(NEG_NO_BOUND_HANDLE), [])

    def test_neg_inert_arg_silent(self):
        self.assertEqual(self._sol(NEG_INERT_ARG), [])

    # ---- FP regressions (constant/immutable + bogus block/input-local handle) ---- #
    def test_neg_immutable_sink_silent(self):
        """An immutable transfer token cannot move between phases -> must not fire
        (reserve-governor UnstakingManager.claimLock targetToken)."""
        self.assertEqual(self._sol(NEG_IMMUTABLE_SINK), [])

    def test_neg_block_handle_silent(self):
        """block.timestamp is a live global, not a stored request -> no enforcement
        point (polygon rollup single-phase path)."""
        self.assertEqual(self._sol(NEG_BLOCK_HANDLE), [])

    def test_neg_input_local_handle_silent(self):
        """A per-call copy of a function INPUT array element is the fresh single-phase
        input, not a committed request -> must not fire (polygon PolygonZkEVM
        sequenceBatches currentBatch/batchFee)."""
        self.assertEqual(self._sol(NEG_INPUT_LOCAL_HANDLE), [])

    def test_pos_mutable_reread_with_immutable_still_fires(self):
        """The immutable exclusion is surgical: a genuine re-read of a MUTABLE state var
        across a real two-phase (pending.validAt) flow still fires even when an unrelated
        immutable exists in the contract."""
        rows = self._sol(POS_MUTABLE_REREAD_WITH_IMMUTABLE)
        self.assertTrue(rows, "genuine mutable-state re-derive must still fire")
        self.assertTrue(any("feeRate" in r["re_derived_arg"] for r in rows))
        self.assertTrue(any("pending" in r["bound_handle"] for r in rows))

    # ---- Go arm ----------------------------------------------------------- #
    def test_go_pos_fires(self):
        rows = self._go(GO_POS)
        self.assertTrue(rows, "Go execute re-reading GetBalance amount must fire")
        self.assertEqual(rows[0]["lang"], "go")
        self.assertEqual(rows[0]["verdict"], "needs-fuzz")

    def test_go_neg_silent(self):
        self.assertEqual(self._go(GO_NEG), [])

    # ---- advisory-first contract ------------------------------------------ #
    def test_advisory_never_autocredits(self):
        for r in self._sol(POS_STATE_REREAD) + self._go(GO_POS):
            self.assertFalse(r["auto_credit"])
            self.assertTrue(r["advisory"])
            self.assertEqual(r["verdict"], "needs-fuzz")

    # ---- CORE-PREDICATE neutralisation: positive MUST then fail ----------- #
    def test_neutralised_predicate_kills_positive(self):
        """If _classify_arg no longer distinguishes a mutable-state re-read (always
        returns 'replayed'), the PLANTED positive stops firing - proving the
        re-derivation predicate is the load-bearing core, not decoration."""
        orig = self.m._classify_arg
        try:
            self.m._classify_arg = lambda arg, sv, br: "replayed"
            rows = self._sol(POS_STATE_REREAD)
            # under the neutralised predicate the positive no longer fires:
            self.assertEqual(rows, [],
                             "neutralising the re-derivation predicate should silence "
                             "the planted positive (predicate is load-bearing)")
        finally:
            self.m._classify_arg = orig
        # and it fires again once restored (self-check the harness is honest)
        self.assertTrue(self._sol(POS_STATE_REREAD))


if __name__ == "__main__":
    unittest.main()
