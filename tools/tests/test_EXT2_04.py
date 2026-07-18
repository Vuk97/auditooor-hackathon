#!/usr/bin/env python3
"""test_EXT2_04.py - queue-fairness resource-mutation screen (EXT2_04).

Covers tools/queue-fairness-resource-mutation-screen.py, an advisory-first,
NO-AUTO-CREDIT (verdict='needs-fuzz') GENERAL enforcement screen for the ORDERING
invariant that a FIFO/priority queue protects: "if the pending queue is non-empty, a
newly-arriving request must NOT be serviced in full ahead of older queued entries."
The bypass appears when the shared resource pool mutates (deposit/repay/harvest/reserve
top-up/epoch reset) BETWEEN an old request's enqueue and its service, and the service
guard gates on INSTANTANEOUS availability ("enough right now?") instead of on
QUEUE-NONEMPTINESS ("is anyone ahead of me?"). Anchor: Certora FV of infiniFi redemptions.

Non-vacuity / mutation-kill:
  - PLANTED positives (an availability-gated direct-pay service point that neither
    enqueues, drains the queue in order, nor checks queue-nonemptiness) FIRE;
  - COVERED/benign negatives (queue-nonemptiness-gated service; the enqueue request-
    creation path; the in-order FIFO drainer; a module with no request queue; a market-
    priority list that is not a request FIFO) stay SILENT (fires=False / no row);
  - NEUTRALISING the CORE predicate (_reads_instantaneous_availability -> constant False)
    stops the planted positive from firing - proving the availability-gate predicate is
    load-bearing, not decorative.

Real-fleet mutation-verify (executed in the build, temp copy only, ws byte-identical):
  - nuva keeper SwapOut ENQUEUES the pending swap-out request behind older entries -> the
    screen enumerates it SAFE (enqueue=True, fires=False). Replacing the Enqueue with a
    direct SpendableCoins-gated BankKeeper.SendCoins pay (the infiniFi bypass) makes it
    FIRE (enqueue=False, drain=False, queue-gate=False).
"""
import importlib.util
import sys
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "queue-fairness-resource-mutation-screen.py"


def _load():
    spec = importlib.util.spec_from_file_location("ext2_04_screen", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ext2_04_screen"] = mod
    spec.loader.exec_module(mod)
    return mod


# --- synthetic Solidity fixtures ------------------------------------------------ #

# POSITIVE 1: a redemption-queue vault whose redeem() pays a NEW request directly from the
# live balance gated on availability, never checking whether the queue is non-empty.
POS_REDEEM_BYPASS = """
contract RedeemVault {
    struct Req { address who; uint256 amount; }
    mapping(uint256 => Req) public redemptionQueue;
    uint256 public nextRequestId;
    uint256 public lastProcessedId;
    IERC20 public asset;

    function requestRedeem(uint256 amount) external {
        redemptionQueue[nextRequestId] = Req(msg.sender, amount);
        nextRequestId++;
    }
    function redeem(uint256 amount) external {
        uint256 available = asset.balanceOf(address(this));
        require(available >= amount, "insufficient");
        asset.safeTransfer(msg.sender, amount);     // BYPASS: jumps the queue
    }
}
"""

# POSITIVE 2: availability-gated payout in a module with an explicit payout queue + request
# cursor; the fast path pays msg.sender from totalAssets() without gating on the queue.
POS_PAYOUT_BYPASS = """
contract Payouts {
    mapping(uint256 => address) public payoutQueue;
    uint256 public nextRequestId;
    IERC20 public token;
    function claimFast(uint256 amount) public {
        if (token.totalAssets() >= amount) {
            token.transfer(msg.sender, amount);     // BYPASS: no queue-nonemptiness gate
        }
    }
}
"""

# NEGATIVE 1 (COVERED): same shape but the service GATES on queue-nonemptiness first.
NEG_QUEUE_GATED = """
contract RedeemVault {
    mapping(uint256 => uint256) public redemptionQueue;
    uint256 public nextRequestId;
    uint256 public lastProcessedId;
    IERC20 public asset;
    function redeem(uint256 amount) external {
        require(nextRequestId == lastProcessedId, "queue not empty");  // SAFE gate
        uint256 available = asset.balanceOf(address(this));
        require(available >= amount, "insufficient");
        asset.safeTransfer(msg.sender, amount);
    }
}
"""

# NEGATIVE 2 (COVERED): the ENQUEUE request-creation path - reads availability + escrows,
# then enqueues. Deferring the payout is the SAFE discipline; must not fire.
NEG_ENQUEUE_PATH = """
contract RedeemVault {
    mapping(uint256 => uint256) public redemptionQueue;
    uint256 public nextRequestId;
    IERC20 public asset;
    function requestRedeem(uint256 amount) external {
        uint256 available = asset.balanceOf(address(this));
        asset.transferFrom(msg.sender, address(this), amount);        // escrow
        redemptionQueue[nextRequestId] = amount;                       // enqueue
        nextRequestId++;
    }
}
"""

# NEGATIVE 3 (COVERED): the in-order FIFO DRAINER - iterates the queue and pays the head.
# This is the legit processor, not a bypass; must stay silent.
NEG_FIFO_DRAINER = """
contract RedeemVault {
    struct Req { address who; uint256 amount; }
    Req[] public redemptionQueue;
    uint256 public head;
    IERC20 public asset;
    function processQueue() external {
        for (uint256 i = head; i < redemptionQueue.length; i++) {
            Req memory r = redemptionQueue[i];
            uint256 available = asset.balanceOf(address(this));
            if (available < r.amount) break;
            asset.safeTransfer(r.who, r.amount);
            head++;
        }
    }
}
"""

# NEGATIVE 4 (out of class): no request queue at all - a plain vault withdraw. There is no
# ordering invariant to violate; must emit no enforcement point.
NEG_NO_QUEUE = """
contract Vault {
    IERC20 public asset;
    function withdraw(uint256 amount) external {
        uint256 available = asset.balanceOf(address(this));
        require(available >= amount);
        asset.safeTransfer(msg.sender, amount);
    }
}
"""

# NEGATIVE 5 (FP regression - market-priority list, NOT a request FIFO): a MetaMorpho-style
# `withdrawQueue`/`supplyQueue` is an array of market Ids, not queued user requests sharing a
# pool. `skim` reads balanceOf(this) and transfers stray tokens, but the module has no
# request-FIFO semantics (no enqueue/dequeue/request-cursor) -> no enforcement point.
NEG_MARKET_PRIORITY_LIST = """
contract MetaMorpho {
    Id[] public supplyQueue;
    Id[] public withdrawQueue;
    address public skimRecipient;
    IERC20 public asset;
    function setWithdrawQueue(uint256[] calldata indexes) external {}
    function skim(address token) external {
        uint256 amount = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransfer(skimRecipient, amount);   // stray-token recovery, not a service
    }
}
"""

# --- Go fixtures ---------------------------------------------------------------- #

# Go POSITIVE: an exported swap-out handler in a module with a pending queue pays the owner
# directly from SpendableCoins instead of enqueueing behind older pending swap-outs.
GO_POS = """
package keeper
type PendingSwapOut struct{}
func (k Keeper) SwapOut(ctx Context, vault, owner Addr, assets Coin) (uint64, error) {
    avail := k.BankKeeper.SpendableCoins(ctx, vault)
    if avail.AmountOf(assets.Denom) >= assets.Amount {
        if err := k.BankKeeper.SendCoins(ctx, vault, owner, NewCoins(assets)); err != nil {
            return 0, err
        }
    }
    return 0, nil
}
"""

# Go NEGATIVE (COVERED): the same handler ENQUEUES the request (safe deferral).
GO_NEG_ENQUEUE = """
package keeper
type PendingSwapOut struct{}
func (k Keeper) SwapOut(ctx Context, vault, owner Addr, assets Coin) (uint64, error) {
    avail := k.BankKeeper.SpendableCoins(ctx, vault)
    _ = avail
    if err := k.BankKeeper.SendCoins(ctx, owner, vault, NewCoins(assets)); err != nil {
        return 0, err
    }
    return k.PendingSwapOutQueue.Enqueue(ctx, payoutTime, &req)   // safe: defer behind queue
}
"""

# Go NEGATIVE (COVERED): the in-order drainer walks the due queue -> not a bypass.
GO_NEG_DRAINER = """
package keeper
type PendingSwapOut struct{}
func (k Keeper) ProcessPayouts(ctx Context) error {
    return k.PendingSwapOutQueue.WalkDue(ctx, now, func(ts int64, id uint64, v Addr, req PendingSwapOut) (bool, error) {
        avail := k.BankKeeper.SpendableCoins(ctx, v)
        _ = avail
        return false, k.BankKeeper.SendCoins(ctx, v, req.Owner, req.Assets)
    })
}
"""


class TestEXT2_04(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _sol(self, text):
        return self.m.scan_file_sol(Path("X.sol"), "X.sol", queue_present=None, file_text=text)

    def _go(self, text):
        return self.m.scan_file_go(Path("X.go"), "X.go", queue_present=None, file_text=text)

    @staticmethod
    def _fired(rows):
        return [r for r in rows if r["fires"]]

    def _sol_qp(self, text):
        # file-local queue presence, mirroring scan_path/--file behaviour
        qp = self.m._has_queue_structure(self.m._mask_comments(text))
        return self.m.scan_file_sol(Path("X.sol"), "X.sol", queue_present=qp, file_text=text)

    def _go_qp(self, text):
        qp = self.m._has_queue_structure(self.m._mask_comments(text))
        return self.m.scan_file_go(Path("X.go"), "X.go", queue_present=qp, file_text=text)

    # ---- planted positives fire ------------------------------------------- #
    def test_pos_redeem_bypass_fires(self):
        fired = self._fired(self._sol_qp(POS_REDEEM_BYPASS))
        self.assertTrue(fired, "availability-gated redeem with no queue gate must FIRE")
        r = next(x for x in fired if x["function"] == "redeem")
        self.assertEqual(r["verdict"], "needs-fuzz")
        self.assertFalse(r["auto_credit"])
        self.assertTrue(r["advisory"])
        self.assertEqual(r["key"], "EXT2_04")
        self.assertIn("EXT2_04", r["capability"])
        self.assertTrue(r["reads_instantaneous_availability"])
        self.assertFalse(r["gates_on_queue_nonemptiness"])
        self.assertFalse(r["enqueues"])

    def test_pos_payout_bypass_fires(self):
        fired = self._fired(self._sol_qp(POS_PAYOUT_BYPASS))
        self.assertTrue(any(r["function"] == "claimFast" for r in fired),
                        "totalAssets-gated payout with no queue gate must FIRE")

    # ---- covered/benign negatives stay silent ----------------------------- #
    def test_neg_queue_gated_silent(self):
        self.assertEqual(self._fired(self._sol_qp(NEG_QUEUE_GATED)), [],
                         "a queue-nonemptiness-gated service must NOT fire")

    def test_neg_enqueue_path_silent(self):
        self.assertEqual(self._fired(self._sol_qp(NEG_ENQUEUE_PATH)), [],
                         "the enqueue request-creation path is the safe discipline")

    def test_neg_fifo_drainer_silent(self):
        self.assertEqual(self._fired(self._sol_qp(NEG_FIFO_DRAINER)), [],
                         "the in-order FIFO drainer is the legit processor, not a bypass")

    def test_neg_no_queue_emits_nothing(self):
        # No request queue -> no ordering invariant -> no enforcement point at all.
        self.assertEqual(self._sol_qp(NEG_NO_QUEUE), [],
                         "a plain vault with no request queue must emit no point")

    def test_neg_market_priority_list_silent(self):
        # MetaMorpho withdrawQueue/supplyQueue are market lists, not request FIFOs.
        rows = self._sol_qp(NEG_MARKET_PRIORITY_LIST)
        self.assertEqual(rows, [],
                         "a market-priority list (no request-FIFO semantics) must not "
                         "enumerate skim as a queue-fairness point (FP regression)")

    # ---- Go arm ----------------------------------------------------------- #
    def test_go_pos_fires(self):
        fired = self._fired(self._go_qp(GO_POS))
        self.assertTrue(fired, "Go direct-pay swap-out with no enqueue must FIRE")
        self.assertEqual(fired[0]["lang"], "go")
        self.assertEqual(fired[0]["verdict"], "needs-fuzz")

    def test_go_neg_enqueue_silent(self):
        self.assertEqual(self._fired(self._go_qp(GO_NEG_ENQUEUE)), [],
                         "Go enqueue path (safe deferral) must not fire")

    def test_go_neg_drainer_silent(self):
        self.assertEqual(self._fired(self._go_qp(GO_NEG_DRAINER)), [],
                         "Go WalkDue drainer is the in-order processor, not a bypass")

    # ---- advisory-first contract ------------------------------------------ #
    def test_advisory_never_autocredits(self):
        rows = self._sol_qp(POS_REDEEM_BYPASS) + self._go_qp(GO_POS)
        self.assertTrue(rows)
        for r in rows:
            self.assertFalse(r["auto_credit"])
            self.assertTrue(r["advisory"])
            self.assertEqual(r["verdict"], "needs-fuzz")

    # ---- CORE-PREDICATE neutralisation: positive MUST then fail ----------- #
    def test_neutralised_predicate_kills_positive(self):
        """If _reads_instantaneous_availability no longer detects the live-pool gate
        (constant False), the planted positive stops firing - proving the availability-
        gate predicate is the load-bearing core, not decoration."""
        orig = self.m._reads_instantaneous_availability
        try:
            self.m._reads_instantaneous_availability = lambda body, lang: False
            fired = self._fired(self._sol_qp(POS_REDEEM_BYPASS))
            self.assertEqual(fired, [],
                             "neutralising the availability predicate should silence the "
                             "planted positive (predicate is load-bearing)")
        finally:
            self.m._reads_instantaneous_availability = orig
        # and it fires again once restored (self-check the harness is honest)
        self.assertTrue(self._fired(self._sol_qp(POS_REDEEM_BYPASS)))


if __name__ == "__main__":
    unittest.main()
