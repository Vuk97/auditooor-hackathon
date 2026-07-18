#!/usr/bin/env python3
"""Regression tests for tools/epoch-restake-replay.py.

Proves the epoch/nonce/key uniqueness set-difference query
CREDIT_OR_ACCEPT \\ CONSUMED_MARKER_DOMINATED is:
  - a SET relation whose predicate DISCRIMINATES: an entrypoint that credits
    value keyed on an epoch/nonce/key but whose closure writes NO consumed
    marker is a SURVIVOR; the SAME entrypoint once a consumed-marker write is
    added to its closure is KEPT (the NON-VACUITY MUTATION - the marker guard is
    load-bearing, not the trivial "all crediting fns" answer);
  - TRANSITIVE: a consumed-marker write reached N hops deep in a helper KEEPS
    the entrypoint (impossible for a body-scoped regex);
  - NOT a shape: a crediting fn with no epoch/nonce/key is not a member; a keyed
    read with no credit/accept is not a member;
  - covers the ACCEPT (double-sign / double-vote) arm as well as the CREDIT arm;
  - HONEST on class-absence: a repo with no consumed-marker primitive and no
    keyed survivor reports class_present False + honest cited-empty (distinct
    from a vacuous 0-fn substrate).
"""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "epoch-restake-replay.py"
_spec = importlib.util.spec_from_file_location("epoch_restake_replay", _TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


# A synthetic staking module. ClaimReward credits value (Mint) keyed on epoch
# but NEVER writes a consumed marker -> epoch-replay survivor. ClaimSafe marks
# the epoch consumed first (setClaimed) -> DOMINATED (kept).
#
# The crediting ENTRYPOINTS (ClaimReward / ClaimSafe) live on a `msgServer`
# receiver - a TRUE external tx-message handler (the go_entrypoint_surface
# classifier's family 1), so the entrypoint gate KEEPS them as candidate readers.
# The value-moving helpers (setClaimed / Mint / rewardFor) stay on the internal
# `Keeper` receiver: they are reached only THROUGH the msgServer entrypoint and
# are covered transitively (Go analog of Solidity `internal`), so the gate does
# NOT treat them as independent replay obligations.
_STAKE_REPLAY = """
package keeper

func (k Keeper) setClaimed(ctx Ctx, acct Addr, epoch uint64) error {
    return nil
}

func (k Keeper) Mint(ctx Ctx, acct Addr, amt Int) error {
    return nil
}

func (k Keeper) rewardFor(ctx Ctx, acct Addr, epoch uint64) Int {
    return Int{}
}

func (k msgServer) ClaimReward(ctx Ctx, acct Addr, epoch uint64) error {
    amt := k.rewardFor(ctx, acct, epoch)
    return k.Mint(ctx, acct, amt)
}

func (k msgServer) ClaimSafe(ctx Ctx, acct Addr, epoch uint64) error {
    k.setClaimed(ctx, acct, epoch)
    amt := k.rewardFor(ctx, acct, epoch)
    return k.Mint(ctx, acct, amt)
}

func (k msgServer) SetParams(ctx Ctx, p Params) error {
    return nil
}
"""

# The SAME repo but ClaimReward now transitively consumes the epoch through a
# helper `settleAndStamp` (marker N hops deep) - proving the KEEP is TRANSITIVE.
_STAKE_TRANSITIVE_FIX = """
package keeper

func (k Keeper) setClaimed(ctx Ctx, acct Addr, epoch uint64) error { return nil }

func (k Keeper) settleAndStamp(ctx Ctx, acct Addr, epoch uint64) error {
    return k.setClaimed(ctx, acct, epoch)
}

func (k Keeper) Mint(ctx Ctx, acct Addr, amt Int) error { return nil }

func (k Keeper) rewardFor(ctx Ctx, acct Addr, epoch uint64) Int { return Int{} }

func (k msgServer) ClaimReward(ctx Ctx, acct Addr, epoch uint64) error {
    k.settleAndStamp(ctx, acct, epoch)
    amt := k.rewardFor(ctx, acct, epoch)
    return k.Mint(ctx, acct, amt)
}
"""

# ACCEPT arm: AcceptVote accepts a vote keyed by (keyId, epoch) but writes no
# hasVoted marker -> double-count survivor. AcceptVoteSafe stamps hasVoted.
# Both are msgServer handlers (true entrypoints); castVote is an internal Keeper
# helper reached transitively.
_VOTE_REPLAY = """
package keeper

func (k msgServer) AcceptVote(ctx Ctx, keyId uint64, epoch uint64, sig []byte) error {
    return k.castVote(ctx, keyId, epoch)
}

func (k Keeper) castVote(ctx Ctx, keyId uint64, epoch uint64) error {
    return nil
}

func (k msgServer) AcceptVoteSafe(ctx Ctx, keyId uint64, epoch uint64) error {
    k.hasVoted[keyId] = true
    return k.castVote(ctx, keyId, epoch)
}
"""

# ENTRYPOINT-GATE negative: a CLI command builder (Cobra) that credits value
# (mintReward) keyed on an epoch identifier but is NOT an external attack surface
# - a free `GetCmd*` function returning *cobra.Command is client-side scaffolding
# reached by an operator running a CLI, never by an on-chain attacker. Before the
# gate this over-emitted as a survivor (credit + epoch key, no marker); the
# go_entrypoint_surface classifier marks it an internal/non-entry fn so it is
# DROPPED from the candidate reader set. Mirrors the real axelar over-emit
# (AddGenesisAccountCmd / GetCmdAddChain grpc getters + CLI builders).
_CLI_BUILDER = """
package cli

func GetCmdClaimReward() *cobra.Command {
    return buildCmd(func() error {
        epoch := currentEpoch()
        return mintReward(epoch)
    })
}

func mintReward(epoch uint64) error { return nil }

func currentEpoch() uint64 { return 0 }
"""

# A Solidity assignment-form marker: claim() credits keyed on epoch but no
# claimed[..]=true; claimSafe() stamps claimed[msg.sender] = true.
_SOL_ASSIGN = """
contract Staking {
    mapping(address => bool) public claimed;

    function claim(uint256 epoch) external {
        uint256 amt = rewardOf(msg.sender, epoch);
        _mint(msg.sender, amt);
    }

    function claimSafe(uint256 epoch) external {
        claimed[msg.sender] = true;
        uint256 amt = rewardOf(msg.sender, epoch);
        _mint(msg.sender, amt);
    }

    function rewardOf(address a, uint256 epoch) internal view returns (uint256) {
        return epoch;
    }

    function _mint(address a, uint256 amt) internal {}
}
"""

# A repo with NO consumed-marker primitive AND no keyed credit at all - the
# class does not apply -> honest cited-empty.
_NO_CLASS = """
package keeper

func (k Keeper) LinkAddress(ctx Ctx, a Addr) error {
    return k.SendCoins(ctx, a, mod, coins)
}

func (k Keeper) totalSupply(ctx Ctx) Int { return Int{} }
"""


def _write(tmp: Path, name: str, body: str) -> Path:
    p = tmp / "src"
    p.mkdir(parents=True, exist_ok=True)
    (p / name).write_text(body)
    return tmp


def _run(tmp: Path) -> dict:
    emit = tmp / "out.jsonl"
    return mod.run(["--workspace", str(tmp), "--emit", str(emit), "--json"])


class NodePredicateTest(unittest.TestCase):
    def test_marker_predicate(self):
        for n in ("setClaimed", "markConsumed", "useNonce", "recordVote",
                  "updateRewardCheckpoint", "setLastClaimedEpoch", "spendNonce"):
            self.assertTrue(mod._MARKER.match(n), n)

    def test_marker_negatives(self):
        for n in ("ClaimReward", "SetParams", "Mint", "rewardFor", "LinkAddress"):
            self.assertFalse(mod._MARKER.match(n), n)

    def test_credit_accept_key_predicates(self):
        self.assertTrue(mod._CREDIT.match("Mint"))
        self.assertTrue(mod._CREDIT.match("distributeReward"))
        self.assertTrue(mod._ACCEPT.match("acceptVote"))
        self.assertTrue(mod._ACCEPT.match("verifySignature"))
        self.assertTrue(mod._EPOCH_KEY.search("epoch uint64"))
        self.assertTrue(mod._EPOCH_KEY.search("nonce uint64"))
        self.assertFalse(mod._CREDIT.match("SetParams"))

    def test_marker_assign_form(self):
        self.assertTrue(mod._MARKER_ASSIGN.search("hasVoted[keyId] = true"))
        self.assertTrue(mod._MARKER_ASSIGN.search("claimed[msg.sender] = true"))
        self.assertTrue(mod._MARKER_ASSIGN.search("lastClaimedEpoch = epoch"))
        # a plain read / equality compare is NOT a marker write
        self.assertIsNone(mod._MARKER_ASSIGN.search("if claimed[a] == true {"))


class SetDifferenceDiscriminatesTest(unittest.TestCase):
    def test_survivor_and_kept_split(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            _write(tmp, "stake.go", _STAKE_REPLAY)
            s = _run(tmp)
            self.assertTrue(s["class_present"])
            survivors = {x["fn"] for x in s["survivors"]}
            # ClaimReward credits keyed on epoch, NO consumed marker -> survivor
            self.assertIn("ClaimReward", survivors)
            # ClaimSafe stamps setClaimed first -> KEPT (dominated)
            self.assertNotIn("ClaimSafe", survivors)
            self.assertIn("ClaimSafe", s["kept_with_marker"])
            # SetParams neither credits nor is keyed -> not a member
            self.assertNotIn("SetParams", survivors)
            self.assertGreaterEqual(s["size_CONSUMED_MARKER_DOMINATED"], 1)

    def test_nonvacuity_mutation_kills_the_survivor(self):
        # THE non-vacuity mutation: add a (transitive) consumed-marker write to
        # ClaimReward's closure. The SAME fn must flip survivor -> kept, proving
        # the marker-closure guard is load-bearing.
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            _write(tmp, "stake.go", _STAKE_TRANSITIVE_FIX)
            s = _run(tmp)
            survivors = {x["fn"] for x in s["survivors"]}
            self.assertNotIn("ClaimReward", survivors,
                             "consumed-marker N hops deep must KEEP ClaimReward")
            self.assertIn("ClaimReward", s["kept_with_marker"])
            self.assertEqual(s["size_DIFF_survivors"], 0)

    def test_accept_arm_double_vote_survivor(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            _write(tmp, "vote.go", _VOTE_REPLAY)
            s = _run(tmp)
            survivors = {x["fn"]: x for x in s["survivors"]}
            self.assertIn("AcceptVote", survivors)
            self.assertEqual(survivors["AcceptVote"]["action_kind"], "accept")
            # AcceptVoteSafe stamps hasVoted[..]=true -> dominated
            self.assertNotIn("AcceptVoteSafe", survivors)
            self.assertIn("AcceptVoteSafe", s["kept_with_marker"])

    def test_solidity_assignment_marker(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            _write(tmp, "Staking.sol", _SOL_ASSIGN)
            s = _run(tmp)
            survivors = {x["fn"] for x in s["survivors"]}
            self.assertIn("claim", survivors)
            # claimSafe writes claimed[..]=true assignment marker -> dominated
            self.assertNotIn("claimSafe", survivors)
            self.assertIn("claimSafe", s["kept_with_marker"])

    def test_cli_command_builder_is_not_a_survivor(self):
        # ENTRYPOINT GATE: a `GetCmd*` CLI command builder that credits value
        # (mintReward) keyed on an epoch is NOT an external attack surface. The
        # go_entrypoint_surface classifier drops it, so it must NOT survive even
        # though it satisfies the credit + epoch-key predicates.
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            _write(tmp, "cli.go", _CLI_BUILDER)
            s = _run(tmp)
            survivors = {x["fn"] for x in s["survivors"]}
            self.assertNotIn("GetCmdClaimReward", survivors,
                             "a CLI command builder is not an external entrypoint "
                             "and must be gated out of the candidate readers")
            self.assertEqual(s["size_DIFF_survivors"], 0)
            # the fn WAS indexed (substrate materialized) - it is gated, not absent.
            self.assertGreater(s["n_functions_indexed"], 0)
            self.assertGreaterEqual(s["n_go_nonentry_gated"], 1)

    def test_cli_builder_survives_without_entrypoint_gate(self):
        # NON-VACUITY of the gate: the SAME CLI builder, if the entrypoint gate
        # were not load-bearing, satisfies credit + epoch-key with no marker. Prove
        # the classifier is what removes it by confirming is_go_entry_point returns
        # False for it (so the drop is the gate's doing, not a missing predicate).
        self.assertFalse(
            mod.is_go_entry_point("GetCmdClaimReward", "", "x/foo/client/cli/tx.go",
                                  "func GetCmdClaimReward() *cobra.Command {"),
            "GetCmd* CLI builder must classify as a non-entrypoint")
        # a genuine msgServer handler DOES classify as an entrypoint (kept).
        self.assertTrue(
            mod.is_go_entry_point("ClaimReward", "msgServer",
                                  "x/foo/keeper/msg_server.go",
                                  "func (k msgServer) ClaimReward(...) error {"))

    def test_obligation_written_for_survivor(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            _write(tmp, "stake.go", _STAKE_REPLAY)
            s = _run(tmp)
            rows = [json.loads(l) for l in
                    Path(s["obligations_path"]).read_text().splitlines() if l.strip()]
            r = next(r for r in rows if r["function"] == "ClaimReward")
            self.assertEqual(r["schema"], "auditooor.epoch_restake_replay.v1")
            self.assertEqual(r["attack_class"],
                             "epoch-nonce-key-uniqueness-replay-double-collect")
            self.assertTrue(r["source_refs"])
            self.assertTrue(r["uniqueness_key"])
            self.assertTrue(r["missing_marker"])


class HonestEmptyTest(unittest.TestCase):
    def test_no_class_is_honest_empty_not_survivors(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            _write(tmp, "nexus.go", _NO_CLASS)
            s = _run(tmp)
            self.assertFalse(s["class_present"])
            self.assertEqual(s["size_DIFF_survivors"], 0)
            self.assertTrue(s["honest_empty_class_not_present"])
            self.assertGreater(s["n_functions_indexed"], 0)
            self.assertFalse(s["substrate_vacuous"])


if __name__ == "__main__":
    unittest.main()
