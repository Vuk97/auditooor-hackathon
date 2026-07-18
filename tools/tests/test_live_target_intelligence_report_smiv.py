#!/usr/bin/env python3
"""Focused PHASE-II.1 SMIV tests for live-target P1 semantic predicates."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


_HERE = Path(__file__).resolve().parent
_TOOL_PATH = _HERE.parent / "live-target-intelligence-report.py"
_spec = importlib.util.spec_from_file_location(
    "live_target_intelligence_report_smiv", _TOOL_PATH
)
ltir_mod = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(ltir_mod)


def _semantic(inv_id: str, source: str) -> list[str]:
    return ltir_mod._semantic_p1_matches(
        "smiv-direct",
        matched_p1=[inv_id],
        file_line="src/Smiv.sol:1",
        snippet="",
        source_context=source,
        source_contract_context=source,
    )


class SmivBackfilledPredicateTest(unittest.TestCase):
    def test_backfilled_positive_predicate_shapes_become_semantic(self) -> None:
        cases = {
            "INV-AUTH-006": (
                "contract Emergency is Ownable {\n"
                "  function pause() external onlyOwner { _pause(); }\n"
                "}\n"
            ),
            "INV-AUTH-007": (
                "module m::cap { public fun acquire(owner: &signer) acquires Capability {\n"
                "  let cap = borrow_global_mut<Capability>(@core); cap;\n"
                "} }\n"
            ),
            "INV-AUTH-008": (
                "func Dispatch(ctx sdk.Context, msg sdk.Msg) error {\n"
                "  return keeper.HandleMsg(ctx, msg)\n"
                "}\n"
            ),
            "INV-AUTH-009": (
                "contract TimelockLike {\n"
                "  struct Proposal { bool cancelled; }\n"
                "  mapping(uint256 => Proposal) proposals;\n"
                "  function cancel(uint256 id) external { proposals[id].cancelled = true; }\n"
                "}\n"
            ),
            "INV-UNI-010": (
                "contract BadOrderBook {\n"
                "  function fillOrder(Order calldata order, bytes calldata sig) external {\n"
                "    bytes32 orderHash = hashOrder(order);\n"
                "    address maker = ECDSA.recover(orderHash, sig);\n"
                "    settle(order, maker);\n"
                "  }\n"
                "}\n"
            ),
            "INV-ORD-003": (
                "func Dispatch(ctx sdk.Context, msg sdk.Msg) error {\n"
                "  return msgServer.HandleTransfer(ctx, msg)\n"
                "}\n"
            ),
            "INV-ORD-004": (
                "contract BadSwap {\n"
                "  function swap(uint256 amountIn, uint256 minAmountOut) external {\n"
                "    router.swap(amountIn);\n"
                "  }\n"
                "}\n"
            ),
            "INV-ORD-006": (
                "contract BadBridge {\n"
                "  function bridge(uint256 amount) external {\n"
                "    dispatch(amount);\n"
                "    _burn(msg.sender, amount);\n"
                "  }\n"
                "}\n"
            ),
            "INV-ORD-007": (
                "var current *Client\n"
                "func SetClient(c *Client) { current = c }\n"
                "func GetClient() *Client { return current }\n"
            ),
            "INV-ORD-009": (
                "contract StandalonePermit {\n"
                "  function permit(address owner, bytes calldata sig) external { owner; sig; }\n"
                "}\n"
            ),
            "INV-MON-001": (
                "fn validate(update: Update, store: &mut Store) {\n"
                "    store.finalized_period = update.finalized_period;\n"
                "}\n"
            ),
            "INV-MON-003": (
                "contract BadSupply { function setTotalSupply(uint256 supply) external { totalSupply = supply; } }\n"
            ),
            "INV-MON-004": (
                "fn process(update: Update, state: &mut State) { state.latest_epoch = update.epoch; }\n"
            ),
            "INV-MON-006": (
                "contract Clock { function setLastUpdate(uint256 t) external { lastUpdate = t; } }\n"
            ),
            "INV-MON-008": (
                "func DeliverTx(req abci.RequestDeliverTx) { now := time.Now(); _ = now }\n"
            ),
            "INV-MON-010": (
                "fn set_root(update: Root, oracle: &mut Oracle) { oracle.last_finalized_height = update.height; }\n"
            ),
            "INV-CUST-001": (
                "contract Token {\n"
                "  function transferFrom(address from, address to, uint256 amount) external returns (bool) {\n"
                "    balances[from] -= amount; balances[to] += amount; return true;\n"
                "  }\n"
                "}\n"
            ),
            "INV-CUST-002": (
                "contract Vault {\n"
                "  function withdraw(uint256 assets, address receiver, address owner) external {\n"
                "    _burn(owner, assets); asset.transfer(receiver, assets);\n"
                "  }\n"
                "}\n"
            ),
            "INV-CUST-003": (
                "contract Key721 {\n"
                "  function _transfer(address from, address to, uint256 tokenId) internal {\n"
                "    _owners[tokenId] = to;\n"
                "  }\n"
                "}\n"
            ),
            "INV-CUST-004": (
                "contract Adapter { function pay(IERC20 asset, address receiver, uint256 amount) external {\n"
                "  IERC20(asset).transfer(receiver, amount);\n"
                "} }\n"
            ),
            "INV-CUST-005": (
                "contract Safeish { function safeApprove(IERC20 token, address spender, uint256 value) internal {\n"
                "  token.approve(spender, value);\n"
                "} }\n"
            ),
            "INV-CUST-006": (
                "contract Multi {\n"
                "  uint256 threshold; mapping(uint256 => uint256) confirmations;\n"
                "  function executeTransaction(uint256 txId) external { transactions[txId].to.call(\"\"); }\n"
                "}\n"
            ),
            "INV-CUST-008": (
                "module m::cap { public fun forge() acquires Capability {\n"
                "  borrow_global_mut<Capability>(@core);\n"
                "} }\n"
            ),
            "INV-CUST-009": (
                "contract Lending { function repay(uint256 id, address token, uint256 amount) external {\n"
                "  require(isWhitelisted[token]); id; amount;\n"
                "} }\n"
            ),
            "INV-CUST-010": (
                "contract NativeEscrow {\n"
                "  function payout(address payable to, uint256 owed) external {\n"
                "    uint256 bal = address(this).balance;\n"
                "    require(bal >= owed, \"insufficient\");\n"
                "    (bool ok,) = to.call{value: owed}(\"\");\n"
                "    require(ok);\n"
                "  }\n"
                "}\n"
            ),
            "INV-BND-003": (
                "module m::coin { public fun mint(issuer: address, amount: u64) { coin::mint(amount); } }\n"
            ),
            "INV-BND-005": (
                "module m::perp { fun set_funding_rate(funding_rate: u64) { global.funding_rate = funding_rate; } }\n"
            ),
            "INV-BND-010": (
                "func Decode(size uint32) []byte { return make([]byte, size) }\n"
            ),
            "INV-CON-009": (
                "contract Rewards { function claim(uint256 epoch) external {\n"
                "  rewardToken.transfer(msg.sender, rewards[msg.sender]);\n"
                "  claimedRewards[msg.sender][epoch] = true;\n"
                "} }\n"
            ),
            "INV-FRESH-008": (
                "fn validate(update: Update) { let signature_slot = update.signature_slot; let period = current_period; store(update); }\n"
            ),
            "INV-FRESH-010": (
                "contract Permit { function permit(address owner, bytes calldata sig) external {\n"
                "  ECDSA.recover(hash, sig); owner;\n"
                "} }\n"
            ),
            "INV-DET-001": (
                "func ProcessProposal(req abci.RequestProcessProposal) { r := rand.Int(); _ = r }\n"
            ),
            "INV-DET-005": (
                "func DecodeTx(bz []byte) error { var msg Msg; return proto.Unmarshal(bz, &msg) }\n"
            ),
            "INV-DET-008": (
                "func NewBridgeEvent() BridgeEvent { return BridgeEvent{ID: time.Now().UnixNano()} }\n"
            ),
        }
        for inv_id, source in cases.items():
            self.assertEqual(_semantic(inv_id, source), [inv_id], inv_id)

    def test_safe_shapes_stay_topical_only(self) -> None:
        cases = {
            "INV-AUTH-006": (
                "contract Emergency { function pause() external onlyTimelock { _pause(); } }\n"
            ),
            "INV-AUTH-008": (
                "func Dispatch(client Client, tx []byte) error { return client.BroadcastTxSync(tx) }\n"
            ),
            "INV-ORD-004": (
                "contract Swap { function swap(uint256 amountIn, uint256 minAmountOut) external {\n"
                "  router.exactInput(ExactInputParams({amountIn: amountIn, amountOutMinimum: minAmountOut}));\n"
                "} }\n"
            ),
            "INV-ORD-006": (
                "contract Bridge { function bridge(uint256 amount) external { _burn(msg.sender, amount); dispatch(amount); } }\n"
            ),
            "INV-CUST-001": (
                "contract Token { function transferFrom(address from, address to, uint256 amount) external returns (bool) {\n"
                "  _spendAllowance(from, msg.sender, amount); _transfer(from, to, amount); return true;\n"
                "} }\n"
            ),
            "INV-CUST-004": (
                "contract Adapter { using SafeERC20 for IERC20; function pay(IERC20 asset, address receiver, uint256 amount) external {\n"
                "  asset.safeTransfer(receiver, amount);\n"
                "} }\n"
            ),
            "INV-FRESH-010": (
                "contract Permit { function permit(address owner, uint256 deadline, bytes calldata sig) external {\n"
                "  require(deadline >= block.timestamp); ECDSA.recover(hash, sig); owner;\n"
                "} }\n"
            ),
            "INV-MON-006": (
                "contract Clock { function setLastUpdate(uint256 t) external { require(t >= lastUpdate); lastUpdate = t; } }\n"
            ),
        }
        for inv_id, source in cases.items():
            self.assertEqual(_semantic(inv_id, source), [], inv_id)

    def test_unstable_catalog_ids_remain_topical_without_source_proof(self) -> None:
        matched = ["INV-UNI-003", "INV-UNI-004", "INV-FRESH-005", "INV-DET-003"]
        semantic = ltir_mod._semantic_p1_matches(
            "smiv-topical-only",
            matched_p1=matched,
            file_line="src/Topical.sol:1",
            snippet="oracle freshness, custody, uniqueness, canonical encoding",
            source_context="contract Topical { function f() external {} }",
            source_contract_context="contract Topical { function f() external {} }",
        )
        self.assertEqual(semantic, [])
        self.assertEqual(
            ltir_mod._p1_match_tier(matched_p1=matched, semantic_p1=semantic),
            "TOPICAL-MATCH",
        )


if __name__ == "__main__":
    unittest.main()
