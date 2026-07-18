// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// =====================================================================
// CANDIDATE HARNESS — NOT PROOF
// ---------------------------------------------------------------------
// This file is a v2 protocol-family invariant template introduced by
// PR 203 (Invariant Library v2). It is a *candidate harness* only.
// The runner must execute this against a concrete pool+oracle pairing
// before anyone cites it as evidence. It does not prove the oracle
// is safe — it only flags one specific failure mode.
//
// Family: Lending protocol.
// Property: per-block oracle-price delta is bounded. A legitimate
//           price feed moves smoothly; a compromised or mispriced
//           feed tends to jump by >>MAX_BPS_DELTA between two
//           consecutive blocks for the same asset. The handler
//           drives the pool one call at a time and snapshots the
//           pool's reported price-per-asset at each step.
// =====================================================================

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";

// TODO: replace `{ContractName}` with the lending-pool contract that
// exposes the oracle-routed price accessor.
import "../src/{ContractName}.sol";

contract OraclePriceDelta is StdInvariant, Test {
    {ContractName} internal pool;

    // 5000 bps = 50% per-block move. Tune per protocol; a stablecoin-
    // only pool should use a much tighter bound (e.g. 200 bps).
    uint256 internal constant MAX_BPS_DELTA = 5_000;
    uint256 internal constant BPS = 10_000;

    // TODO: populate `assets` with every collateral / debt market the
    // pool reads a price for.
    address[] internal assets;

    // Per-asset last-seen price and the block it was read in.
    mapping(address => uint256) internal lastPrice;
    mapping(address => uint256) internal lastBlock;

    function setUp() public virtual {
        // TODO: deploy `pool`, populate `assets`, call targetContract()
        //       + a handler that exercises pool entry points. Prime
        //       lastPrice/lastBlock from the initial oracle read.
        for (uint256 i = 0; i < assets.length; i++) {
            lastPrice[assets[i]] = _priceOf(assets[i]);
            lastBlock[assets[i]] = block.number;
        }
    }

    function _priceOf(address asset) internal view returns (uint256) {
        // TODO: call pool.getUnderlyingPrice(cToken) or pool-specific
        //       equivalent (Aave: oracle.getAssetPrice; Morpho: irm).
        // return IPool(address(pool)).getUnderlyingPrice(asset);
        asset; // silence unused
        return 0;
    }

    /// Every price the pool reads must either be unchanged vs the
    /// last block we sampled, or change by <= MAX_BPS_DELTA.
    function invariant_oracle_delta_bounded_per_block() public {
        for (uint256 i = 0; i < assets.length; i++) {
            address a = assets[i];
            uint256 pNow = _priceOf(a);
            uint256 pPrev = lastPrice[a];
            if (pPrev == 0) {
                lastPrice[a] = pNow;
                lastBlock[a] = block.number;
                continue;
            }
            uint256 delta = pNow > pPrev ? pNow - pPrev : pPrev - pNow;
            uint256 bps = (delta * BPS) / pPrev;
            assertLe(
                bps,
                MAX_BPS_DELTA,
                "Lending: oracle moved more than MAX_BPS_DELTA across step"
            );
            lastPrice[a] = pNow;
            lastBlock[a] = block.number;
        }
    }
}
