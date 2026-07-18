// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// =====================================================================
// CANDIDATE HARNESS — NOT PROOF
// ---------------------------------------------------------------------
// This file is a v2 protocol-family invariant template introduced by
// PR 203-b (Invariant Library v2 — bridge family). It is a *candidate
// harness* only — a skeleton the protocol-specific setUp must
// complete before any execution. It does not constitute evidence of
// any property until a runner records a concrete status in the
// workspace evidence matrix.
//
// Family: Bridge (lock-and-mint).
// Property: supply conservation across the source lock vault and the
//           destination mint token. At all times,
//
//             total_minted_on_dst - total_locked_on_src == 0
//
//           must hold across any sequence of lock/burn/mint/unlock
//           transactions. A non-zero delta means the bridge printed
//           synthetic tokens the source vault cannot redeem (a
//           solvency break) or burned synthetics without releasing
//           the locked principal (a user-loss break).
// =====================================================================

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";

// TODO: replace `{ContractName}` with the bridge contract (or the
// pair of source-lock + destination-mint contracts — one per side).
import "../src/{ContractName}.sol";

interface IERC20Like {
    function balanceOf(address) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

contract LockMintBalanceConservation is StdInvariant, Test {
    {ContractName} internal bridge;

    // Mock source-lock escrow — the vault holding the original token
    // on the source chain. In a single-VM test harness, both the
    // source and destination are deployed locally and the handler
    // simulates the relayer round-trip.
    address internal srcLockVault;
    IERC20Like internal srcToken;     // original token on src side

    // Mock destination-mint — the wrapped/minted representation on
    // the destination chain.
    IERC20Like internal dstMintToken;

    function setUp() public virtual {
        // TODO: deploy `bridge`, deploy mock src token + src lock vault
        //       + dst mint token, wire the bridge to both sides, seed
        //       a handler that calls bridgeFromChain / lock / unlock /
        //       mint / burn paths under vm.prank(user). Call
        //       targetContract(address(bridge)).
    }

    function _totalLockedOnSrc() internal view returns (uint256) {
        // TODO: return srcToken.balanceOf(srcLockVault). If the
        //       protocol tracks locked separately from ad-hoc donations,
        //       read the protocol's own accounting variable instead.
        if (address(srcToken) == address(0)) return 0;
        return srcToken.balanceOf(srcLockVault);
    }

    function _totalMintedOnDst() internal view returns (uint256) {
        // TODO: return dstMintToken.totalSupply(). If only a subset
        //       of supply is bridged (e.g. the token has a native
        //       pre-mint), subtract that constant so the delta is
        //       bridge-scoped.
        if (address(dstMintToken) == address(0)) return 0;
        return dstMintToken.totalSupply();
    }

    /// total_minted_on_dst - total_locked_on_src == 0.
    /// Any non-zero delta means either: (a) mint fired without a
    /// matching lock (inflation), or (b) unlock fired without a
    /// matching burn (user loss). Both are solvency breaks.
    function invariant_balance_conserved() public {
        uint256 locked = _totalLockedOnSrc();
        uint256 minted = _totalMintedOnDst();
        assertEq(
            minted,
            locked,
            "Bridge: minted/locked supply delta != 0 (conservation break)"
        );
    }
}
