// SPDX-License-Identifier: MIT
// A8 MUTANT fixture: CLEAN + the behavior-changing mutation = a same-tx
// value-move (claim) injected into the migration entry. Now the entry reaches
// BOTH a _migrate* step AND a value-move via internal call edges, with an
// observable intermediate (lazy per-entity version guard + external call in the
// migrate step) -> detector MUST FIRE (mutation-kill vs clean.sol).
pragma solidity ^0.8.0;

interface ILP { function sharesForAmount(uint256) external view returns (uint256); }

contract Membership {
    struct Tok { uint8 version; uint8 tier; }
    mapping(uint256 => Tok) tokenData;
    mapping(uint256 => uint128) tokenDeposits;
    ILP liquidityPool;

    // entry: migrate step AND a same-tx value-move -> fires.
    function migrateFromV0ToV1(uint256 _tokenId) public {
        claim(_tokenId);
        _migrateFromV0ToV1(_tokenId);
    }

    function _migrateFromV0ToV1(uint256 _tokenId) internal {
        if (tokenData[_tokenId].version != 0) return;
        uint256 eEthShare = liquidityPool.sharesForAmount(tokenDeposits[_tokenId]);
        _decrementTokenDeposit(_tokenId, uint128(eEthShare));
        tokenData[_tokenId].version = 1;
    }

    function _decrementTokenDeposit(uint256 a, uint128 b) internal {}
    function claim(uint256 _tokenId) public {}
}
