// SPDX-License-Identifier: MIT
// A8 CLEAN fixture: a migration entry that reaches the migrate step but does
// NOT perform a same-tx value-move -> the migration-reestablish predicate is
// NOT met -> detector must be SILENT. Structure mirrors etherfi
// MembershipManager.migrateFromV0ToV1 with the value-move edge removed.
pragma solidity ^0.8.0;

interface ILP { function sharesForAmount(uint256) external view returns (uint256); }

contract Membership {
    struct Tok { uint8 version; uint8 tier; }
    mapping(uint256 => Tok) tokenData;
    mapping(uint256 => uint128) tokenDeposits;
    ILP liquidityPool;

    // entry: migrate step ONLY, no same-tx value move -> silent.
    function migrateFromV0ToV1(uint256 _tokenId) public {
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
