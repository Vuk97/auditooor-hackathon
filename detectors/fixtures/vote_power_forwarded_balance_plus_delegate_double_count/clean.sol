// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VotePowerForwardedBalancePlusDelegateDoubleCountClean {
    struct Period {
        mapping(uint256 => bool) voted;
        mapping(uint256 => address[]) tokenIdVotedList;
        mapping(address => mapping(uint256 => uint256)) tokenIdVotes;
    }

    mapping(uint256 => Period) private period;
    mapping(address => address) public gauge;
    mapping(uint256 => uint256) public totalWeight;

    function seed(uint256 periodId, uint256 tokenId, address pool, address gaugeAddress, uint256 weight) external {
        gauge[pool] = gaugeAddress;
        period[periodId].tokenIdVotedList[tokenId].push(pool);
        period[periodId].tokenIdVotes[gaugeAddress][tokenId] = weight;
    }

    function getCurrentPeriod() public pure returns (uint256) {
        return 10;
    }

    function carryVoteForward(uint256 _tokenId, uint256 _fromPeriod) public {
        uint256 nextPeriod = getCurrentPeriod() + 1;
        require(!period[nextPeriod].voted[_tokenId], "already voted");
        period[nextPeriod].voted[_tokenId] = true;

        Period storage ps = period[_fromPeriod];
        address[] memory _poolList = ps.tokenIdVotedList[_tokenId];
        uint256[] memory _weightList = new uint256[](_poolList.length);

        for (uint256 i; i < _poolList.length; i++) {
            address _gauge = gauge[_poolList[i]];
            _weightList[i] = ps.tokenIdVotes[_gauge][_tokenId];
        }

        _vote(nextPeriod, _tokenId, _poolList, _weightList);
    }

    function _vote(uint256 targetPeriod, uint256 tokenId, address[] memory pools, uint256[] memory weights) internal {
        for (uint256 i; i < pools.length; i++) {
            period[targetPeriod].tokenIdVotes[gauge[pools[i]]][tokenId] += weights[i];
            totalWeight[targetPeriod] += weights[i];
        }
    }
}
