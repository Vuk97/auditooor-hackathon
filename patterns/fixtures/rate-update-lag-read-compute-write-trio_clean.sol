// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RateUpdateLagReadComputeWriteTrioClean {
    uint256[2] public rate;
    uint256 public lastTs;
    mapping(address => uint256) public shares;

    function update_rates() public {
        rate[0] = 1e18 + (block.timestamp - lastTs);
        rate[1] = 1e18;
        lastTs = block.timestamp;
    }

    function add_liquidity(uint256 amount) external {
        update_rates();
        uint256 r = rate[0];
        uint256 newShares = amount * 1e18 / r;
        shares[msg.sender] += newShares;
    }
}
