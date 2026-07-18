// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire.
/// Same PufferVault-style restaking delegator, but every withdraw path
/// burns the caller's delegated shares atomically with the asset
/// movement. `_burn`, `decreaseShares`, and `burnPodShares` calls are
/// present in the respective function bodies, suppressing the match.
contract RestakingWithdrawClean {
    mapping(address => uint256) public delegatedShares;
    uint256 public validatorBalance;
    uint256 public totalDelegatedShares;

    event Burn(address indexed from, uint256 shares);

    function deposit() external payable {
        uint256 sharesOut = msg.value;
        delegatedShares[msg.sender] += sharesOut;
        totalDelegatedShares += sharesOut;
        validatorBalance += msg.value;
    }

    function completeWithdrawal(uint256 amt) external {
        require(delegatedShares[msg.sender] >= amt, "insufficient");
        _burn(msg.sender, amt);
        validatorBalance -= amt;
        (bool ok, ) = payable(msg.sender).call{value: amt}("");
        require(ok);
    }

    function processWithdraw(uint256 amt) external {
        decreaseShares(msg.sender, amt);
        validatorBalance -= amt;
        (bool ok, ) = payable(msg.sender).call{value: amt}("");
        require(ok);
    }

    function finalizeWithdraw(uint256 amt) external {
        burnPodShares(msg.sender, amt);
        validatorBalance -= amt;
        (bool ok, ) = payable(msg.sender).call{value: amt}("");
        require(ok);
    }

    function _burn(address from, uint256 amt) internal {
        delegatedShares[from] -= amt;
        totalDelegatedShares -= amt;
        emit Burn(from, amt);
    }

    function decreaseShares(address from, uint256 amt) internal {
        delegatedShares[from] -= amt;
        totalDelegatedShares -= amt;
    }

    function burnPodShares(address from, uint256 amt) internal {
        delegatedShares[from] -= amt;
        totalDelegatedShares -= amt;
    }
}
