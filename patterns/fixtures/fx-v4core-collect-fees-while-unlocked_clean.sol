// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.20;

// Fixture: fixed collectProtocolFees — revert if called while pool is unlocked.
// Source: Uniswap/v4-core@4dc48bb (ToB L01)

contract Fix {
    bool private _unlocked;
    address public protocolFeeController;

    error InvalidCaller();
    error ContractUnlocked();

    modifier onlyController() {
        if (msg.sender != protocolFeeController) revert InvalidCaller();
        _;
    }

    function unlock(bytes calldata data) external returns (bytes memory) {
        require(!_unlocked);
        _unlocked = true;
        _unlocked = false;
        return data;
    }

    // FIXED: revert when unlock session is active to prevent mid-tx fee drainage
    function collectProtocolFees(address recipient, address currency, uint256 amount)
        external
        onlyController
        returns (uint256 collected)
    {
        if (_unlocked) revert ContractUnlocked(); // FIXED
        collected = amount;
        _transfer(currency, recipient, collected);
    }

    function _transfer(address token, address to, uint256 amount) internal {
        (bool ok,) = token.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
        require(ok);
    }
}
