// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.20;

// Fixture: collectProtocolFees callable while pool is unlocked — ToB L01 / Spearbit.
// Source: Uniswap/v4-core@4dc48bb (ToB L01)
// Vulnerability: Protocol fee collection transfers tokens out of the pool. If called during
// an active unlock session, the transfer happens between sync() and settle(), meaning the
// reserves used for delta calculation are stale (they include the amount being collected).
// This allows the fee controller to double-count tokens already taken, enabling theft.

contract Fix {
    bool private _unlocked;
    address public protocolFeeController;

    error InvalidCaller();

    modifier onlyController() {
        if (msg.sender != protocolFeeController) revert InvalidCaller();
        _;
    }

    function unlock(bytes calldata data) external returns (bytes memory) {
        require(!_unlocked);
        _unlocked = true;
        // callback to msg.sender
        _unlocked = false;
        return data;
    }

    // VULNERABLE: no check that contract is locked; can be called mid-unlock
    function collectProtocolFees(address recipient, address currency, uint256 amount)
        external
        onlyController
        returns (uint256 collected)
    {
        // missing: if (_unlocked) revert ContractUnlocked();
        collected = amount;
        _transfer(currency, recipient, collected);
    }

    function _transfer(address token, address to, uint256 amount) internal {
        // simplified ERC20 transfer
        (bool ok,) = token.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
        require(ok);
    }
}
