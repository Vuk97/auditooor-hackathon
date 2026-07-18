// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Clean fixture: contract inherits plain OpenZeppelin Context only.
// _msgSender() returns msg.sender verbatim - no calldata-suffix decode, no
// trusted-forwarder relationship, no inheritance from a meta-tx context class.
// Sender forgery is impossible here.
// This MUST NOT fire the erc-2771-msgSender-forgery detector.
// Modeled on VWAPOracle.sol from hyperbridge (wave-14 FP source).

abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }
}

// Plain Context user - no ERC2771, no trustedForwarder, no isTrustedForwarder.
// _msgSender() is just msg.sender; there is nothing to forge.
contract VWAPOracle is Context {
    address public owner;
    uint256 public price;

    modifier onlyOwner() {
        require(_msgSender() == owner, "not owner");
        _;
    }

    constructor() {
        owner = _msgSender();
    }

    function updatePrice(uint256 newPrice) external onlyOwner {
        price = newPrice;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero address");
        owner = newOwner;
    }
}
