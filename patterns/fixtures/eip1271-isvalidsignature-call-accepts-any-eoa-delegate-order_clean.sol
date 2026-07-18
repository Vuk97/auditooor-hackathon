// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: same CTFExchange-style maker-order matcher, but the 1271 path
// guards against EIP-7702-delegated EOAs in two complementary ways:
//   (a) An explicit allowlist of trusted 1271 validator contracts —
//       `allowedDelegate[maker]` must be true before isValidSignature is
//       called. No EOA-installed delegate ever ends up on the allowlist.
//   (b) A runtime-bytecode prefix check — the contract reads the first 3
//       bytes of `maker.code` and rejects any address whose code begins
//       with `0xef0100` (the EIP-7702 set-code stub). Real 1271 wallets'
//       runtime bytecode never starts with that prefix.
// Either guard alone defuses the attack; using both is belt-and-braces.

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4);
}

enum SigType { EOA, POLY_1271 }

struct Order {
    address signer;
    address maker;
    uint256 makerAmount;
    uint256 takerAmount;
    bytes signature;
    SigType signatureType;
}

contract CtfExchangeClean {
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;

    /// @notice Allowlist of contracts the operator has vetted as legitimate
    /// 1271-validating smart wallets. trusted1271Validator gating on this
    /// mapping is what closes the 7702 attack surface.
    mapping(address => bool) public allowed1271;

    address public immutable governor;

    constructor(address _governor) {
        governor = _governor;
    }

    function setAllowed1271(address validator, bool ok) external {
        require(msg.sender == governor, "only-governor");
        allowed1271[validator] = ok;
    }

    function fillOrder(Order calldata order, uint256 fillAmount) external {
        bytes32 orderHash = keccak256(abi.encode(order.signer, order.maker, order.makerAmount, order.takerAmount));
        require(_isValidSignature(order, orderHash), "bad sig");
        // ... settle ...
        (fillAmount);
    }

    function _isValidSignature(Order calldata order, bytes32 hash) internal view returns (bool) {
        if (order.signatureType == SigType.EOA) {
            return order.signer == order.maker;
        }
        return _verifyPoly1271Signature(order.signer, order.maker, hash, order.signature);
    }

    function _verifyPoly1271Signature(
        address signer,
        address maker,
        bytes32 hash,
        bytes memory signature
    ) internal view returns (bool) {
        if (signer != maker) return false;
        // GUARD (a): explicit allowlist of trusted 1271 validators.
        // An attacker can install a permissive delegate on their own EOA
        // via EIP-7702, but they cannot forge an entry in this map.
        if (!allowed1271[maker]) return false;
        // GUARD (b): reject 7702-delegated EOAs by inspecting the runtime
        // bytecode prefix. EIP-7702 stubs are exactly 23 bytes long and
        // begin with the magic bytes 0xef0100; real deployed contracts'
        // runtime bytecode never starts with that prefix.
        bytes memory rt = maker.code;
        if (rt.length == 23 && rt[0] == 0xef && rt[1] == 0x01 && rt[2] == 0x00) {
            return false; // 7702-delegated EOA — refuse to treat as 1271 wallet
        }
        return IERC1271(maker).isValidSignature(hash, signature) == MAGIC_VALUE;
    }
}
