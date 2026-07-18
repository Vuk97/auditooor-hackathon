// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: a CTFExchange-style maker-order matching contract authenticates
// POLY_1271 orders by calling isValidSignature on the order's maker address
// without any defence against EIP-7702-delegated EOAs. Post-Pectra an
// attacker can:
//   1. Deploy a "PermissiveDelegate" contract whose isValidSignature
//      returns the 0x1626ba7e magic value for any input.
//   2. Submit a type-4 set-code transaction making their own EOA delegate
//      to that contract.
//   3. Sign and submit an order claiming arbitrary maker = their EOA, with
//      signatureType = POLY_1271 and an empty signature blob.
// fillOrder() routes through _verifyPoly1271Signature, the code.length > 0
// check passes (the 7702 stub is 23 bytes), and the delegate accepts the
// hash unconditionally — the order fills against attacker-favourable price.
//
// Real-world shape: Polymarket CTFExchange::_verifyPoly1271Signature uses
// `maker.code.length > 0 && SignatureCheckerLib.isValidSignatureNow(...)`
// which fits exactly this anti-pattern.

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

contract CtfExchangeVuln {
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;

    event OrderFilled(address indexed maker, uint256 makerAmount, uint256 takerAmount);

    /// @notice External entrypoint that fills a maker order.
    /// VULN: routes 1271 orders to isValidSignature() on attacker-controlled
    /// maker without any allowlist of trusted 1271 validators and without
    /// distinguishing 7702-delegated EOAs from real 1271 wallets.
    function fillOrder(Order calldata order, uint256 fillAmount) external {
        bytes32 orderHash = keccak256(abi.encode(order.signer, order.maker, order.makerAmount, order.takerAmount));
        require(_isValidSignature(order, orderHash), "bad sig");

        // ... transfer maker collateral, transfer taker collateral, settle ...
        emit OrderFilled(order.maker, order.makerAmount, fillAmount);
    }

    function _isValidSignature(Order calldata order, bytes32 hash) internal view returns (bool) {
        if (order.signatureType == SigType.EOA) {
            // ECDSA path omitted for brevity.
            return order.signer == order.maker;
        }
        // POLY_1271 — VULN: no allowlist, no 7702 prefix check.
        return _verifyPoly1271Signature(order.signer, order.maker, hash, order.signature);
    }

    function _verifyPoly1271Signature(
        address signer,
        address maker,
        bytes32 hash,
        bytes memory signature
    ) internal view returns (bool) {
        // VULN: code.length > 0 check is the *only* "is this a contract?"
        // discriminator. A 7702-delegated EOA has 23 bytes of code (prefix
        // 0xef0100 || delegate-address). The check passes, and the delegate
        // is trusted to validate signatures for the maker.
        return (signer == maker)
            && maker.code.length > 0
            && IERC1271(maker).isValidSignature(hash, signature) == MAGIC_VALUE;
    }
}
