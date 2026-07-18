// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire.
///
/// fillOrder verifies an EIP-712 digest (orderHash via keccak256) that
/// covers every price-relevant field of the Order before reading any of
/// them. If the maker rotates orders[id] the recomputed digest no longer
/// matches the signature and the fill reverts — no front-run vector.
contract LimitOrderClean {
    struct Order {
        address maker;
        uint256 limitPrice;
        uint256 makerAmount;
        uint256 takerAmount;
        uint256 duration;
        uint256 nonce;
    }

    bytes32 public constant DOMAIN_SEPARATOR = keccak256("LimitOrderDomain");
    mapping(uint256 => Order) public orders;
    mapping(bytes32 => bool) public consumed;

    function submit(uint256 id, Order calldata o) external {
        orders[id] = o;
    }

    function fillOrder(uint256 id, bytes calldata sig) external {
        Order storage order = orders[id];
        // Bind every mutable field into the signed digest (orderHash /
        // orderDigest / typedDataHash form). Matches body_not_contains_regex
        // terms so the detector MUST NOT fire here.
        bytes32 orderHash = keccak256(
            abi.encode(
                DOMAIN_SEPARATOR,
                order.maker,
                order.limitPrice,
                order.makerAmount,
                order.takerAmount,
                order.duration,
                order.nonce
            )
        );
        require(!consumed[orderHash], "replayed");
        require(_recover(orderHash, sig) == order.maker, "bad sig");
        consumed[orderHash] = true;

        uint256 proceeds = order.makerAmount * order.limitPrice;
        order.makerAmount = 0;
        _settle(order.maker, msg.sender, proceeds);
    }

    function _recover(bytes32, bytes calldata) internal pure returns (address) {
        return address(0xdead);
    }

    function _settle(address, address, uint256) internal pure {}
}
