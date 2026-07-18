// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract DvBridgeLikeClean {
    address[] public validators;
    uint256 public validator_fee = 0.01 ether;
    uint256 public chain_id = 1;

    mapping(uint256 => mapping(address => mapping(address => uint256))) public maxPerRoute;

    event TransferInitiated(
        address indexed from, address indexed to, uint256 amount,
        uint256 src, uint256 dst, address tokenIn, address tokenOut
    );

    constructor(address[] memory _validators) payable {
        validators = _validators;
    }

    function isTransferAllowed(
        uint256 destination_chain, address token_in, address token_out, uint256 amount
    ) public view returns (bool) {
        return maxPerRoute[destination_chain][token_in][token_out] >= amount;
    }

    // CLEAN: caller must supply at least `validator_fee` in msg.value —
    // the reward is funded from the caller, not from the bridge's pool.
    function initiateTransfer(
        address recipient,
        uint256 amount,
        uint256 source_chain,
        uint256 destination_chain,
        address token_in,
        address token_out
    ) public payable returns (bool) {
        require(msg.value >= validator_fee, "insufficient fee");
        require(recipient != address(0), "zero recipient");
        require(amount > 0, "zero amount");
        require(source_chain == chain_id, "bad source");
        require(destination_chain != chain_id, "bad dest");
        require(
            isTransferAllowed(destination_chain, token_in, token_out, amount),
            "route"
        );

        emit TransferInitiated(
            msg.sender, recipient, amount, source_chain, destination_chain,
            token_in, token_out
        );

        rewardValidators(validator_fee);
        uint256 refund = msg.value - validator_fee;
        if (refund > 0) payable(msg.sender).transfer(refund);
        return true;
    }

    function rewardValidators(uint256 validator_fee_) internal {
        uint256 amount = validator_fee_ / validators.length;
        for (uint256 i = 0; i < validators.length; i++) {
            payable(validators[i]).transfer(amount);
        }
    }

    receive() external payable {}
}
