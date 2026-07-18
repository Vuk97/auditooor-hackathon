// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

library GlvDeposit {
    struct Data {
        address owner;
    }

    function account(Data memory self) internal pure returns (address) {
        return self.owner;
    }
}

library GlvDepositUtils {
    bytes32 internal constant USER_INITIATED_CANCEL = keccak256("USER_INITIATED_CANCEL");

    struct CancelGlvDepositParams {
        bytes32 reason;
        address keeper;
    }
}

contract GlvHandlerPositive {
    using GlvDeposit for GlvDeposit.Data;

    function cancelGlvDeposit(GlvDeposit.Data memory deposit) external {
        GlvDepositUtils.CancelGlvDepositParams memory params =
            GlvDepositUtils.CancelGlvDepositParams({
                reason: GlvDepositUtils.USER_INITIATED_CANCEL,
                keeper: msg.sender
            });

        _cancelGlvDeposit(deposit, params);
    }

    function _cancelGlvDeposit(
        GlvDeposit.Data memory,
        GlvDepositUtils.CancelGlvDepositParams memory
    ) internal pure {}
}
