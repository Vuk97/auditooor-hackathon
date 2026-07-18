// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IDepositContract {
    function deposit(
        bytes calldata pubkey,
        bytes calldata withdrawal_credentials,
        bytes calldata signature,
        bytes32 deposit_data_root
    ) external payable;
}

contract RocketPoolNodeOperatorDepositSafe {
    address internal constant DEPOSIT_CONTRACT = 0x00000000219ab540356cBB839Cbe05303d7705Fa;
    bytes32 public predeposit_root;

    function submitNodeDeposit(
        bytes calldata pubkey,
        bytes calldata withdrawalCredentials,
        bytes calldata signature,
        bytes32 depositDataRoot
    ) external payable {
        require(predeposit_root != bytes32(0), "guard");
        require(msg.value == 32 ether, "stake");
        IDepositContract(DEPOSIT_CONTRACT).deposit{value: 32 ether}(
            pubkey,
            withdrawalCredentials,
            signature,
            depositDataRoot
        );
    }
}
