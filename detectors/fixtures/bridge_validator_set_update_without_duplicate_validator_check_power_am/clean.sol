// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BridgeValidatorSetUpdateWithoutDuplicateValidatorCheckPowerAmClean {
    error DuplicateValidator();

    struct ValidatorPower {
        address validator;
        uint256 power;
    }

    ValidatorPower[] public currentValidators;
    uint256 public totalVotingPower;

    function updateValset(address[] calldata validators, uint256[] calldata powers) external {
        require(validators.length == powers.length, "length");
        _checkNoDuplicateValidators(validators);

        delete currentValidators;
        uint256 nextTotalPower;
        for (uint256 i = 0; i < validators.length; ++i) {
            require(validators[i] != address(0), "zero validator");
            currentValidators.push(ValidatorPower({validator: validators[i], power: powers[i]}));
            nextTotalPower += powers[i];
        }

        totalVotingPower = nextTotalPower;
    }

    function _checkNoDuplicateValidators(address[] calldata validators) internal pure {
        for (uint256 i = 0; i < validators.length; ++i) {
            for (uint256 j = i + 1; j < validators.length; ++j) {
                if (validators[i] == validators[j]) {
                    revert DuplicateValidator();
                }
            }
        }
    }
}
