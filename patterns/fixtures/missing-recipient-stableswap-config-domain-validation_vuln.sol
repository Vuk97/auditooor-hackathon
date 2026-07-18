// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library Create2 {
    function deploy(uint256, bytes32, bytes memory) internal returns (address) {
        return address(0xBEEF);
    }
}

library StableSwapMathFixture {
    uint256 internal constant AMP_PRECISION = 100;
}

contract MissingRecipientStableSwapConfigDomainValidationVuln {
    uint256 public constant MAX_AMP = 1_000_000;
    uint256 public baseAmp;

    error InvalidAmp();

    constructor(uint256 _baseAmp) {
        if (_baseAmp >= MAX_AMP) {
            revert InvalidAmp();
        }

        baseAmp = _baseAmp * StableSwapMathFixture.AMP_PRECISION;
    }
}

contract MissingRecipientStableSwapHookFactoryDomainValidationVuln {
    bytes32 public creationCodeHash;

    function deploy(bytes calldata _creationCode, uint256 _lpFeePercentage, bytes32 _salt)
        external
        returns (address deployedHook)
    {
        if (keccak256(_creationCode) != creationCodeHash) {
            revert();
        }

        bytes memory bytecode = abi.encodePacked(_creationCode, abi.encode(_lpFeePercentage));
        deployedHook = Create2.deploy(0, _salt, bytecode);
    }
}
