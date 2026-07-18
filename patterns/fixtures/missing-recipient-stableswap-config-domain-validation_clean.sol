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

library LPFeeLibrary {
    uint24 internal constant DYNAMIC_FEE_FLAG = 0x800000;
}

contract MissingRecipientStableSwapConfigDomainValidationClean {
    uint256 public constant MAX_AMP = 1_000_000;
    uint256 public constant MAX_LP_FEE = 1_000_000;
    uint256 public baseAmp;
    bytes32 public creationCodeHash;

    error InvalidAmp();
    error InvalidFee();

    constructor(uint256 _baseAmp) {
        if (_baseAmp == 0 || _baseAmp >= MAX_AMP) {
            revert InvalidAmp();
        }

        baseAmp = _baseAmp * StableSwapMathFixture.AMP_PRECISION;
    }

    function deploy(bytes calldata _creationCode, uint256 _lpFeePercentage, bytes32 _salt)
        external
        returns (address deployedHook)
    {
        if (_lpFeePercentage > MAX_LP_FEE || _lpFeePercentage == LPFeeLibrary.DYNAMIC_FEE_FLAG) {
            revert InvalidFee();
        }

        if (keccak256(_creationCode) != creationCodeHash) {
            revert();
        }

        bytes memory bytecode = abi.encodePacked(_creationCode, abi.encode(_lpFeePercentage));
        deployedHook = Create2.deploy(0, _salt, bytecode);
    }
}
