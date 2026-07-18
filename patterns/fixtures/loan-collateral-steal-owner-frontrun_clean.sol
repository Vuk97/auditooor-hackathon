// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Clean variant: every buyout / refinance / takeover entry is gated by
// the `nonReentrant` modifier, so the has_modifier negate:true predicate
// fails and the detector does NOT fire. A loanInfo digest check is also
// present to block mempool frontruns even without reentrancy.
contract LoanOwnerFrontrunClean {
    struct LoanInfo {
        address loanOwner;
        address collateral;
        uint256 collateralAmount;
        uint256 debt;
    }

    mapping(uint256 => LoanInfo) public loanInfo;

    uint256 private _locked = 1;
    modifier nonReentrant() {
        require(_locked == 1, "reentrancy");
        _locked = 2;
        _;
        _locked = 1;
    }

    // CLEAN: nonReentrant modifier present. Pattern `has_modifier`
    // negate:true predicate fails → detector is suppressed.
    function buyout(uint256 loanId, bytes32 expectedDigest) external nonReentrant {
        LoanInfo storage _loan = loanInfo[loanId];
        bytes32 actual = keccak256(abi.encode(_loan.loanOwner, _loan.collateral, _loan.collateralAmount, _loan.debt));
        require(actual == expectedDigest, "loan mutated mid-flight");
        _loan.loanOwner = msg.sender;
    }

    function swapCollateral(uint256 loanId, address newCollateral) external nonReentrant {
        LoanInfo storage _loan = loanInfo[loanId];
        require(msg.sender == _loan.loanOwner, "only owner");
        _loan.collateral = newCollateral;
        _loan.collateralAmount = 1;
    }

    function refinance(uint256 loanId, uint256 newDebt) external nonReentrant {
        LoanInfo storage _loan = loanInfo[loanId];
        require(msg.sender == _loan.loanOwner, "only owner");
        _loan.debt = newDebt;
    }

    function acceptOffer(uint256 loanId, address challenger) external nonReentrant {
        LoanInfo storage _loan = loanInfo[loanId];
        _loan.loanOwner = challenger;
    }
}
