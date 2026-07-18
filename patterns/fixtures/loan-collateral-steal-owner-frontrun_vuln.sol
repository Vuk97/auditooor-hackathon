// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal loan manager with a per-loan record that the current owner
// controls. C0369 root cause: `buyout` / `swapCollateral` mutate loanInfo
// WITHOUT a reentrancy guard, so the current owner can frontrun (or
// re-enter via a token callback) a pending challenger buyout and steal
// collateral. Detector MUST fire on buyout and swapCollateral.
contract LoanOwnerFrontrunVuln {
    struct LoanInfo {
        address loanOwner;
        address collateral;
        uint256 collateralAmount;
        uint256 debt;
    }

    // Satisfies `contract.has_state_var_matching: loan|loanInfo|...`.
    mapping(uint256 => LoanInfo) public loanInfo;

    // VULN: buyout reads loanInfo, transfers value, and rotates loanOwner
    // WITHOUT nonReentrant. A challenger committing to buyout at the
    // observed loan parameters can be frontrun by the current owner
    // calling swapCollateral to degrade the collateral before settlement.
    function buyout(uint256 loanId) external {
        LoanInfo storage _loan = loanInfo[loanId];
        // pretend-transfer the debt from caller to the previous owner …
        _loan.loanOwner = msg.sender;
    }

    // VULN: current owner replaces collateral mid-flight. No guard, no
    // loanInfo digest check, so a pending buyout settles against the
    // degraded loan.
    function swapCollateral(uint256 loanId, address newCollateral) external {
        LoanInfo storage _loan = loanInfo[loanId];
        require(msg.sender == _loan.loanOwner, "only owner");
        _loan.collateral = newCollateral;
        _loan.collateralAmount = 1; // dust
    }

    // VULN: refinance is also unguarded; challenger's accepted offer can
    // be overwritten by the current owner before execution.
    function refinance(uint256 loanId, uint256 newDebt) external {
        LoanInfo storage _loan = loanInfo[loanId];
        require(msg.sender == _loan.loanOwner, "only owner");
        _loan.debt = newDebt;
    }

    // VULN: acceptOffer still exposed without a guard; owner can mutate
    // loanInfo during callback-triggered reentrancy.
    function acceptOffer(uint256 loanId, address challenger) external {
        LoanInfo storage _loan = loanInfo[loanId];
        _loan.loanOwner = challenger;
    }
}
