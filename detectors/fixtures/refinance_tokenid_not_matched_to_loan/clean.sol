pragma solidity ^0.8.20;

contract RefinanceTokenIdNotMatchedToLoanClean {
    struct Loan {
        address borrower;
        uint256 nftCollateralTokenId;
    }

    struct LoanExecutionData {
        address lender;
        uint256 tokenId;
        uint256 principal;
    }

    mapping(uint256 => Loan) public loans;
    mapping(address => mapping(uint256 => bool)) public lenderOfferAllowsTokenId;

    function refinanceFromLoanExecutionData(uint256 loanId, LoanExecutionData calldata executionData) external {
        Loan storage loan = loans[loanId];
        require(msg.sender == loan.borrower, "only borrower");
        require(executionData.tokenId == loan.nftCollateralTokenId, "tokenId mismatch");
        require(lenderOfferAllowsTokenId[executionData.lender][executionData.tokenId], "offer tokenId rejected");

        uint256 validatedTokenId = executionData.tokenId;
        _openReplacementLoan(loanId, validatedTokenId, executionData.principal, executionData.lender);
    }

    function _openReplacementLoan(uint256, uint256, uint256, address) internal pure {}
}
