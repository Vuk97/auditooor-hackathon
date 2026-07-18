pragma solidity ^0.8.20;

contract RefinanceDoesNotPinCollateralTokenIdClean {
    struct Loan {
        address borrower;
        address principalAddress;
        address nftCollateralAddress;
        uint256 nftCollateralTokenId;
    }

    struct LoanExecutionData {
        address lender;
        address principalAddress;
        address nftCollateralAddress;
        uint256 tokenId;
    }

    mapping(uint256 => Loan) public loans;
    mapping(address => bool) public knownLenders;

    function refinanceFromLoanExecutionData(uint256 loanId, LoanExecutionData calldata executionData) external {
        Loan storage _loan = loans[loanId];
        require(msg.sender == _loan.borrower, "only borrower");
        require(_loan.principalAddress == executionData.principalAddress, "principal mismatch");
        require(_loan.nftCollateralAddress == executionData.nftCollateralAddress, "collection mismatch");
        require(_loan.nftCollateralTokenId == executionData.tokenId, "tokenId mismatch");
        require(knownLenders[executionData.lender], "unknown lender");

        _openReplacementLoan(loanId, executionData.lender, executionData.tokenId);
    }

    function _openReplacementLoan(uint256, address, uint256) internal pure {}
}
