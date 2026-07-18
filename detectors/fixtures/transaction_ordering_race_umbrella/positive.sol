// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// positive.sol - transaction-ordering-race-umbrella
// Source-shape fixture only. Each contract models one transaction-ordering-race
// subfamily from the same recall-gap row.

contract VulnERC20 {
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public balanceOf;

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "insufficient allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    event Approval(address indexed owner, address indexed spender, uint256 value);
}

contract ProposalOrderingRace {
    struct Proposal {
        address proposer;
        bool exists;
    }

    mapping(bytes32 => Proposal) public proposals;

    function propose(bytes32 proposalId) external {
        proposals[proposalId] = Proposal(msg.sender, true);
    }
}

contract PublicNonceInvalidationRace {
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;

    function invalidateNonce(address maker, uint256 word, uint256 bit) external {
        nonceBitmap[maker][word] |= bit;
    }
}

interface IOptimismPortalLike {
    function finalizeWithdrawalTransaction(bytes calldata withdrawalTx) external;
}

contract WithdrawalFinalizeRace {
    IOptimismPortalLike public optimismPortal;
    mapping(bytes32 => uint256) public provenAt;
    mapping(bytes32 => bool) public finalized;
    uint256 public finalizationPeriodSeconds = 7 days;

    function finalizeWithdrawal(bytes32 withdrawalHash, bytes calldata withdrawalTx) external {
        require(block.timestamp >= provenAt[withdrawalHash] + finalizationPeriodSeconds, "early");
        finalized[withdrawalHash] = true;
        optimismPortal.finalizeWithdrawalTransaction(withdrawalTx);
    }
}

contract RepayOnBehalfRace {
    struct Loan {
        address borrower;
        uint256 amount;
        uint256 lastAction;
    }

    mapping(uint256 => Loan) public loans;

    function isolateRepay(uint256 loanId, address onBehalfOf, uint256 amount) external {
        Loan storage loan = loans[loanId];
        require(loan.borrower == onBehalfOf, "borrower mismatch");
        loan.amount -= amount;
        loan.lastAction = block.timestamp;
    }
}
