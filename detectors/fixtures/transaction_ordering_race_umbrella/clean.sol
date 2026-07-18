// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// clean.sol - transaction-ordering-race-umbrella
// Source-shape fixture only. Each clean control preserves the public operation
// but adds the class-specific ordering guard.

contract CleanERC20 {
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public balanceOf;

    function approve(address spender, uint256 amount) external returns (bool) {
        require(
            allowance[msg.sender][spender] == 0 || amount == 0,
            "reset first"
        );
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    // CLEAN: increaseAllowance is race-safe (no frontrun double-spend path).
    function increaseAllowance(address spender, uint256 addedValue) external returns (bool) {
        allowance[msg.sender][spender] += addedValue;
        emit Approval(msg.sender, spender, allowance[msg.sender][spender]);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool) {
        uint256 currentAllowance = allowance[msg.sender][spender];
        require(currentAllowance >= subtractedValue, "decreased below zero");
        allowance[msg.sender][spender] = currentAllowance - subtractedValue;
        emit Approval(msg.sender, spender, allowance[msg.sender][spender]);
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

contract CleanProposalOrdering {
    struct Proposal {
        address proposer;
        bool exists;
    }

    mapping(bytes32 => Proposal) public proposals;

    function propose(bytes32 proposalId, bytes32 proposalSalt) external {
        bytes32 saltedId = keccak256(abi.encode(msg.sender, proposalSalt, proposalId));
        require(!proposals[saltedId].exists, "exists");
        proposals[saltedId] = Proposal(msg.sender, true);
    }
}

contract CleanNonceInvalidation {
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;

    function invalidateNonce(address maker, uint256 word, uint256 bit) external {
        require(msg.sender == maker, "maker only");
        nonceBitmap[maker][word] |= bit;
    }
}

interface IFaultDisputeGameLike {
    function status() external view returns (uint8);
}

interface IOptimismPortalCleanLike {
    function finalizeWithdrawalTransaction(bytes calldata withdrawalTx) external;
}

contract CleanWithdrawalFinalize {
    IOptimismPortalCleanLike public optimismPortal;
    IFaultDisputeGameLike public faultDisputeGame;
    mapping(bytes32 => uint256) public provenAt;
    mapping(bytes32 => bool) public finalized;
    uint256 public finalizationPeriodSeconds = 7 days;
    uint256 public proofMaturityDelaySeconds = 1 days;
    uint256 public disputeGameFinalityDelaySeconds = 3 days;
    uint8 public constant DEFENDER_WINS = 1;

    function finalizeWithdrawal(bytes32 withdrawalHash, bytes calldata withdrawalTx) external {
        require(
            block.timestamp >=
                provenAt[withdrawalHash] +
                    finalizationPeriodSeconds +
                    proofMaturityDelaySeconds +
                    disputeGameFinalityDelaySeconds,
            "early"
        );
        require(faultDisputeGame.status() == DEFENDER_WINS, "game unresolved");
        finalized[withdrawalHash] = true;
        optimismPortal.finalizeWithdrawalTransaction(withdrawalTx);
    }
}

contract CleanRepayOnBehalf {
    struct Loan {
        address borrower;
        uint256 amount;
        uint256 lastAction;
    }

    mapping(uint256 => Loan) public loans;
    mapping(address => mapping(address => bool)) public approvedRepayer;

    function isolateRepay(uint256 loanId, address onBehalfOf, uint256 amount) external {
        Loan storage loan = loans[loanId];
        require(loan.borrower == onBehalfOf, "borrower mismatch");
        require(
            msg.sender == loan.borrower || approvedRepayer[loan.borrower][msg.sender],
            "not approved"
        );
        loan.amount -= amount;
        loan.lastAction = block.timestamp;
    }
}
