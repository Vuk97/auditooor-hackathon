// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GovParamInjectionClean {
    struct Proposal {
        bytes32 payloadHash;
        bytes32 descriptionHash;
        uint256 snapshot;
        uint256 readyAt;
        bool executed;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(bytes4 => address) public selectorTarget;
    mapping(bytes32 => uint256) public governanceParameters;

    bytes32 public immutable DOMAIN_SEPARATOR;
    uint256 public constant MIN_FORK_THRESHOLD = 1;
    uint256 public constant MAX_FORK_THRESHOLD = 10_000;
    uint256 public constant MIN_VOTING_WINDOW = 1 days;
    uint256 public constant MAX_VOTING_WINDOW = 14 days;
    uint256 public constant MAX_DISTRIBUTION_AMOUNT = 1_000_000 ether;
    uint256 public timelockDelay = 2 days;
    address public governor;

    modifier onlyGovernance() {
        require(msg.sender == governor, "only governance");
        _;
    }

    constructor(address newGovernor) {
        require(newGovernor != address(0), "zero governor");
        governor = newGovernor;
        DOMAIN_SEPARATOR = keccak256(abi.encode(block.chainid, address(this)));
    }

    function updateProposal(uint256 proposalId, bytes32 currentHash, bytes32 newPayloadHash, bytes32 newDescriptionHash) external onlyGovernance {
        Proposal storage proposal = proposals[proposalId];
        require(proposal.snapshot < block.number, "snapshot pending");
        require(proposal.payloadHash == currentHash, "stale proposal");
        proposal.payloadHash = newPayloadHash;
        proposal.descriptionHash = newDescriptionHash;
        proposal.readyAt = block.timestamp + timelockDelay;
    }

    function executeProposal(uint256 proposalId, bytes4 selector, address target) external onlyGovernance {
        Proposal storage proposal = proposals[proposalId];
        require(block.timestamp >= proposal.readyAt, "delay");
        require(target != address(0), "zero target");
        proposal.executed = true;
        selectorTarget[selector] = target;
    }

    function setGovernanceParameter(bytes32 key, uint256 value, uint256 minValue, uint256 maxValue) external onlyGovernance {
        require(minValue <= value && value <= maxValue, "bounds");
        require(block.timestamp >= proposals[uint256(key)].readyAt, "delay");
        governanceParameters[key] = value;
    }

    function executeFork(uint256 newForkThreshold, uint256 newVotingWindow) external onlyGovernance {
        require(newForkThreshold >= MIN_FORK_THRESHOLD && newForkThreshold <= MAX_FORK_THRESHOLD, "fork bounds");
        require(newVotingWindow >= MIN_VOTING_WINDOW && newVotingWindow <= MAX_VOTING_WINDOW, "window bounds");
        proposals[0].snapshot = block.number - 1;
    }

    function mintGTToAddress(address to, uint256 amount) external onlyGovernance {
        require(to != address(0), "zero recipient");
        require(amount <= MAX_DISTRIBUTION_AMOUNT, "cap");
        _mint(to, amount);
    }

    function _mint(address, uint256) internal {}
}
