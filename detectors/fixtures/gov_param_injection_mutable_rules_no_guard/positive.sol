// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IGovRouteRegistry {
    function setSelector(bytes4 selector, address target) external;
}

contract GovParamInjectionPositive {
    struct Proposal {
        bytes32 payloadHash;
        bytes32 descriptionHash;
        bool executed;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(bytes4 => address) public selectorTarget;
    mapping(bytes32 => uint256) public governanceParameters;

    uint256 public forkThreshold;
    uint256 public votingWindow;
    uint256 public distributionAmount;
    address public governor;
    IGovRouteRegistry public registry;

    constructor(IGovRouteRegistry registry_) {
        registry = registry_;
        forkThreshold = 100;
        votingWindow = 3 days;
        distributionAmount = 1_000_000 ether;
    }

    function updateProposal(uint256 proposalId, bytes32 newPayloadHash, bytes32 newDescriptionHash) external {
        proposals[proposalId].payloadHash = newPayloadHash;
        proposals[proposalId].descriptionHash = newDescriptionHash;
    }

    function executeProposal(uint256 proposalId, bytes4 selector, address target) external {
        proposals[proposalId].executed = true;
        selectorTarget[selector] = target;
        registry.setSelector(selector, target);
    }

    function setGovernanceParameter(bytes32 key, uint256 value) external {
        governanceParameters[key] = value;
    }

    function executeFork(uint256 newForkThreshold, uint256 newVotingWindow) external {
        forkThreshold = newForkThreshold;
        votingWindow = newVotingWindow;
    }

    function mintGTToAddress(address to, uint256 amount) external {
        distributionAmount = amount;
        _mint(to, amount);
    }

    function initialize(address newGovernor) external {
        governor = newGovernor;
    }

    function _mint(address, uint256) internal {}
}
