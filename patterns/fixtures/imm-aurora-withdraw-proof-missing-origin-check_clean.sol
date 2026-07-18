// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ILightClient {
    function verifyOutcome(bytes calldata proof) external view returns (bool);
}

contract EthCustodianClean {
    struct BurnResult { uint128 amount; address recipient; address ethCustodian; }
    mapping(bytes32 => bool) public usedProof;
    mapping(address => bool) public trustedRelayer;
    address public lightClient;

    modifier onlyRelayer() { require(trustedRelayer[msg.sender], "not relayer"); _; }

    function parseProof(bytes calldata proofData) public pure returns (BurnResult memory r) {
        r = abi.decode(proofData, (BurnResult));
    }

    function withdraw(bytes calldata proofData) external onlyRelayer {
        require(ILightClient(lightClient).verifyOutcome(proofData), "origin");
        BurnResult memory r = parseProof(proofData);
        require(r.ethCustodian == address(this), "bad custodian");
        bytes32 id = keccak256(proofData);
        require(!usedProof[id], "replay");
        usedProof[id] = true;
        payable(r.recipient).transfer(uint256(r.amount));
    }

    receive() external payable {}
}
