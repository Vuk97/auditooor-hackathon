// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract EthCustodianVuln {
    struct BurnResult { uint128 amount; address recipient; address ethCustodian; }

    mapping(bytes32 => bool) public usedProof;

    function parseProof(bytes calldata proofData) public pure returns (BurnResult memory r) {
        r = abi.decode(proofData, (BurnResult));
    }

    // VULN: trusts the embedded ethCustodian field as the ONLY origin
    // check. No relayer whitelist, no outcome root, no merkle proof.
    function withdraw(bytes calldata proofData) external {
        BurnResult memory r = parseProof(proofData);
        require(r.ethCustodian == address(this), "bad custodian");
        bytes32 id = keccak256(proofData);
        require(!usedProof[id], "replay");
        usedProof[id] = true;
        payable(r.recipient).transfer(uint256(r.amount));
    }

    receive() external payable {}
}
