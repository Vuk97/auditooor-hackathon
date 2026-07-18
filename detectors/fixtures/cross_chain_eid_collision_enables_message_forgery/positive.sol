// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LayerZeroDvnAdapterPositive {
    struct SrcConfig {
        uint32 eid;
        bytes32 peer;
    }

    mapping(string => SrcConfig) public srcConfig;
    mapping(uint32 => bytes32) public dstConfig;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    function setSrcConfig(string calldata chainName, uint32 eid, bytes32 peer) external onlyOwner {
        require(eid != 0, "eid");
        require(peer != bytes32(0), "peer");

        if (srcConfig[chainName].eid == 0) {
            srcConfig[chainName] = SrcConfig({eid: eid, peer: peer});
            return;
        }

        require(srcConfig[chainName].peer == peer, "peer changed");
        srcConfig[chainName].eid = eid;
    }

    function setDstConfig(uint32 eid, bytes32 trustedPeer) external onlyOwner {
        require(eid != 0, "eid");
        require(trustedPeer != bytes32(0), "peer");
        require(dstConfig[eid] == bytes32(0), "already set");
        dstConfig[eid] = trustedPeer;
    }
}
