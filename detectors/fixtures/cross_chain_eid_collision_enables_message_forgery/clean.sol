// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LayerZeroDvnAdapterClean {
    struct SrcConfig {
        uint32 eid;
        bytes32 peer;
    }

    mapping(string => SrcConfig) public srcConfig;
    mapping(uint32 => string) public eidToChain;
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
        _assertUniqueEid(chainName, eid);

        if (srcConfig[chainName].eid == 0) {
            srcConfig[chainName] = SrcConfig({eid: eid, peer: peer});
            eidToChain[eid] = chainName;
            return;
        }

        require(srcConfig[chainName].peer == peer, "peer changed");
        srcConfig[chainName].eid = eid;
        eidToChain[eid] = chainName;
    }

    function setDstConfig(uint32 eid, bytes32 trustedPeer) external onlyOwner {
        require(eid != 0, "eid");
        require(trustedPeer != bytes32(0), "peer");
        require(dstConfig[eid] == bytes32(0), "already set");
        dstConfig[eid] = trustedPeer;
    }

    function _assertUniqueEid(string calldata chainName, uint32 eid) internal view {
        bytes memory claimed = bytes(eidToChain[eid]);
        require(claimed.length == 0 || keccak256(claimed) == keccak256(bytes(chainName)), "eid claimed");
    }
}
