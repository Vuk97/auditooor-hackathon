pragma solidity ^0.8.20;

contract CleanCollectionSettings {
    address public collectionAdmin;
    mapping(address => uint256) public reclaimAfter;
    mapping(address => bool) public enhancedRoyaltiesEnabled;

    modifier onlyCollectionAdmin() {
        require(msg.sender == collectionAdmin, "not admin");
        _;
    }

    constructor(address admin) {
        collectionAdmin = admin;
    }

    function addPair(address pair) external onlyCollectionAdmin {
        enhancedRoyaltiesEnabled[pair] = true;
        reclaimAfter[pair] = block.timestamp + 7 days;
    }

    function reclaimPair(address pair) external onlyCollectionAdmin {
        require(block.timestamp >= reclaimAfter[pair], "still locked");
        enhancedRoyaltiesEnabled[pair] = false;
        delete reclaimAfter[pair];
    }
}
