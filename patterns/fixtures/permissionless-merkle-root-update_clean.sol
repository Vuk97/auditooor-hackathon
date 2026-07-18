// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address a) external view returns (uint256);
}

// CLEAN: merkle-root setter is onlyOwner-gated.
contract StakingMerkleClean {
    address public owner;
    IERC20 public rewardToken;
    bytes32 public merkleRoot;
    mapping(address => bool) public claimed;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(IERC20 _rewardToken) {
        owner = msg.sender;
        rewardToken = _rewardToken;
    }

    function updateMerkleRoot(bytes32 newRoot) external onlyOwner {
        merkleRoot = newRoot;
    }

    function claim(uint256 amount, bytes32[] calldata proof) external {
        require(!claimed[msg.sender], "already claimed");
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, amount));
        require(_verify(proof, merkleRoot, leaf), "bad proof");
        claimed[msg.sender] = true;
        rewardToken.transfer(msg.sender, amount);
    }

    function _verify(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        bytes32 cur = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 p = proof[i];
            cur = cur < p ? keccak256(abi.encodePacked(cur, p)) : keccak256(abi.encodePacked(p, cur));
        }
        return cur == root;
    }
}
