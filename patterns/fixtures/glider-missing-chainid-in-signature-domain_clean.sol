// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract SigClean {
    mapping(bytes32 => bool) public used;

    function withdraw(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(to, amount, block.chainid, address(this)));
        address signer = ecrecover(digest, v, r, s);
        require(signer == to, "bad sig");
        require(!used[digest], "replay");
        used[digest] = true;
        payable(to).transfer(amount);
    }

    receive() external payable {}
}
