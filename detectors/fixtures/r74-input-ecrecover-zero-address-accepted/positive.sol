pragma solidity ^0.8.20;

contract PermitSignerZeroAccepted {
    mapping(address => uint256) public nonces;
    mapping(address => mapping(address => uint256)) public allowance;

    event Approval(address indexed owner, address indexed spender, uint256 value);

    function permitBySig(
        address owner,
        address spender,
        uint256 value,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 digest = keccak256(abi.encodePacked(address(this), owner, spender, value, nonce));
        address signer = ecrecover(digest, v, r, s);

        require(signer == owner, "bad signer");
        require(nonce == nonces[owner], "bad nonce");
        nonces[owner] = nonce + 1;

        allowance[owner][spender] = value;
        emit Approval(owner, spender, value);
    }
}
