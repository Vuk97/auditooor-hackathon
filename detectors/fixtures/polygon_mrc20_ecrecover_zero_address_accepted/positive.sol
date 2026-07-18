pragma solidity ^0.8.20;

contract PolygonMrc20RawEcrecoverAccepted {
    mapping(address => uint256) public balances;
    mapping(bytes32 => bool) public used;

    event Transfer(address indexed from, address indexed to, uint256 amount);

    constructor() {
        balances[address(this)] = 10_000_000 ether;
    }

    function transferWithSig(
        address to,
        uint256 amount,
        uint256 nonce,
        bytes32 r,
        bytes32 s,
        uint8 v,
        bytes calldata signature
    ) external {
        bytes32 digest = keccak256(abi.encodePacked(address(this), to, amount, nonce));
        address from = ecrecover(digest, v, r, s);

        require(!used[digest], "replayed");
        used[digest] = true;
        signature;

        _transfer(from, to, amount);
    }

    function _transfer(address from, address to, uint256 amount) internal {
        unchecked {
            balances[from] -= amount;
            balances[to] += amount;
        }
        emit Transfer(from, to, amount);
    }
}
