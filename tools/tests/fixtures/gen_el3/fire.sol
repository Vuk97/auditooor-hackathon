contract C {
    mapping(bytes32 => bool) seen;
    function submit(bytes calldata data) external {
        (uint256 a, address b) = abi.decode(data, (uint256, address));
        bytes32 id = keccak256(data);
        require(!seen[id], "dup");
        seen[id] = true;
        use(a, b);
    }
}
