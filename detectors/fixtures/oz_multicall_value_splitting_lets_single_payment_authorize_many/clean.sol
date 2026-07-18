pragma solidity ^0.8.20;

contract Multicall {
    function multicall(bytes[] calldata data) external payable returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; ++i) {
            (bool ok, bytes memory ret) = address(this).delegatecall(data[i]);
            require(ok, "delegatecall failed");
            results[i] = ret;
        }
    }
}

contract SinglePaymentTicketSaleSafe is Multicall {
    uint256 public immutable pricePerSeat = 1 ether;
    uint256 private accountedBalance;
    mapping(uint256 => bool) public seatAuthorized;

    function authorizeSeat(uint256 seatId) external payable {
        require(!seatAuthorized[seatId], "already authorized");
        require(address(this).balance >= accountedBalance + pricePerSeat, "price");
        accountedBalance += pricePerSeat;
        seatAuthorized[seatId] = true;
    }
}
