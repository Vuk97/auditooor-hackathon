pragma solidity ^0.8.20;

contract PayableMulticall {
    function multicall(bytes[] calldata data) external payable returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; ++i) {
            (bool ok, bytes memory ret) = address(this).delegatecall(data[i]);
            require(ok, "delegatecall failed");
            results[i] = ret;
        }
    }
}

contract SeatReservationVaultSafe is PayableMulticall {
    uint256 public immutable seatPrice = 1 ether;
    uint256 private accountedBalance;
    mapping(uint256 => bool) public seatBooked;

    function reserveSeat(uint256 seatId) external payable {
        require(!seatBooked[seatId], "booked");
        require(address(this).balance >= accountedBalance + seatPrice, "price");
        accountedBalance += seatPrice;
        seatBooked[seatId] = true;
    }
}
