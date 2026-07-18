// Fixture: an oracle latestAnswer/price lookup shape (docstring anchor: a
// Compound/Chainlink-style cToken/oracle the Punk-style lending target reads).
// latestAnswer() and price(address) are settable getters the exploit drives to
// manipulate the donation/inflation valuation; latestRoundData() is a
// multi-return view backed by a safe-default stub. Generic SHAPE.
interface IPriceOracle {
    function latestAnswer() external view returns (int256);
    function price(address token) external view returns (uint256);
    function latestRoundData() external view returns (
        uint80 roundId, int256 answer, uint256 startedAt,
        uint256 updatedAt, uint80 answeredInRound);
    function decimals() external view returns (uint8);
}
