// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for
/// the chainlink-feed-registry-address-hardcoded detector. DO NOT DEPLOY.
///
/// The mainnet Chainlink FeedRegistry address is baked into an oracle
/// read path with no chainid branch. Any non-mainnet deployment
/// (Arbitrum, Optimism, Base, Polygon, BNB, Avalanche, etc.) will
/// either revert on every call or — worse — silently consume bytes
/// returned by an unrelated contract at the same address.
interface IFeedRegistry {
    function latestRoundData(address base, address quote)
        external
        view
        returns (uint80, int256, uint256, uint256, uint80);
}

contract PriceReaderVuln {
    // VULN: literal mainnet FeedRegistry address hardcoded. The
    // detector's positive regex anchor will match on the address
    // literal AND on the `FeedRegistry(0x...)` cast shape below.
    function getPrice(address base, address quote) external view returns (int256) {
        // Both triggers fire in a single line: the raw address literal
        // AND the FeedRegistryInterface(0x...) cast idiom.
        IFeedRegistry reg = IFeedRegistry(0x47Fb2585D2C56Fe188D0E6ec628a38b74fCeeeDf);
        (, int256 answer, , , ) = reg.latestRoundData(base, quote);
        // NOTE: no `block.chainid == 1` or `_isMainnet` gate anywhere in
        // the body, so the detector's negative regex predicate reports
        // "not guarded" → detector fires.
        return answer;
    }
}
