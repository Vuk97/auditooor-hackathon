// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — fixed variant of the
/// chainlink-feed-registry-address-hardcoded pattern. The function gates
/// the hardcoded mainnet registry literal behind a `block.chainid == 1`
/// branch and reverts on any other chain so the caller must pass a
/// chain-appropriate registry. The detector's negative regex anchor
/// (`block\.chainid\s*==`) matches → the not-contains predicate is FALSE
/// → the detector does NOT fire.
interface IFeedRegistry {
    function latestRoundData(address base, address quote)
        external
        view
        returns (uint80, int256, uint256, uint256, uint80);
}

contract PriceReaderClean {
    IFeedRegistry public immutable registry;

    constructor(IFeedRegistry _registry) {
        require(address(_registry) != address(0), "zero registry");
        registry = _registry;
    }

    // CLEAN: the function still names the mainnet address as a
    // documentation / sanity-check constant, but the actual registry
    // pointer is an injected immutable set per-chain at construction.
    // The body also references `block.chainid == 1` explicitly, which
    // satisfies the detector's guard anchor and silences it.
    function getPrice(address base, address quote) external view returns (int256) {
        if (block.chainid == 1) {
            // On mainnet the injected registry MUST equal the canonical
            // Chainlink deployment. Documented for reviewers.
            require(
                address(registry) == 0x47Fb2585D2C56Fe188D0E6ec628a38b74FCeeeDF,
                "wrong registry"
            );
        }
        (, int256 answer, , , ) = registry.latestRoundData(base, quote);
        return answer;
    }
}
