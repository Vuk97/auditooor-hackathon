// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Clean variant: every weight-indexing function asserts either
// `i < weights.length` (or `i < tokens.length`) or
// `weights.length == tokens.length`. The negated regex matches and
// suppresses the detector.
contract WeightCalcIndexMismatchClean {
    address[] public tokens;
    uint256[] public weights;
    uint256[] public normalizedWeights;

    function addToken(address t, uint256 w) external {
        tokens.push(t);
        weights.push(w);
    }

    function removeToken(uint256 i) external {
        require(i < tokens.length, "oob");
        tokens[i] = tokens[tokens.length - 1];
        weights[i] = weights[weights.length - 1];
        tokens.pop();
        weights.pop();
    }

    // CLEAN: bounds-checked via `i < weights.length`.
    function updateWeights(uint256 i, uint256 newW) external {
        require(i < weights.length, "oob");
        weights[i] = newW;
    }

    // CLEAN: asserts length equality up front.
    function getNormalizedWeights() external view returns (uint256[] memory) {
        require(weights.length == tokens.length, "mismatch");
        uint256[] memory out = new uint256[](weights.length);
        for (uint256 i = 0; i < weights.length; i++) {
            out[i] = weights[i];
        }
        return out;
    }

    // CLEAN variant: `i < tokens.length` bound.
    function _setWeight(uint256 i, uint256 w) external {
        require(i < tokens.length, "oob");
        weights[i] = w;
    }

    // CLEAN variant: length-equality check.
    function rebalanceWeights(uint256 i, uint256 w) external {
        require(weights.length == tokens.length, "mismatch");
        normalizedWeights[i] = w;
    }

    // CLEAN variant: bounds check on i.
    function calculateWeight(uint256 i) external view returns (uint256) {
        require(i < weights.length, "oob");
        return weights[i];
    }
}
