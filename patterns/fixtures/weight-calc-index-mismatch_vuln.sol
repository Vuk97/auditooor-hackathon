// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal weighted-pool that reads/writes weights[i] without asserting
// weights.length == tokens.length or i < weights.length. This is the
// C0083 bug shape — `updateWeights`, `getNormalizedWeights`, and
// `_setWeight` each drift silently when tokens and weights diverge.
contract WeightCalcIndexMismatchVuln {
    address[] public tokens;
    uint256[] public weights;
    uint256[] public normalizedWeights;

    function addToken(address t, uint256 w) external {
        tokens.push(t);
        weights.push(w);
    }

    // VULN: removes from tokens without touching weights. Every
    // subsequent index load is off.
    function removeToken(uint256 i) external {
        tokens[i] = tokens[tokens.length - 1];
        tokens.pop();
    }

    // VULN: no bounds check, no length-equality check.
    function updateWeights(uint256 i, uint256 newW) external {
        weights[i] = newW;
    }

    // VULN: reads weights[i] in a loop bounded by weights.length only.
    function getNormalizedWeights() external view returns (uint256[] memory) {
        uint256[] memory out = new uint256[](weights.length);
        for (uint256 i = 0; i < weights.length; i++) {
            out[i] = weights[i];
        }
        return out;
    }

    // VULN variant: _setWeight — same shape.
    function _setWeight(uint256 i, uint256 w) external {
        weights[i] = w;
    }

    // VULN variant: rebalanceWeights — indexes normalizedWeights without check.
    function rebalanceWeights(uint256 i, uint256 w) external {
        normalizedWeights[i] = w;
    }

    // VULN variant: calculateWeight — reads _weights[i].
    function calculateWeight(uint256 i) external view returns (uint256) {
        return weights[i];
    }
}
