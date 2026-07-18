// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — detector MUST fire on at least one setter.
///
/// Mirrors OZ-2025 The Graph DisputeManager (fishermanRewardCut vs
/// maxVerifierCut). Two related cut variables, independent setters,
/// neither cross-validates the implicit invariant
/// `fishermanRewardCut <= maxVerifierCut`. The downstream slash() path
/// uses both cuts in arithmetic; mis-ordering causes underflow / DoS.
contract DisputeManagerCutsVulnerable {
    uint256 public constant MAX_PPM = 1_000_000;

    uint256 public fishermanRewardCut; // bps in PPM
    uint256 public maxVerifierCut;     // bps in PPM

    /// VULN: bounds-only check, no cross-require against maxVerifierCut.
    /// Detector must flag this setter.
    function setFishermanRewardCut(uint256 newCut) external {
        require(newCut <= MAX_PPM, "above MAX_PPM");
        fishermanRewardCut = newCut;
    }

    /// VULN: bounds-only check, no cross-require against fishermanRewardCut.
    /// Detector must flag this setter.
    function setMaxVerifierCut(uint256 newCut) external {
        require(newCut <= MAX_PPM, "above MAX_PPM");
        maxVerifierCut = newCut;
    }

    /// Downstream consumer: combines both cuts in arithmetic. This is
    /// where the implicit invariant matters — if fisherman > verifier,
    /// the subtraction underflows.
    function slash(uint256 slashAmount, uint256 provisionTokens)
        external
        view
        returns (uint256 fishermanShare, uint256 verifierResidual)
    {
        fishermanShare = (slashAmount * fishermanRewardCut) / MAX_PPM;
        uint256 verifierBudget = (provisionTokens * maxVerifierCut) / MAX_PPM;
        verifierResidual = verifierBudget - fishermanShare; // underflow when invariant violated
    }
}
