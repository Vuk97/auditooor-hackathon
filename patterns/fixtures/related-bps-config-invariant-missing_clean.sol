// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire.
///
/// Both setters cross-validate the implicit invariant
/// `fishermanRewardCut <= maxVerifierCut`. Each setter references the
/// sibling variable in a require, so governance cannot put the cuts
/// into a mis-ordered state.
contract DisputeManagerCutsClean {
    uint256 public constant MAX_PPM = 1_000_000;

    uint256 public fishermanRewardCut;
    uint256 public maxVerifierCut;

    /// CLEAN: cross-require ties this setter to the sibling cut.
    function setFishermanRewardCut(uint256 newCut) external {
        require(newCut <= MAX_PPM, "above MAX_PPM");
        require(newCut <= maxVerifierCut, "fishermanRewardCut > maxVerifierCut");
        fishermanRewardCut = newCut;
    }

    /// CLEAN: cross-require ties this setter to the sibling cut.
    function setMaxVerifierCut(uint256 newCut) external {
        require(newCut <= MAX_PPM, "above MAX_PPM");
        require(newCut >= fishermanRewardCut, "maxVerifierCut < fishermanRewardCut");
        maxVerifierCut = newCut;
    }

    /// Downstream consumer — same shape as vulnerable, but governance
    /// cannot land an invariant-violating config so the subtraction is
    /// safe.
    function slash(uint256 slashAmount, uint256 provisionTokens)
        external
        view
        returns (uint256 fishermanShare, uint256 verifierResidual)
    {
        fishermanShare = (slashAmount * fishermanRewardCut) / MAX_PPM;
        uint256 verifierBudget = (provisionTokens * maxVerifierCut) / MAX_PPM;
        verifierResidual = verifierBudget - fishermanShare;
    }
}
