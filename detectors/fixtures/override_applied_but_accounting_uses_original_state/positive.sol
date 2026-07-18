// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OverrideAppliedButAccountingUsesOriginalStatePositive {
    struct CampaignState {
        uint256 rate;
        uint256 spent;
        uint256 budget;
        uint256 version;
    }

    mapping(uint256 => CampaignState) internal campaigns;

    constructor() {
        campaigns[7] = CampaignState({
            rate: 1,
            spent: 10,
            budget: 1000,
            version: 1
        });
    }

    function overrideCampaignAndFinalize(
        uint256 campaignId,
        uint256 newRate,
        uint256 spend
    ) external returns (uint256 remaining) {
        CampaignState memory originalCampaign = campaigns[campaignId];

        campaigns[campaignId].rate = newRate;
        campaigns[campaignId].version = originalCampaign.version + 1;
        campaigns[campaignId].spent += spend;

        remaining =
            originalCampaign.budget -
            (originalCampaign.spent + (spend * originalCampaign.rate));
    }
}
