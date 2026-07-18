pragma solidity ^0.8.0;

// VULN: moves a settings/config token via safeTransferFrom but credits the
// NOMINAL amount - no measured balanceOf delta, no decimal-normalization.
contract Vault {
    struct Settings { address tokenAddress; }
    Settings settings;

    function receiveStakeAsset(uint stake_asset_amount) internal {
        if (settings.tokenAddress == address(0))
            require(msg.value == stake_asset_amount, "wrong amount received");
        else {
            require(msg.value == 0, "don't send ETH");
            IERC20(settings.tokenAddress).safeTransferFrom(msg.sender, address(this), stake_asset_amount);
        }
    }
}
