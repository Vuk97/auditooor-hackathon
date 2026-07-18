pragma solidity ^0.8.0;

// CLEAN control: same config-token transfer, but the invariant IS enumerated -
// measured balanceOf delta AND decimal-normalization. Must NOT fire.
contract Vault {
    struct Settings { address tokenAddress; }
    Settings settings;

    function receiveStakeAsset(uint stake_asset_amount) internal {
        require(msg.value == 0, "don't send ETH");
        uint balBefore = IERC20(settings.tokenAddress).balanceOf(address(this));
        uint scale = 10 ** IERC20Metadata(settings.tokenAddress).decimals();
        IERC20(settings.tokenAddress).safeTransferFrom(msg.sender, address(this), stake_asset_amount);
        uint received = IERC20(settings.tokenAddress).balanceOf(address(this)) - balBefore;
        require(received >= stake_asset_amount / scale, "fot desync");
    }
}
