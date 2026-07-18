pragma solidity ^0.8.0;

// BENIGN: pure ETH-asset path (tokenAddress==0, msg.value==amount). No
// transferFrom on any token -> the FP-guard must keep this silent.
contract Vault {
    function receiveStakeAsset(uint stake_asset_amount) internal {
        require(msg.value == stake_asset_amount, "wrong amount received");
    }
}
