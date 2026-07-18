pragma solidity ^0.8.20;

contract PendingSiloNativeAssetMintPositive {
    function depositEth(address controller) external payable {
        controller;
    }
}

contract NativeAssetMintWithoutMsgvalueEqualityCheckPositive {
    struct EpochData {
        mapping(address => uint256) depositRequest;
        uint256 totalDepositAssets;
    }

    PendingSiloNativeAssetMintPositive public pendingSilo;
    mapping(uint256 => EpochData) internal epochs;
    uint256 internal currentEpoch;
    address public wrappedNativeToken;

    constructor(PendingSiloNativeAssetMintPositive silo, address wrapped) {
        pendingSilo = silo;
        wrappedNativeToken = wrapped;
    }

    function requestDeposit(
        uint256 assets,
        address controller,
        address owner
    ) external payable returns (uint256 requestId) {
        if (msg.value > 0) {
            pendingSilo.depositEth{value: msg.value}(controller);
        }

        epochs[currentEpoch].depositRequest[controller] += assets;
        epochs[currentEpoch].totalDepositAssets += assets;
        requestId = owner == controller ? currentEpoch + 1 : currentEpoch + 2;
    }
}
