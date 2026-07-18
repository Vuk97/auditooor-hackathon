pragma solidity ^0.8.20;

interface IERC20PendingSiloClean {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract PendingSiloSettlesPostValuationDepositsClean {
    IERC20PendingSiloClean public asset;
    address public pendingSilo;
    uint256 public valuationTimestamp;
    uint256 public currentEpoch;
    uint256 public lastRequestTimeProcessed;
    mapping(uint256 => uint256) public sharePrice;
    mapping(uint256 => uint256) public pendingAssetsAtValuation;

    constructor(IERC20PendingSiloClean asset_, address pendingSilo_) {
        asset = asset_;
        pendingSilo = pendingSilo_;
    }

    function settleDeposit() external {
        uint256 price = sharePrice[currentEpoch];
        require(price != 0, "valuation required");

        uint256 requestTime = lastRequestTimeProcessed;
        require(requestTime <= valuationTimestamp, "post-valuation deposits wait");

        uint256 assetsAtValuation = pendingAssetsAtValuation[currentEpoch];
        asset.transferFrom(pendingSilo, address(this), assetsAtValuation);
        _mintSharesForEpoch(currentEpoch, assetsAtValuation, price);
    }

    function _mintSharesForEpoch(uint256 epoch, uint256 assets, uint256 price) internal pure returns (uint256) {
        return epoch + assets + price;
    }
}
