pragma solidity ^0.8.20;

contract PresaleStrictlyLessBoundsMismatchWindowClean {
    error PresaleUnavailable();

    struct PresaleMeta {
        uint256 startTime;
        uint256 endTime;
    }

    mapping(address => PresaleMeta) public presalesMeta;

    function configurePresale(
        address subject,
        uint256 startTime,
        uint256 endTime
    ) external {
        presalesMeta[subject] = PresaleMeta({startTime: startTime, endTime: endTime});
    }

    function buyPresale(address subject, uint256 amount) external payable {
        if (
            presalesMeta[subject].startTime == 0 ||
            block.timestamp < presalesMeta[subject].startTime
        ) {
            revert PresaleUnavailable();
        }

        require(block.timestamp < presalesMeta[subject].endTime, "presale closed");
        require(amount > 0, "amount");
    }
}
