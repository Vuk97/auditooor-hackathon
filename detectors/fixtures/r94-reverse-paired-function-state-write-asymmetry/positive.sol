pragma solidity ^0.8.20;

contract R94ReversePairedFunctionStateWriteAsymmetryPositive {
    mapping(address => bool) public operatorRole;
    mapping(address => uint256) public operatorIndexPlusOne;
    address[] public operatorList;

    function addOperator(address operator) external {
        require(!operatorRole[operator], "already added");
        operatorRole[operator] = true;
        operatorIndexPlusOne[operator] = operatorList.length + 1;
        operatorList.push(operator);
    }

    function removeOperator(address operator) external {
        require(operatorRole[operator], "missing");
        operatorRole[operator] = false;
    }
}
