pragma solidity ^0.8.20;

contract R94ReversePairedFunctionStateWriteAsymmetryClean {
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
        uint256 storedIndex = operatorIndexPlusOne[operator];
        operatorRole[operator] = false;

        if (storedIndex != 0) {
            uint256 index = storedIndex - 1;
            uint256 lastIndex = operatorList.length - 1;
            if (index != lastIndex) {
                address moved = operatorList[lastIndex];
                operatorList[index] = moved;
                operatorIndexPlusOne[moved] = storedIndex;
            }
            operatorList.pop();
            delete operatorIndexPlusOne[operator];
        }
    }
}
