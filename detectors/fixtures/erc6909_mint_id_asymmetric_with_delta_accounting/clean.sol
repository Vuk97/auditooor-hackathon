pragma solidity ^0.8.20;

type Currency is address;

library CurrencyLibrary {
    function fromId(uint256 id) internal pure returns (Currency) {
        return Currency.wrap(address(uint160(id)));
    }

    function toId(Currency currency) internal pure returns (uint256) {
        return uint256(uint160(Currency.unwrap(currency)));
    }
}

contract Claims6909Base {
    mapping(address => mapping(uint256 => uint256)) internal balanceOf;
    mapping(address => int256) internal deltaByCurrency;

    function _accountDelta(Currency currency, int256 amount) internal {
        deltaByCurrency[Currency.unwrap(currency)] += amount;
    }

    function _mint(address to, uint256 id, uint256 amount) internal {
        balanceOf[to][id] += amount;
    }
}

contract NormalizedPoolClaimsManager is Claims6909Base {
    function mint(address to, uint256 id, uint256 amount) external {
        Currency currency = CurrencyLibrary.fromId(id);
        uint256 normalizedId = CurrencyLibrary.toId(currency);
        _accountDelta(currency, -int256(amount));
        _mint(to, normalizedId, amount);
    }
}
