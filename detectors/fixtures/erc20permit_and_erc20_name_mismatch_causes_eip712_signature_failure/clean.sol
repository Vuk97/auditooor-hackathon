// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ERC20 {
    string private _name;
    string private _symbol;

    constructor(string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
    }

    function name() external view returns (string memory) {
        return _name;
    }

    function symbol() external view returns (string memory) {
        return _symbol;
    }
}

contract ERC20Permit {
    string private _permitName;

    constructor(string memory name_) {
        _permitName = name_;
    }

    function permitDomainName() external view returns (string memory) {
        return _permitName;
    }
}

contract PermitNameAlignedToken is ERC20, ERC20Permit {
    constructor()
        ERC20("Aligned Token", "ALT")
        ERC20Permit("Aligned Token")
    {}
}
