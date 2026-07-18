// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Vuln fixture: contract inherits ERC2771Context and uses _msgSender() in a
// state-changing function without validating msg.sender == trustedForwarder.
// The trusted forwarder is never checked before extracting the 20-byte suffix,
// allowing any caller to craft msg.data to spoof an arbitrary sender address.
// This SHOULD fire the erc-2771-msgSender-forgery detector.

interface IERC2771Context {
    function isTrustedForwarder(address forwarder) external view returns (bool);
}

abstract contract ERC2771Context is IERC2771Context {
    address private immutable _trustedForwarder;

    constructor(address trustedForwarder_) {
        _trustedForwarder = trustedForwarder_;
    }

    function isTrustedForwarder(address forwarder) public view virtual override returns (bool) {
        return forwarder == _trustedForwarder;
    }

    // Extracts the last 20 bytes of msg.data as the "real" sender when called
    // via the trusted forwarder; otherwise returns msg.sender directly.
    function _msgSender() internal view virtual returns (address sender) {
        if (isTrustedForwarder(msg.sender)) {
            // solhint-disable-next-line no-inline-assembly
            assembly {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            return msg.sender;
        }
    }
}

// Vulnerable contract: inherits ERC2771Context but does NOT guard an
// external entry-point against arbitrary callers spoofing _msgSender().
contract VulnerableToken is ERC2771Context {
    mapping(address => uint256) public balances;
    address public owner;

    constructor(address forwarder) ERC2771Context(forwarder) {
        owner = msg.sender;
    }

    // BUG: any caller who can inject 20 bytes into msg.data can spoof
    // _msgSender() here, transferring tokens from an arbitrary victim.
    function transfer(address to, uint256 amount) external {
        address from = _msgSender(); // <- forgeable when called through arbitrary path
        require(balances[from] >= amount, "insufficient balance");
        balances[from] -= amount;
        balances[to] += amount;
    }

    function mint(address to, uint256 amount) external {
        require(_msgSender() == owner, "not owner"); // <- owner spoofable
        balances[to] += amount;
    }
}
