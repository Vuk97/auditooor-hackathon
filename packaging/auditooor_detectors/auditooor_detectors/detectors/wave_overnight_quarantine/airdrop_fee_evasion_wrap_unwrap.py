import re
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.utils.output import Output

_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_WRAP_UNWRAP_RE = re.compile(r"^(wrap|unwrap|wrapNFT|unwrapNFT|fractionalize|decentralize)$", re.IGNORECASE)
_SWAP_RE = re.compile(r"^(swap|exchange|trade|swapNFT|exchangeNFT)$", re.IGNORECASE)


def _is_skip_contract(contract) -> bool:
    name_lower = contract.name.lower()
    if any(kw in name_lower for kw in _SKIP_KEYWORDS):
        return True
    return False


def _has_tokenid_param(func) -> bool:
    """Check if function takes a uint256 tokenId parameter."""
    for param in func.parameters:
        if param.name and "tokenid" in param.name.lower():
            if "uint256" in str(param.type):
                return True
    return False


def _modifies_wrapped_state(func) -> bool:
    """Check if function writes to a wrapped mapping or balance tracking."""
    for node in func.nodes:
        for ir in node.irs:
            if str(ir).startswith("MEMORY_WRITE") or str(ir).startswith("STORAGE_WRITE"):
                for var in func.state_variables_written:
                    name_lower = var.name.lower()
                    if "wrapped" in name_lower or "balance" in name_lower:
                        return True
    return False


def _has_fee_validation(func) -> bool:
    """Check if function validates fees via msg.value require or fee transfer."""
    if func.is_payable:
        for node in func.nodes:
            for ir in node.irs:
                ir_str = str(ir).lower()
                if "msg.value" in ir_str:
                    return True
    for node in func.nodes:
        for ir in node.irs:
            if "transfer" in str(ir).lower() or "send" in str(ir).lower():
                return True
    return False


def _has_nonreentrant(func) -> bool:
    """Check if function uses nonReentrant modifier or similar reentrancy guard."""
    for modifier in func.modifiers:
        if "nonreentrant" in modifier.name.lower() or "reentrancyguard" in modifier.name.lower():
            return True
    return False


def _is_wrap_unwrap(func) -> bool:
    return bool(_WRAP_UNWRAP_RE.match(func.name))


def _is_swap(func) -> bool:
    return bool(_SWAP_RE.match(func.name))


class AirdropFeeEvasionWrapUnwrap(AbstractDetector):
    """Detect wrap/unwrap/swap functions that bypass fee collection enabling airdrop fee evasion."""

    ARGUMENT = "airdrop-fee-evasion-wrap-unwrap"
    HELP = "Wrap/unwrap/swap functions missing fee validation allow airdrop fee evasion"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/airdrop-fee-evasion.yaml"
    WIKI_TITLE = "Airdrop Fee Evasion via Wrap/Unwrap/Swap"
    WIKI_DESCRIPTION = (
        "Contracts that implement wrap/unwrap or swap mechanisms for NFTs must charge "
        "fees on each operation to prevent fee evasion attacks. If wrap/unwrap functions "
        "accept a tokenId parameter but do not validate msg.value fees and lack reentrancy "
        "guards, attackers can bypass fee collection while executing value-draining swaps."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract NFTFractional {
    mapping(uint256 => bool) public wrapped;
    function wrap(uint256 tokenId) external payable {
        require(!wrapped[tokenId]);
        nft.transferFrom(msg.sender, address(this), tokenId);
        wrapped[tokenId] = true;
    }
    function swap(uint256 tokenIdIn, uint256 tokenIdOut) external {
        wrapped[tokenIdIn] = false;
        wrapped[tokenIdOut] = true;
        nft.transferFrom(msg.sender, address(this), tokenIdOut);
        nft.transferFrom(address(this), msg.sender, tokenIdIn);
    }
}
```
An attacker wraps NFT-A paying the fee, then calls swap(NFT-A, NFT-B) to exchange
without paying fees. Repeating this drains protocol value as only net positions are tracked.
"""
    WIKI_RECOMMENDATION = (
        "Enforce fee validation on every wrap/unwrap/swap operation and apply "
        "nonReentrant modifiers to all state-modifying functions."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if _is_skip_contract(contract):
                continue

            for func in contract.functions:
                if not func.is_public_and_external:
                    continue

                is_target = _is_wrap_unwrap(func) or _is_swap(func)
                if not is_target:
                    continue

                if not _has_tokenid_param(func):
                    continue

                if not _modifies_wrapped_state(func):
                    continue

                has_fee = _has_fee_validation(func)
                has_guard = _has_nonreentrant(func)

                if has_fee:
                    continue

                if _is_swap(func):
                    info: DETECTOR_INFO = [
                        func,
                        " is a swap function with tokenId parameters that performs state "
                        "updates without fee validation. Attackers can exchange NFTs without "
                        "paying trading fees, draining protocol value.\n",
                    ]
                    results.append(self.generate_result(info))
                elif not has_guard:
                    info: DETECTOR_INFO = [
                        func,
                        " is a wrap/unwrap function with tokenId that modifies wrapped state "
                        "without fee validation and lacks a nonReentrant modifier. This allows "
                        "reentrancy attacks and fee evasion simultaneously.\n",
                    ]
                    results.append(self.generate_result(info))

        return results