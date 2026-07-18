import re
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_CRITICAL_KEYWORDS = (
    "mint", "burn", "pause", "upgrade", "setfee", "withdraw",
    "emergency", "transferownership",
)

_EXCLUDE_MODIFIER_KEYWORDS = ("timelock", "delayed", "governance")


class CentralizationRiskAdminPrivilege(AbstractDetector):
    """Detect critical functions protected only by onlyOwner without timelock."""

    ARGUMENT = "centralization-risk-admin-privilege"
    HELP = (
        "Centralization risk: critical functions use onlyOwner without "
        "timelock or governance delay mechanism"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/centralization-risk-admin-privilege.yaml"
    WIKI_TITLE = "Centralization Risk - Admin Privilege"
    WIKI_DESCRIPTION = (
        "Functions performing critical operations (mint, burn, pause, upgrade, "
        "setFee, withdraw, emergency) protected solely by onlyOwner modifier "
        "create centralization risk. Without a timelock or governance delay, "
        "the admin can unilaterally corrupt protocol state — draining funds, "
        "pausing all activity, or altering fee parameters instantly."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract CentralizedVault {
    address public owner;
    function setFee(uint256 newFee) external onlyOwner { fee = newFee; }
    function emergencyWithdraw() external onlyOwner { /* immediate withdrawal */ }
    function pause() external onlyOwner { paused = true; }
}
```
A malicious or compromised owner can front-run user transactions by
changing fees, drain the vault via emergencyWithdraw, or pause
the contract at a critical moment — all without any delay or
governance oversight."""
    WIKI_RECOMMENDATION = (
        "Add a timelock or governance layer for critical operations, or "
        "implement multi-sig controls on the owner account."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions:
                if function.is_constructor or function.is_fallback or function.is_receive:
                    continue
                if function.visibility not in ("external", "public"):
                    continue

                has_onlyowner = False
                for mod in function.modifiers:
                    if mod.name.lower() == "onlyowner":
                        has_onlyowner = True
                        break
                if not has_onlyowner:
                    continue

                has_excluded_modifier = False
                for mod in function.modifiers:
                    mod_name_lower = mod.name.lower()
                    if any(excl in mod_name_lower for excl in _EXCLUDE_MODIFIER_KEYWORDS):
                        has_excluded_modifier = True
                        break
                if has_excluded_modifier:
                    continue

                has_critical = any(
                    crit in function.name.lower()
                    for crit in _CRITICAL_KEYWORDS
                )

                if not has_critical:
                    for node in function.nodes:
                        if node.expression:
                            expr_str = str(node.expression).lower()
                            if any(crit in expr_str for crit in _CRITICAL_KEYWORDS):
                                has_critical = True
                                break
                if not has_critical:
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " performs critical operation with onlyOwner modifier "
                    "but has no timelock, delay, or governance protection. "
                    "The admin can unilaterally execute this action.\n",
                ]
                results.append(self.generate_result(info))

        return results