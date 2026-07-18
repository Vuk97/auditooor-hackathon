import re
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")


def _has_arbitrary_call_enablement(func) -> bool:
    """Check if a function enables arbitrary external calls."""
    func_name = func.name.lower()
    if "proposearbitrarycall" in func_name or "arbitrary" in func_name:
        return True
    
    if "addprecioustoken" in func_name:
        return True
    
    for node in func.nodes:
        if node.underlying and hasattr(node.underlying, "expression"):
            expr = str(node.underlying.expression)
            if " preciousTokens[" in expr and "=" in expr:
                return True
    
    return False


def _has_simple_majority_threshold(func) -> bool:
    """Check if a function uses simple majority (51% or ~50%) without supermajority."""
    has_supermajority = False
    
    for node in func.nodes:
        if not hasattr(node, "expression") or node.expression is None:
            continue
        
        expr_str = str(node.expression)
        
        if re.search(r'\b(67|75|80|90|2[/]3|66\.6)\b', expr_str):
            has_supermajority = True
        
        if re.search(r'\b51\b', expr_str):
            return True
        
        if "THRESHOLD_NUMERATOR" in expr_str and "51" in expr_str:
            return True
        
        if "* 100 >=" in expr_str or "* 100 >" in expr_str:
            if "51" in expr_str:
                return True
    
    return not has_supermajority


def _has_mutable_veto(func) -> bool:
    """Check if a function can disable or remove veto power."""
    func_name = func.name.lower()
    
    if "remov" in func_name and "veto" in func_name:
        return True
    
    if "disable" in func_name and "veto" in func_name:
        return True
    
    if "set" in func_name and "veto" in func_name and "immutable" not in func_name:
        return True
    
    for node in func.nodes:
        if not hasattr(node, "expression") or node.expression is None:
            continue
        
        expr_str = str(node.expression)
        
        if "hasVetoPowerEnabled" in expr_str and ("=" in expr_str) and "true" not in expr_str.lower():
            return True
        
        if "vetoCouncil" in expr_str and "=" in expr_str and "constructor" not in func.name.lower():
            if "immutable" not in func.source_mapping.content.lower():
                return True
    
    return False


class FiftyOnePercentAttackPartyGovernance(AbstractDetector):
    """Detect 51% attack vulnerabilities in party governance contracts."""

    ARGUMENT = "51-percent-attack-party-governance"
    HELP = (
        "Party governance allows 51% majority to remove veto power and execute "
        "arbitrary calls, enabling fund theft"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/example/51-percent-attack-party-governance"
    WIKI_TITLE = "51% Attack via Mutable Veto in Party Governance"
    WIKI_DESCRIPTION = (
        "Party governance contracts that allow arbitrary external calls, use simple "
        "majority (51%) voting without supermajority requirements, and have mutable "
        "veto power that can be removed by majority vote are vulnerable to 51% attacks. "
        "A malicious actor controlling 51% of voting power can remove veto protections "
        "and execute arbitrary calls to drain treasury funds or precious tokens."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract PartyGovernanceVulnerable {
    bool public hasVetoPowerEnabled = true;
    uint256 public constant THRESHOLD_NUMERATOR = 51;
    
    function removeVetoPower() external {
        require(checkMajority(msg.sender), "Need majority");
        hasVetoPowerEnabled = false;
    }
    
    function execute(uint256 id) external {
        require(p.votes * 100 >= totalPower * 51, "Need 51%");
        (bool success,) = p.target.call(p.data);
    }
}
```
An attacker with 51% voting power calls removeVetoPower() to disable veto, 
then proposes and executes an arbitrary call to drain all treasury funds."""
    WIKI_RECOMMENDATION = (
        "Make veto power immutable or use supermajority (67%+) for all critical "
        "operations. Restrict arbitrary calls on precious tokens and use proposal "
        "type guards for treasury operations."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for func in contract.functions:
                if func.is_constructor or func.is_constructor_or_fallback:
                    continue
                if func.is_view or func.is_pure:
                    continue
                
                if not _has_arbitrary_call_enablement(func):
                    continue
                if not _has_simple_majority_threshold(func):
                    continue
                if not _has_mutable_veto(func):
                    continue

                info: DETECTOR_INFO = [
                    func,
                    " is vulnerable to 51% attack: enables arbitrary external calls, "
                    "uses simple majority threshold without supermajority, and has mutable "
                    "veto power that can be removed by majority vote.\n",
                ]
                results.append(self.generate_result(info))

        return results