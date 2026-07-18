"""
signer_add_no_remove.py - Custom Slither detector.

Pattern (Zellic slice_af Mina Bridge + slice_ae InfiniCard Vault, HIGH):
a privileged registry contract exposes an `addValidator` / `addSigner` /
`addDelegatedSigner` function that writes `true` into an authorization
mapping, but there is NO corresponding remove/revoke function. Once added,
a signer is permanent. If that key is ever compromised, rotated, or
deprecated, the attacker retains the ability to act as the protocol
forever - draining approved funds, forging bridge messages, etc.

Detection strategy:
    1. For each non-vendored contract, scan all declared functions.
    2. Collect the set of functions whose lowercased name contains a
       "grant" verb ({"add", "register", "set"}) AND a "signer" noun
       ({"signer", "validator", "attestor", "oracle", "keeper",
       "delegatedsigner"}).
    3. Collect the set of functions whose name contains a "revoke" verb
       ({"remove", "revoke", "delete", "disable", "deauthoriz", "unset"})
       AND the same signer noun family.
    4. If the contract has a grant function but no revoke function for the
       same noun → flag the grant function.
    5. Require that the grant function writes to a state variable whose
       name suggests an auth mapping (signer/validator/allowlist/…) so we
       don't flag non-auth "addX" helpers.

Dedup: wave5 `revoke_no_cascade` targets revocation that clears tier-1 but
leaves tier-2 stale - a DIFFERENT pattern. This detector targets the
complete absence of any revocation path. No wave1..10 or Slither builtin
covers "add-without-remove" for auth registries.

@author auditooor wave11
@pattern slice_af Mina Bridge, slice_ae InfiniCard Vault
"""

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_GRANT_VERBS = ("add", "register", "set", "new", "grant")
_REVOKE_VERBS = ("remove", "revoke", "delete", "disable", "deauthoriz", "unset", "forbid")

_SIGNER_NOUNS = (
    "signer",
    "validator",
    "attestor",
    "attester",
    "relayer",
    "keeper",
    "operator",
    "delegate",
    "notary",
)

_AUTH_SV_HINTS = (
    "signer",
    "validator",
    "attestor",
    "attester",
    "relayer",
    "keeper",
    "operator",
    "delegate",
    "allowlist",
    "authorized",
    "isauthoriz",
    "whitelist",
    "trusted",
)


def _fn_is_grant(name: str) -> str | None:
    """Return the matched signer-noun if *name* is a grant function, else None."""
    n = name.lower()
    if not any(v in n for v in _GRANT_VERBS):
        return None
    for noun in _SIGNER_NOUNS:
        if noun in n:
            return noun
    return None


def _fn_is_revoke_for_noun(name: str, noun: str) -> bool:
    n = name.lower()
    if noun not in n:
        return False
    return any(v in n for v in _REVOKE_VERBS)


def _writes_auth_state(function) -> bool:
    for sv in function.state_variables_written:
        nm = (sv.name or "").lower()
        if any(h in nm for h in _AUTH_SV_HINTS):
            return True
    return False


class SignerAddNoRemove(AbstractDetector):
    """
    Detect validator/signer registry contracts that expose an add function
    but no corresponding remove/revoke function.
    """

    ARGUMENT = "signer-add-no-remove"
    HELP = (
        "Contract has addValidator/addSigner (or similar) but no matching "
        "remove function - compromised keys stay authorized permanently"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Validator / Signer Registry - Add Without Remove"
    WIKI_DESCRIPTION = (
        "A registry contract stores a set of trusted signers (validators, "
        "attestors, delegated signers, etc.) and exposes a privileged "
        "`addSigner` / `addValidator` / `addDelegatedSigner` entry point. "
        "There is no symmetric `removeSigner`/`revokeValidator` function. "
        "Once a key is added, it is authorized forever. A compromised, "
        "rotated, or deprecated signer key retains full signing authority "
        "and can drain any funds guarded by that signature check. Observed "
        "in Mina Token Bridge EVM (Zellic slice_af) and InfiniCard Vault "
        "(Zellic slice_ae)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Bridge {
    mapping(address => bool) public isSigner;
    function addSigner(address s) external onlyOwner { isSigner[s] = true; }
    // BUG: no removeSigner
}
```
1. Owner adds Alice as a signer; Alice is responsible for signing user withdrawals.
2. Alice's key is stolen (phishing, leaked device, insider threat).
3. Attacker signs arbitrary withdrawal messages - bridge authorizes them.
4. There is no `removeSigner` - Alice remains authorized and the only
   mitigation is redeploying the whole contract."""
    WIKI_RECOMMENDATION = (
        "Add a symmetric `removeSigner` / `revokeValidator` function gated "
        "by the same (or a more restrictive) role. Consider also a two-"
        "step rotation where adds and removes must both be called within a "
        "bounded window to prevent stale-key windows."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            # Build the set of (grant_fn, noun) pairs where grant_fn writes
            # an auth state variable.
            grants = []
            all_fn_names = [f.name or "" for f in contract.functions_and_modifiers_declared]

            for function in contract.functions_and_modifiers_declared:
                noun = _fn_is_grant(function.name or "")
                if noun is None:
                    continue
                if not _writes_auth_state(function):
                    continue
                grants.append((function, noun))

            for grant_fn, noun in grants:
                has_revoke = any(
                    _fn_is_revoke_for_noun(n, noun) for n in all_fn_names
                )
                if has_revoke:
                    continue
                info: DETECTOR_INFO = [
                    grant_fn,
                    " adds a trusted ",
                    noun,
                    " to the authorization registry but the contract has "
                    "no matching `remove`/`revoke` function for this noun. "
                    "Compromised keys stay authorized permanently - any "
                    "leaked signer retains full signing authority forever.\n",
                ]
                results.append(self.generate_result(info))

        return results
