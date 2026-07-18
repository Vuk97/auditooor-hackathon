"""
forwarder_nonce_on_revert.py — Hand-written CFG-based Slither detector.

ARG: forwarder-nonce-on-revert
SEVERITY: HIGH
CONFIDENCE: MEDIUM

Pattern: ERC-2771 / EIP-712 trusted-forwarder / meta-transaction relay where the
caller's `nonce` is incremented ONLY on the success branch of the inner external
call (i.e. `nonces[signer]++` is positioned AFTER the external `.call(...)` and
typically after a `require(success)` guard). Because a failed inner call short-
circuits the function (via the require) and bypasses the nonce write, a relayer
can submit the same signed payload repeatedly — every revert leaves the nonce
unchanged, enabling unbounded replay.

Correct shape: increment the nonce BEFORE the inner call (atomic claim — even
if the inner call reverts, the require unwinds the increment together with the
call's state changes), or use OZ's `_useNonce` / `_useCheckedNonce` /
`_useUnorderedNonce` helpers that consume the nonce slot before any external
interaction.

═══════════════════════════════════════════════════════════════════════════
Why hand-written, not pure DSL
═══════════════════════════════════════════════════════════════════════════

The existing DSL `forwarder-nonce-increment-on-revert.yaml` matches the inverse
shape (increment-before-call without `require(success)` afterwards = nonce burn
on revert / DoS). That predicate cannot easily express "nonce-write node index
is GREATER than external-call node index AND a require(success) sits between
them" — which is the precise replay-vector shape codified here.

Walking the CFG node list in order and comparing positional indices of the
external-call node vs. the nonce-write node is straightforward in Slither IR
but awkward to express as a body_contains_regex predicate. Codex sign-off:
14:42Z permits hand-written for `forwarder-nonce-on-revert` because revert-
branch ordering analysis is structurally beyond the DSL engine.

═══════════════════════════════════════════════════════════════════════════
Detection logic
═══════════════════════════════════════════════════════════════════════════

1. Iterate `contract.functions_and_modifiers_declared`. Skip vendored/test.
2. Function-shape match — must satisfy ALL of:
   a. Name matches `^(execute|executeBatch|relay|relayMeta|forward|exec|
      executeMetaTransaction|executeWithSignature)$` (case-insensitive).
   b. Either the contract has a state mapping named `nonces|_nonces` OR one of
      the function's parameters is a struct/tuple containing a `nonce` field
      (forwarder shape).
3. Walk `function.nodes` in CFG order. Record:
     - first_ext_idx — index of the first node whose IR contains a
       LowLevelCall or HighLevelCall (the "inner call").
     - nonce_write_idx — index of the first node that writes to a state
       variable whose name matches `^_?nonces?$` (single-word mapping).
4. Whitelist short-circuit: if any node calls a Solidity function or internal
   function whose name is in {`_useNonce`, `_useCheckedNonce`,
   `_useUnorderedNonce`} → skip (atomic OZ claim).
5. Flag iff `first_ext_idx is not None` AND `nonce_write_idx is not None` AND
   `nonce_write_idx > first_ext_idx`. The nonce-increment is on the success-
   only branch of the inner call.

False-positive guards:
- Nonce-write that is itself the external-call's lvalue (rare; we filter on
  state_variables_written so this never matches).
- Functions that use `_useNonce`-style helpers (skipped per step 4).
- Vendored/mock/test contracts (skipped via is_vendored_or_test_contract).

False-negative awareness:
- If the nonce-increment lives in a private helper called AFTER the external
  call, this CFG walk does NOT recurse. Documented; intra-procedural only.
- Functions using assembly for the nonce write (rare in forwarders) won't show
  up as state_variables_written.

Source seed: reference/solodit_corpus_gaps.json wave_8_candidates_top_tier
entry "forwarder-nonce-increment-on-revert" (slice aa, tier ★★★, severity HIGH,
EIP-2771 meta-tx forwarder family). The replay-vector framing is documented in
reference/corpus_mined/NOVELS_UNPORTED.md row 7.

@author auditooor
@pattern wave18 forwarder-nonce-on-revert
"""

import re
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations import (
    HighLevelCall,
    LowLevelCall,
    InternalCall,
    SolidityCall,
    LibraryCall,
)
from slither.utils.output import Output


# Forwarder-shape entry-point names (case-insensitive).
_FN_NAME_REGEX = re.compile(
    r"^(execute|executebatch|relay|relaymeta|forward|exec|"
    r"executemetatransaction|executewithsignature)$",
    re.IGNORECASE,
)

# Mapping name shape that tracks per-signer nonces.
_NONCE_VAR_REGEX = re.compile(r"^_?nonces?$", re.IGNORECASE)

# OZ atomic-claim helpers that consume the nonce before the inner call. If any
# of these is invoked anywhere in the function body the detector skips —
# nonce ordering is correct by construction.
_OZ_NONCE_HELPERS = {
    "_useNonce",
    "_useCheckedNonce",
    "_useUnorderedNonce",
    "useNonce",
    "useCheckedNonce",
    "useUnorderedNonce",
}


def _has_nonce_state_var(contract) -> bool:
    """True iff contract declares a state variable matching `nonces|_nonces`."""
    try:
        for sv in getattr(contract, "state_variables", []) or []:
            if _NONCE_VAR_REGEX.search(sv.name or ""):
                return True
    except Exception:
        pass
    return False


def _function_has_nonce_struct_param(function) -> bool:
    """Heuristic: any parameter whose source signature mentions `nonce` field."""
    try:
        for p in getattr(function, "parameters", []) or []:
            t = getattr(p, "type", None)
            if t is None:
                continue
            t_str = str(t)
            # Struct types are referenced by qualified name (`Forwarder.ForwardRequest`)
            # in Slither's type rendering. Inspect the underlying user-defined type if available.
            if "ForwardRequest" in t_str or "MetaTransaction" in t_str or "ForwardCall" in t_str:
                return True
            # Walk struct members if Slither resolves the struct.
            udt = getattr(t, "type", None)
            members = getattr(udt, "elems", None) if udt is not None else None
            if members:
                try:
                    for name in members:
                        if "nonce" in str(name).lower():
                            return True
                except Exception:
                    pass
    except Exception:
        pass
    return False


def _node_has_external_call(node) -> bool:
    """True iff the node's IR contains a LowLevelCall or HighLevelCall."""
    try:
        for ir in node.irs:
            if isinstance(ir, (LowLevelCall, HighLevelCall)):
                # Skip library calls — they don't represent untrusted external
                # interactions (LibraryCall subclasses HighLevelCall in Slither
                # but solidity-internal-by-design).
                if isinstance(ir, LibraryCall):
                    continue
                return True
    except Exception:
        pass
    return False


def _node_writes_nonce_state(node) -> bool:
    """True iff the node writes a state variable matching the nonce regex."""
    try:
        for sv in getattr(node, "state_variables_written", []) or []:
            if _NONCE_VAR_REGEX.search(sv.name or ""):
                return True
    except Exception:
        pass
    return False


def _function_uses_oz_nonce_helper(function) -> bool:
    """True iff any IR in any node calls one of the OZ atomic-claim helpers."""
    try:
        for node in getattr(function, "nodes", []) or []:
            for ir in node.irs:
                if isinstance(ir, (InternalCall, HighLevelCall, SolidityCall, LibraryCall)):
                    callee = getattr(ir, "function", None)
                    name = getattr(callee, "name", "") or ""
                    if name in _OZ_NONCE_HELPERS:
                        return True
    except Exception:
        pass
    return False


def _scan_function(function):
    """
    Return a (first_ext_idx, first_nonce_write_idx, ext_node, nonce_node) tuple
    or None when the function does not meet the structural prerequisites.
    """
    nodes = list(getattr(function, "nodes", []) or [])
    if not nodes:
        return None

    first_ext_idx = None
    first_ext_node = None
    nonce_write_idx = None
    nonce_write_node = None

    for i, node in enumerate(nodes):
        if first_ext_idx is None and _node_has_external_call(node):
            first_ext_idx = i
            first_ext_node = node
        if nonce_write_idx is None and _node_writes_nonce_state(node):
            nonce_write_idx = i
            nonce_write_node = node

    return (first_ext_idx, nonce_write_idx, first_ext_node, nonce_write_node)


class ForwarderNonceOnRevert(AbstractDetector):
    """
    Detect forwarder/meta-tx execute() functions where the per-signer nonce is
    incremented on the success-only branch of the inner external call,
    enabling replay of any signed payload that intentionally reverts.
    """

    ARGUMENT = "forwarder-nonce-on-revert"
    HELP = (
        "Forwarder execute() increments the user nonce AFTER the inner external "
        "call (success-only branch), so a relayer can replay any signed payload "
        "that reverts."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "forwarder-nonce-on-revert.yaml"
    )
    WIKI_TITLE = (
        "ERC-2771 forwarder skips nonce-increment on revert: signed payload replayable"
    )
    WIKI_DESCRIPTION = (
        "Trusted-forwarder / meta-transaction `execute()` functions that increment "
        "the per-signer nonce only AFTER the inner external call (e.g. inside an "
        "`if (success)` branch or after `require(success)`) leave the nonce slot "
        "unchanged whenever the inner call reverts. A malicious relayer can submit "
        "the same signed payload repeatedly, intentionally forcing reverts (out-of-"
        "gas, unsupported target, etc.) and re-using the signature indefinitely."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function execute(ForwardRequest calldata req, bytes calldata sig) external {
    address signer = _recover(req, sig);
    require(nonces[signer] == req.nonce, "bad nonce");
    (bool success, ) = req.to.call(req.data);
    require(success, "inner call failed");   // <-- short-circuits on revert
    nonces[signer]++;                         // <-- never reached on revert
}
```
Mallory submits Alice's signed `ForwardRequest` against a target that always
reverts (e.g. an under-funded transfer). The `require(success)` reverts the
whole transaction, the nonce stays at `req.nonce`, and Mallory can resubmit
the exact same signature, forever.
"""
    WIKI_RECOMMENDATION = (
        "Increment the nonce BEFORE the inner external call so a revert atomically "
        "unwinds both the call and the nonce write — or use OpenZeppelin's "
        "`_useNonce` / `_useCheckedNonce` / `_useUnorderedNonce` helpers, which "
        "consume the nonce slot before any external interaction."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            contract_has_nonces = _has_nonce_state_var(contract)

            for function in contract.functions_and_modifiers_declared:
                if is_leaf_helper(function):
                    continue
                if not _FN_NAME_REGEX.search(function.name or ""):
                    continue

                # Structural prerequisite: forwarder shape — either the
                # contract carries a per-signer nonce mapping OR the function
                # parameter shape is a forwarder struct with a `nonce` field.
                if not (contract_has_nonces or _function_has_nonce_struct_param(function)):
                    continue

                # Whitelist atomic OZ claim helpers.
                if _function_uses_oz_nonce_helper(function):
                    continue

                scan = _scan_function(function)
                if scan is None:
                    continue
                first_ext_idx, nonce_write_idx, ext_node, nonce_node = scan

                if first_ext_idx is None or nonce_write_idx is None:
                    continue
                if nonce_write_idx <= first_ext_idx:
                    # nonce written BEFORE / AT the call — atomic-claim ordering.
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " — forwarder-nonce-on-revert: inner external call at ",
                    ext_node,
                    " precedes the per-signer nonce-increment at ",
                    nonce_node,
                    ". A revert in the inner call short-circuits the function "
                    "before the nonce is consumed, so the same signed payload is "
                    "infinitely replayable. Move the nonce increment BEFORE the "
                    "external call, or use `_useNonce` / `_useCheckedNonce`.\n",
                ]
                results.append(self.generate_result(info))

        return results
