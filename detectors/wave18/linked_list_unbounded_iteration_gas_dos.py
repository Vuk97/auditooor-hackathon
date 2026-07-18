"""
linkedlist-unbounded-iteration-gas-dos — custom detector for PR #121 / Engagement-5.

Hand-written (NOT DSL-compiled) — Codex plan a2d11a06 flagged DSL-alone as too
weak for this shape, so the detector lives in wave18/ as a Python file.

Bug class
---------
Linked-list cursor traversal over a `mapping(... => Node)` storage layout where
the function walks the entire list with `while (cursor != 0) { cursor = next[...] }`
(or the equivalent `for (;cursor != 0;) {}` form) and:

  - has NO per-call iteration cap (`limit`, `maxIterations`, `pageSize`,
    `cursor` pagination parameter), AND
  - has NO `gasleft() > THRESHOLD` early-break guard, AND
  - has NO bounded array fallback (`for (uint i; i < cap; ++i)` style).

Once the list grows past the block-gas budget the function reverts and the
caller is permanently DoS'd. Classic example is `LinkedList.removeAt(...)` /
`flushQueue()` patterns over an `EnumerableSet`-style intrusive list.

Engagement-5 motivation
-----------------------
TRST-L-5 LinkedList gas-limit pattern that could resurface in DataServiceFees
or HorizonStaking thawingRequests on the Graph V3.1 codebase.

Severity / confidence
---------------------
MEDIUM / MEDIUM. The shape is structural (not data-dependent) but a real
exploit also requires (a) caller-driven list growth and (b) the function
being on a critical path. We surface candidates and let the human reviewer
confirm those two conditions.
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LinkedListUnboundedIterationGasDos(AbstractDetector):
    ARGUMENT = "linkedlist-unbounded-iteration-gas-dos"
    HELP = (
        "Function walks a storage linked-list (mapping(K => Node) with head/tail/next/prev "
        "pointers) via `while (cursor != 0)` with no iteration cap, gasleft guard, or "
        "bounded array fallback; an attacker who can grow the list permanently DoS's the "
        "function once iteration exceeds the block gas budget."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "linkedlist-unbounded-iteration-gas-dos.yaml"
    )
    WIKI_TITLE = "Linked-list cursor traversal with no iteration bound"
    WIKI_DESCRIPTION = (
        "The contract stores an intrusive linked list as `mapping(K => Node)` with `head`, "
        "`tail`, `next`, and/or `prev` pointers. A function walks the entire list using a "
        "`while (cursor != 0)` (or `while (cursor != address(0))` / `while (cursor != bytes32(0))`) "
        "loop and advances `cursor = next[cursor]` each iteration. The function exposes no "
        "`limit`, `maxIterations`, `pageSize`, or pagination cursor parameter, has no "
        "`gasleft()` early-break guard, and uses no bounded `for (i; i < cap; ++i)` fallback. "
        "Once any caller can grow the list past the block-gas-limit / iteration cost, every "
        "call to this function reverts on out-of-gas and the protocol is stuck."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A staking contract maintains `mapping(uint256 => ThawingRequest)` linked by "
        "`next[reqId]`. `flushExpiredRequests()` walks `while (cur != 0) { ... cur = next[cur]; }` "
        "with no cap. An attacker spams 100k zero-amount stake/unstake cycles to grow the list. "
        "From then on, every call to flushExpiredRequests reverts on out-of-gas, freezing all "
        "withdrawal accounting forever."
    )
    WIKI_RECOMMENDATION = (
        "Bound the loop with one of: (a) a `uint256 limit` parameter and "
        "`for (uint i; i < limit && cur != 0; ++i)`, (b) a pagination `cursor` argument so "
        "callers iterate the list in pages, (c) a `gasleft() > THRESHOLD` early-break that "
        "saves the resume cursor in storage, or (d) gate the list-growing path behind access "
        "control or a per-actor cap so the list cannot be grown unboundedly by an attacker."
    )

    # Contract-shape preconditions: must hold a linked-list storage layout. We
    # accept either a `mapping(... => Node)` declaration or `head`/`tail`/`next`
    # storage variables. This is intentionally broad — fine-grained filtering
    # happens at the function-match level.
    _PRECONDITIONS = [
        {"contract.source_matches_regex": (
            r"mapping\s*\([^)]+=>\s*\w*[Nn]ode\w*\s*\)"
            r"|\b(head|tail)\s*[;=]"
            r"|mapping\s*\([^)]+=>\s*(?:address|uint256|bytes32)\s*\)\s+(public|private|internal)?\s*next\b"
            r"|mapping\s*\([^)]+=>\s*(?:address|uint256|bytes32)\s*\)\s+(public|private|internal)?\s*prev\b"
        )},
    ]

    # Function-match conditions:
    #   1. Body contains a cursor-style `while (cursor != 0)` loop (covering
    #      address(0), bytes32(0), 0, NULL_NODE).
    #   2. Body advances the cursor via a `next[...]` / `tail[...]` / `prev[...]`
    #      mapping read inside the loop body.
    #   3. Body does NOT have a `limit`, `maxIterations`, `pageSize`,
    #      `gasleft()`, or bounded `for (... < cap; ++i)` guard.
    #   4. Skip mocks/tests/fixtures and leaf helpers.
    _MATCH = [
        {"function.kind": "external_or_public"},
        # Cursor walk: `while (X != 0)` or `while (X != address(0))` etc.
        {"function.body_contains_regex": (
            r"while\s*\(\s*\w+\s*!=\s*("
            r"address\s*\(\s*0\s*\)"
            r"|bytes32\s*\(\s*0\s*\)"
            r"|0(?:\s*\))"
            r"|NULL_NODE"
            r"|SENTINEL"
            r")"
        )},
        # Cursor advance via mapping read (rules out plain numeric counters).
        {"function.body_contains_regex": (
            r"=\s*(next|prev|nextNode|prevNode|_next|_prev)\s*\["
        )},
        # No iteration cap / pagination / gasleft early-break / bounded for-fallback.
        {"function.body_not_contains_regex": (
            r"\b(limit|maxIterations|max_iterations|maxIters|pageSize|page_size|maxLen|maxLength)\b"
            r"|gasleft\s*\(\s*\)\s*[<>]"
            r"|for\s*\(\s*uint\d*\s+\w+\s*=\s*\d+\s*;\s*\w+\s*<\s*\w+\s*;"
        )},
        {"function.not_in_skip_list": True},
        {"function.not_leaf_helper": True},
        {"function.not_source_matches_regex": r"(?i)\b(mock|test|fixture)"},
    ]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    def _detect(self):
        results = []
        for c in self.contracts:
            if is_vendored_or_test_contract(c):
                continue
            if not eval_preconditions(c, self._PRECONDITIONS):
                continue
            for f in c.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(f):
                    continue
                if not eval_function_match(f, self._MATCH):
                    continue
                info = [
                    f,
                    " — linkedlist-unbounded-iteration-gas-dos: cursor-walk `while (X != 0)` "
                    "over a linked-list mapping with no limit/maxIterations/gasleft guard or "
                    "bounded for-loop fallback. See WIKI for details.",
                ]
                results.append(self.generate_result(info))
        return results
