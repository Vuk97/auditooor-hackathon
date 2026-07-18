"""
r94_loop_zk_circuit_missing_constraint.py

Flags ZK circuit / constraint-system fns that read a value which is
eventually CONSTRAINED into the verifier's public inputs / trace
(via a `write_*`, `observe_*`, `push_commit`, `.eval(`, or similar
evaluation call) BUT never calls an `assert_*` / `constrain_*` /
`assert_bool` / `assert_eq` / `assert_range` on it first.

The class is "prover-free-write": if the prover can choose a value
without a constraint linking it to something trusted, they can forge
the proof.

Sources: Solodit #63641, #63640, #63639, #63638, #63637, #63636
(Sherlock / Brevis Pico ZKVM, Sept 2025 cohort).

Heuristic:
  1. Fn name matches /verify|eval_|recursive|circuit|constrain|commit|open/.
  2. Body takes a parameter named `prover_*`, `ro_*`, `operand_*`,
     `chip_ordering`, `quotient_*`, `log_blowup`, OR reads a field
     whose name ends in those patterns.
  3. Body uses it in an arithmetic expression, array-index, commit call,
     or eval_*.
  4. Body does NOT call any of:
     - `assert_eq!`, `assert_bool`, `assert_is_zero`, `assert_range`,
       `assert_valid_word`, `constrain(`, `.constrain_*`, `require_constraint(`.
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)


_FN_NAME_RE = re.compile(
    r"(?i)(verify|eval_|verifier|recursive|constrain|commit|open|"
    r"fiat_shamir|circuit|prover_observe)"
)

_PROVER_READ_RE = re.compile(
    r"prover_\w+|ro_\w+|operand_\w+|chip_ordering|quotient_\w+|"
    r"log_blowup|blowup|permutation_challenges|domain_size|"
    r"prover_supplied|alpha_\w+"
)

_CONSTRAINT_CALL_RE = re.compile(
    r"\bassert_eq!|assert_bool|assert_is_zero|assert_range|"
    r"assert_valid_word|\bconstrain\s*\(|\.constrain_|require_constraint|"
    r"assert!\s*\(|debug_assert!\s*\(|"
    r"assert_nonzero|assert_lt|assert_gt|assert_le|assert_ge"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)

        if not _PROVER_READ_RE.search(body_nc):
            continue
        if _CONSTRAINT_CALL_RE.search(body_nc):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` reads a prover-supplied value "
                f"(prover_*/ro_*/operand_*/chip_ordering/quotient_*/"
                f"log_blowup/domain_*) and uses it without any "
                f"`assert_*`, `constrain(`, or `require_constraint`. "
                f"Prover can forge the proof by supplying an "
                f"unconstrained value. See Solodit #63636-#63641 "
                f"(Brevis Pico ZKVM)."
            ),
        })
    return hits
