"""
r94_loop_fiat_shamir_missing_observe.py

Flags Fiat-Shamir / transcript-based verifier fns that derive a
challenge (e.g. `alpha = transcript.challenge(...)`, `beta =
fiat_shamir.get_challenge()`) without first `observe(...)` / `absorb(...)` /
`append(...)`-ing ALL protocol-public values that the challenge should bind.

Source: Solodit #63640 (Sherlock / Brevis Pico ZKVM).
Class: fiat-shamir-missing-observation.

Heuristic:
  1. Fn name matches /verify|verifier|fiat_shamir|challenge|recursive/.
  2. Body contains a `challenge()` / `squeeze()` / `get_challenge()` call.
  3. Body does NOT contain any `observe(`, `absorb(`, `append(`,
     `transcript.add(`, `update(` call preceding the challenge.
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)


_FN_NAME_RE = re.compile(
    r"(?i)(verify|verifier|fiat_shamir|challenge|recursive)"
)

_CHALLENGE_RE = re.compile(
    r"\.challenge\s*\(|\.squeeze\s*\(|\.get_challenge\s*\(|"
    r"fiat_shamir::challenge|transcript\.challenge|derive_challenge"
)

_OBSERVE_RE = re.compile(
    r"\.observe\s*\(|\.absorb\s*\(|\.append\s*\(|\.update\s*\(|"
    r"transcript\.add|fiat_shamir::observe|\.push_to_transcript\s*\("
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

        chal_m = _CHALLENGE_RE.search(body_nc)
        if chal_m is None:
            continue
        # Must have at least one observe BEFORE the challenge call
        observe_m = _OBSERVE_RE.search(body_nc[:chal_m.start()])
        if observe_m is not None:
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` derives a Fiat-Shamir challenge "
                f"(`.challenge()` / `squeeze()` / `get_challenge()`) "
                f"without any preceding `observe()`/`absorb()`/`append()` "
                f"to bind protocol values. Challenge is vacuous — prover "
                f"forges. See Solodit #63640 (Brevis Pico ZKVM)."
            ),
        })
    return hits
