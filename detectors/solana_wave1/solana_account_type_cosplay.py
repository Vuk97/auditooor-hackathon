"""
solana_account_type_cosplay.py

Detects Solana account "type cosplay" (account confusion): deserializing
an account into a typed struct without a discriminator / account-type tag
check, so an account of a DIFFERENT type with a compatible byte layout
can be substituted.

Two account types in the same program (e.g. `UserState` and `AdminState`)
can have identical or prefix-compatible serialized layouts. If a handler
unpacks raw bytes via `try_from_slice` / `unpack` / `deserialize` with no
leading discriminator check, an attacker passes a `UserState` account
where an `AdminState` is expected (or vice-versa) and bypasses the type
invariant entirely.

Anchor's `Account<'info, T>` writes and verifies an 8-byte discriminator
automatically. Native programs (and Anchor `AccountLoader` / zero-copy)
must tag and check a type byte themselves.

Bug class: HIGH (privilege/type confusion via account substitution).
Platform:  Solana native programs + Anchor zero-copy / AccountLoader.
Empirical anchor: OtterSec / sealevel-attacks "type cosplay" canonical class.

Algorithm:
1. Iterate fns.
2. Flag when the body deserializes into a named struct
   (`try_from_slice`, `unpack`, `T::deserialize`) and there is no
   discriminator / account-type-tag check (`discriminator`,
   `account_type`, `ACCOUNT_DISCRIMINATOR`, `state.tag`,
   `require!(...tag...)`).
"""

from __future__ import annotations

import re

DETECTOR_ID = "solana_wave1.solana_account_type_cosplay"

_DESERIALIZE_RE = re.compile(
    r"\b([A-Z]\w+\s*::\s*(try_from_slice|deserialize|unpack(_unchecked)?)"
    r"|try_from_slice\s*\(|unpack(_unchecked)?\s*\()"
)

_DISCRIMINATOR_RE = re.compile(
    r"(discriminator|"
    r"\baccount_type\b|"
    r"ACCOUNT_DISCRIMINATOR|"
    r"\bDISCRIMINATOR\b|"
    r"\.\s*tag\b|"
    r"\bAccountType\b|"
    r"\brequire\w*\s*!\s*\([^)]*(tag|type|discrim))",
    re.IGNORECASE,
)

_TEST_NAME_RE = re.compile(r"^(test_|.*_test$)")


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?" or _TEST_NAME_RE.match(name):
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue
        fn_text = engine.text(fn)
        body_text = engine.text(body)

        # Anchor `Account<'info, T>` self-verifies discriminator -> skip
        # only when the fn does not also do raw deserialization.
        m = _DESERIALIZE_RE.search(body_text)
        if m is None:
            continue
        if _DISCRIMINATOR_RE.search(fn_text):
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": fn_text.splitlines()[0][:160],
            "message": (
                f"Solana handler `{name}` deserializes an account into a "
                f"typed struct with no discriminator / account-type-tag "
                f"check. An account of a different type with a compatible "
                f"layout can be substituted (type cosplay). "
                f"(class: account-type-cosplay)"),
        })
    return hits
