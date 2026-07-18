"""
solana_missing_signer_check.py

Detects Solana/Anchor instruction handlers that act on an `authority` /
`admin` / `owner` account without ever proving that account signed the
transaction.

On Solana the runtime does NOT enforce that an account passed into an
instruction is a signer. The program must check it explicitly. Anchor
expresses the check declaratively (`Signer<'info>` type, or a
`#[account(signer)]` / `constraint = x.is_signer` attribute); native
programs check `account.is_signer` directly. When a handler treats an
account as a privileged actor (authority/admin/owner/payer) but never
asserts `is_signer` on it, ANY account can be supplied and the privileged
action runs permissionlessly.

Bug class: HIGH (permissionless privileged action via unsigned authority).
Platform:  Solana native programs + Anchor framework.
Empirical anchor: OtterSec / Neodyme "missing signer check" canonical class;
                  Wormhole 2022-class signer-omission family.
Cross-lang sibling: go_wave1.cosmos_msgserver_missing_authority_check.

Algorithm (engine functions() + body regex):
1. Iterate every Rust fn.
2. Keep handlers whose body references a privileged account
   (`authority`, `admin`, `owner`, `payer`, `signer`-named binding) AND
   performs a privileged effect (state write / lamport move / mint / close).
3. Safe if the body proves a signer relationship: `.is_signer`,
   `Signer<`, `#[account(... signer`, `require!(...is_signer...)`,
   `assert_signer`, or an Anchor `has_one` against a signer field.
4. Otherwise -> flag.
"""

from __future__ import annotations

import re

DETECTOR_ID = "solana_wave1.solana_missing_signer_check"

# Handler touches a privileged-actor account.
_PRIV_ACTOR_RE = re.compile(
    r"\b(authority|admin|owner|payer|governor|manager|operator)\b",
    re.IGNORECASE,
)

# Handler performs a privileged effect.
_PRIV_EFFECT_RE = re.compile(
    r"(\.\s*lamports\s*\(\s*\)|"          # lamport access / move
    r"try_borrow_mut_lamports|"
    r"\bmint_to\b|\bburn\b|"
    r"\btransfer\b|"
    r"\.\s*data\s*\.\s*borrow_mut|"
    r"\bset_authority\b|"
    r"\.\s*\w+\s*=\s*)"                   # plain field assignment
)

# Proof the privileged account is a signer -> safe.
_SIGNER_PROOF_RE = re.compile(
    r"(\.\s*is_signer\b|"
    r"\bSigner\s*<|"
    r"#\[\s*account\s*\([^)]*signer|"
    r"\bassert_signer\s*\(|"
    r"\brequire\w*\s*!\s*\([^)]*is_signer|"
    r"\bhas_one\b)"
)

# Skip obvious test code.
_TEST_NAME_RE = re.compile(r"^(test_|.*_test$)")


def _looks_like_handler(name: str, body_text: str) -> bool:
    if _TEST_NAME_RE.match(name or ""):
        return False
    if not _PRIV_ACTOR_RE.search(body_text):
        return False
    if not _PRIV_EFFECT_RE.search(body_text):
        return False
    return True


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue
        body_text = engine.text(body)
        fn_text = engine.text(fn)

        if not _looks_like_handler(name, body_text):
            continue
        # The signer proof may appear in the fn signature (Anchor Signer<>)
        # or the struct attribute region, so scan the whole fn text.
        if _SIGNER_PROOF_RE.search(fn_text):
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": fn_text.splitlines()[0][:160],
            "message": (
                f"Solana handler `{name}` treats a privileged account "
                f"(authority/admin/owner/payer) as the actor but never "
                f"proves it signed the tx (no `.is_signer` / `Signer<>` / "
                f"`#[account(signer)]`). Any account can be supplied and "
                f"the privileged action runs permissionlessly. "
                f"(class: missing-signer-check)"),
        })
    return hits
