"""
signature_constraint_or_fiat_shamir_forgery_fire18.py

Rust same-class recall lift for signature-forgery.

Flags verifier surfaces where a concrete cryptographic binding is absent:
  1. Anchor account fields with `#[account(...)]` but no identity constraint.
  2. Proof or circuit conservation checks using `<=` or `>=` where equality is
     required.
  3. Fiat-Shamir transcript challenges derived before any observe or absorb.
  4. Recovered signer values that are never equated with the expected signer.

The detector is deliberately not a keyword detector. It requires verification
context plus one missing equality, observe, account constraint, or signer
identity binding before reporting.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    line_col,
    snippet_of,
)


DETECTOR_ID = "rust_wave1.signature_constraint_or_fiat_shamir_forgery_fire18"

_ANCHOR_MARKER_RE = re.compile(
    r"(#\[\s*derive\s*\(\s*Accounts\s*\)\s*\]|anchor_lang::|"
    r"use\s+anchor_lang|Account\s*<\s*'info|AccountInfo\s*<)"
)

_ACCOUNT_ATTR_RE = re.compile(
    r"#\[\s*account\s*\((?P<attrs>[^)]*)\)\s*\]\s*\n\s*"
    r"(?:pub\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*"
    r"(?P<typ>[^,\n{]+)",
    re.MULTILINE,
)

_SAFE_ACCOUNT_RE = re.compile(
    r"(?i)(seeds\s*=|has_one\s*=|constraint\s*=|address\s*=|owner\s*=|"
    r"Signer\s*<|signer\b|mut\b|token::|associated_token::|bump\b|close\b)"
)

_PROOF_CONTEXT_RE = re.compile(
    r"(?i)(proof|prove|prover|verify|verifier|circuit|constraint|constrain|"
    r"synthesize|public_input|witness|r1cs|halo2|arkworks|bellperson|"
    r"bellman|plonk|groth|zk|zero_knowledge)"
)

_FLOW_TERM = (
    r"(?:sum|total|amount|balance|input|output|inflow|outflow|debit|credit|"
    r"asset|liability|distributed|distribution|withdraw|deposit|note|fund|"
    r"public_input|witness|commitment|opening)"
)

_WEAK_PROOF_BINDING_RE = re.compile(
    rf"(?P<call>\b(?:assert|debug_assert|require|ensure)!\s*\(|"
    rf"\b(?:constrain|enforce_constraint|require_constraint)\s*\()"
    rf"(?P<expr>[^;\n)]*{_FLOW_TERM}[\w\.]*\s*(?:<=|>=)\s*"
    rf"[\w\.]*{_FLOW_TERM}[^;\n)]*)",
    re.IGNORECASE,
)

_FS_CONTEXT_RE = re.compile(
    r"(?i)(fiat|shamir|transcript|challenge|recursive|proof|opening|"
    r"commitment|verifier|verify)"
)

_CHALLENGE_RE = re.compile(
    r"\.challenge\s*\(|\.squeeze\s*\(|\.get_challenge\s*\(|"
    r"derive_challenge\s*\(|transcript\.challenge|fiat_shamir::challenge"
)

_OBSERVE_RE = re.compile(
    r"\.observe\s*\(|\.absorb\s*\(|\.append\s*\(|\.update\s*\(|"
    r"transcript\.add|fiat_shamir::observe|\.push_to_transcript\s*\("
)

_RECOVER_ASSIGN_RE = re.compile(
    r"\blet\s+(?:mut\s+)?(?P<signer>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?::[^=;]+)?=\s*(?P<call>"
    r"(?:recover_signer|recover_pubkey|recover_authority|ecrecover|"
    r"secp256k1_recover|ed25519_recover)\s*\()",
    re.IGNORECASE,
)

_SIGNER_VERIFY_CONTEXT_RE = re.compile(
    r"(?i)(signature|signed|signer|recover|pubkey|authority|owner|"
    r"authorized|verify|validate|permit|account)"
)

_EXPECTED_IDENTITY_RE = re.compile(
    r"(?i)(expected_?signer|expected_?pubkey|owner|authority|"
    r"authorized_?signer|account_?owner|admin|controller|delegate)"
)


def _anchor_account_hits(source_text: str) -> list[dict]:
    hits: list[dict] = []
    if not _ANCHOR_MARKER_RE.search(source_text):
        return hits

    for match in _ACCOUNT_ATTR_RE.finditer(source_text):
        attrs = match.group("attrs")
        typ = match.group("typ")
        if _SAFE_ACCOUNT_RE.search(f"{attrs}\n{typ}"):
            continue

        line = source_text[:match.start()].count("\n") + 1
        field_name = match.group("name")
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "severity": "high",
                "line": line,
                "col": 0,
                "snippet": match.group(0)[:220].replace("\n", " "),
                "message": (
                    f"Anchor account field `{field_name}` has `#[account(...)]` "
                    "without seeds, has_one, constraint, owner, signer, or "
                    "address binding. The account identity is caller supplied."
                ),
            }
        )
    return hits


def _weak_proof_binding(name: str, body_text: str) -> str | None:
    joined = f"{name}\n{body_text}"
    if not _PROOF_CONTEXT_RE.search(joined):
        return None
    if not re.search(r"(?i)(public_input|witness|constraint|constrain|proof|circuit)", body_text):
        return None
    match = _WEAK_PROOF_BINDING_RE.search(body_text)
    if match is None:
        return None
    return match.group("expr").strip()


def _missing_fiat_shamir_observe(name: str, signature: str, body_text: str) -> bool:
    joined = f"{name}\n{signature}\n{body_text}"
    if not _FS_CONTEXT_RE.search(joined):
        return False
    challenge = _CHALLENGE_RE.search(body_text)
    if challenge is None:
        return False
    return _OBSERVE_RE.search(body_text[: challenge.start()]) is None


def _signer_binding_missing(signature: str, body_text: str) -> str | None:
    joined = f"{signature}\n{body_text}"
    if not _SIGNER_VERIFY_CONTEXT_RE.search(joined):
        return None
    if not _EXPECTED_IDENTITY_RE.search(joined):
        return None

    recover = _RECOVER_ASSIGN_RE.search(body_text)
    if recover is None:
        return None

    signer = recover.group("signer")
    escaped = re.escape(signer)
    binding_re = re.compile(
        rf"(?is)("
        rf"(?:require|assert|ensure|debug_assert)!\s*\([^;]*(?:"
        rf"\b{escaped}\b\s*==|==\s*\b{escaped}\b)"
        rf"|require_keys_eq!\s*\([^;]*\b{escaped}\b"
        rf"|assert_keys_eq!\s*\([^;]*\b{escaped}\b"
        rf"|\.contains\s*\(\s*&?\s*\b{escaped}\b\s*\)"
        rf")"
    )
    if binding_re.search(body_text):
        return None
    return signer


def _signature_text(source: bytes, fn, body) -> str:
    return source[fn.start_byte: body.start_byte].decode("utf-8", errors="replace")


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    file_text = source.decode("utf-8", errors="replace")
    hits.extend(_anchor_account_hits(file_text))

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        body = fn_body(fn)
        if body is None:
            continue

        name = fn_name(fn, source)
        signature = _signature_text(source, fn, body)
        body_nc = body_text_nocomment(body, source)
        line, col = line_col(fn)

        weak_expr = _weak_proof_binding(name, body_nc)
        if weak_expr is not None:
            hits.append(
                {
                    "detector_id": DETECTOR_ID,
                    "severity": "high",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(fn, source)[:220],
                    "message": (
                        f"Proof verifier `{name}` uses weak inequality "
                        f"`{weak_expr}` where equality is the load-bearing "
                        "constraint. A prover can satisfy the relaxed relation."
                    ),
                }
            )
            continue

        if _missing_fiat_shamir_observe(name, signature, body_nc):
            hits.append(
                {
                    "detector_id": DETECTOR_ID,
                    "severity": "high",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(fn, source)[:220],
                    "message": (
                        f"Verifier `{name}` derives a Fiat-Shamir challenge "
                        "before observing or absorbing protocol values. The "
                        "challenge is not bound to the proof transcript."
                    ),
                }
            )
            continue

        missing_signer = _signer_binding_missing(signature, body_nc)
        if missing_signer is not None:
            hits.append(
                {
                    "detector_id": DETECTOR_ID,
                    "severity": "high",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(fn, source)[:220],
                    "message": (
                        f"Signature verifier `{name}` recovers `{missing_signer}` "
                        "but never binds it to the expected signer, owner, or "
                        "authority. Any valid signature can satisfy the path."
                    ),
                }
            )

    return hits
