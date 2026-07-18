"""
go-signing-scope-raw-signature-domain-missing.py

Detects custom Go / Cosmos signature verification that verifies a signature
over locally built bytes without binding the signed scope to a chain/domain or
freshness field.

Class invariant:
  A custom signature verifier MUST bind signed bytes to a chain or protocol
  domain, plus an anti-replay freshness field such as account number, sequence,
  or nonce. Cosmos standard transaction signatures normally route through
  SignDoc / SignModeHandler sign bytes; custom application signatures need an
  equivalent domain boundary.

Seed rows used for this sibling generalizer:
  - reports/realworld_recall_slice64_batch6_complete/realworld_recall_scoreboard.md:
    signature-replay-cross-domain has 38 rows and only 60.5 percent recall.
  - audit/corpus_tags/tags/sig-extract-dydx-v4-chain...sigverify.go...yaml:
    tagged go-signature-replay; fix pattern says to bind signatures to chain,
    nonce, signer, and action-specific payload.
  - audit/corpus_tags/derived/invariants_pilot_audited.jsonl:
    INV-UNI-EX-0022 states every signature needs a unique nonce or
    chain-specific domain separator.
  - THORChain / Cosmos corpus seeds were present but noisy for this exact
    Go class: the THORChain Bifrost UTXO public-report row is Go and
    signature-replay tagged, but its source segment is report front matter,
    so it is treated as a weak seed rather than detector evidence.

This is intentionally narrow. It does not try to prove exploitability or
replace R40 proof work. It only marks places where a direct verifier consumes
custom bytes and the local body lacks obvious scope-binding vocabulary.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go-signing-scope-raw-signature-domain-missing"

_DIRECT_VERIFY_RE = re.compile(
    r"(\bed25519\.Verify\s*\("
    r"|\bsecp256k1\.VerifySignature\s*\("
    r"|\becdsa\.Verify(?:ASN1)?\s*\("
    r"|\bVerifySignature\s*\("
    r"|\bVerifySig\s*\("
    r"|\bVerifyBytes\s*\("
    r"|\b[A-Za-z0-9_]+\.VerifySignature\s*\()"
)

_SIGNING_SCOPE_FN_RE = re.compile(
    r"(?i)(verify|validate|authenticate|check).{0,24}(sig|signature|signer|auth)"
)

_LOCAL_PREIMAGE_RE = re.compile(
    r"(\[\]byte\s*\("
    r"|fmt\.Sprintf\s*\("
    r"|json\.Marshal\s*\("
    r"|proto\.Marshal\s*\("
    r"|cdc\.Marshal\s*\("
    r"|sha256\.Sum256\s*\("
    r"|tmhash\.Sum\s*\("
    r"|crypto\.Keccak256\s*\("
    r"|\bhash[A-Za-z0-9_]*\s*:=)"
)

_DOMAIN_OR_FRESHNESS_RE = re.compile(
    r"(\bSignDoc\b"
    r"|\bSignModeHandler\b"
    r"|\bGetSignBytes\b"
    r"|\bChainID\b|\bChainId\b|\bchainID\b|\bchainId\b"
    r"|\bAccountNumber\b"
    r"|\bSequence\b"
    r"|\bNonce\b|\bnonce\b"
    r"|\bDomain\b|\bdomain\b"
    r"|\bEIP712\b|\beip712\b)"
)


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

        if not _DIRECT_VERIFY_RE.search(body_text):
            continue
        if not _SIGNING_SCOPE_FN_RE.search(name):
            continue
        if not _LOCAL_PREIMAGE_RE.search(body_text):
            continue
        if _DOMAIN_OR_FRESHNESS_RE.search(body_text):
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": engine.text(fn).splitlines()[0][:160],
            "message": (
                f"`{name}` directly verifies a signature over locally built "
                f"bytes, but the function body has no SignDoc, ChainID, "
                f"AccountNumber, Sequence, nonce, or domain binding marker. "
                f"Custom Cosmos signatures should bind chain/domain and "
                f"freshness before accepting the signature. "
                f"(class: signature-replay-cross-domain)"
            ),
        })
    return hits
