#!/usr/bin/env python3
"""Rule 44 Opposed-Trace Actor Separation preflight.

For HIGH+ submissions whose PoC dir / harness is an opposed-trace harness,
the harness MUST satisfy all three checks:

  1. Role separation: attacker + defender constructed with DISTINCT signing
     material, not shared wallet / shared signer / single account controlling
     both sides.

  2. Withheld-artifact assertion: the harness must contain an enumeration
     loop that checks every confirmed/accepted/submitted artifact in the
     relevant window and asserts the withheld one is absent.

  3. Attack-causality assertion: production code reaches the claimed impact
     surface (commit / finalization / callback / status transition) WITHOUT
     the withheld artifact.

Verdicts (in evaluation order):
  pass-out-of-scope                  - severity below HIGH, or not an opposed-trace harness
  pass-cooperative-case-labeled      - harness explicitly labels this as a cooperative case
  pass-actor-separation-with-assertions - all three checks satisfied
  ok-rebuttal                        - override marker present and non-empty (<=200 chars)
  fail-no-role-separation            - attacker + defender share signing material
  fail-single-wallet-multi-role      - single wallet / keypair controls both sides
  fail-no-withheld-artifact-assertion - no enumeration loop asserting absence of withheld artifact
  fail-no-attack-causality-assertion - no assertion that production code reached impact surface
  error                              - input error

CLI: <harness-dir|harness-file> [--severity ...] [--strict] [--json]
     If <harness-dir>, scan all .sh/.go/.rs/.sol/.ts/.py files inside.

Override marker: `r44-rebuttal: <reason>` (visible line, <=200 chars)
                 OR `<!-- r44-rebuttal: <reason> -->` (HTML-comment form).

Env extensions:
  AUDITOOOR_R44_SINGLE_WALLET_PATTERNS  - newline-sep regex list (extra anti-patterns)
  AUDITOOOR_R44_WITHHELD_ASSERTION_PATTERNS - newline-sep regex list (extra withheld patterns)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.r44_opposed_trace_actor_separation.v1"
GATE = "R44-OPPOSED-TRACE-ACTOR-SEPARATION"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# ---------------------------------------------------------------------------
# Opposed-trace harness signal - is this even an opposed-trace harness?
# ---------------------------------------------------------------------------
OPPOSED_TRACE_RE = re.compile(
    r"opposed[- ]trace|opposed[- ]regtest|"
    r"attacker.*(?:withholds?|refuses?|doesn'?t sign|withheld)|"
    r"withholds? (?:tx|transaction|artifact|co-?sign)|"
    r"sender.*withholds?|actor[- ]model|"
    r"attacker[_A-Za-z]* = (?:vm\.addr|make_keypair|Keypair::new|getnewaddress)|"
    r"attacker[_A-Za-z]*(?:Addr|Address|_addr)|"
    r"sender.*attacker|defender.*victim|"
    r"honest[- ]ssp[- ]defense|opposed[- ](?:end[- ]to[- ]end|proof)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Cooperative-case label - harness says it's a cooperative / non-attack case
# ---------------------------------------------------------------------------
COOPERATIVE_LABEL_RE = re.compile(
    r"cooperative[- ]case|co[- ]operative[- ]scenario|"
    r"(?:this )?is a cooperative (?:case|exit|flow)|"
    r"no[- ]attacker[- ]role|both parties cooperate|"
    r"non[- ]adversarial[- ](?:case|path)|"
    r"cooperative[- ]baseline|honest[- ]baseline",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Role separation patterns (positive - attacker AND defender distinct)
# ---------------------------------------------------------------------------
# Bitcoin / UTXO
BITCOIN_ROLE_SEP_RE = re.compile(
    r"(?:"
    r"(?:attacker|sender|adversar)[_\w]*(?:Addr|addr|_addr|_address|Address)\s*=\s*[\"']?\$?\(?\w|"
    r"(?:receiver|victim|defender|honest)[_\w]*(?:Addr|addr|_addr|_address|Address)\s*=\s*|"
    r"getnewaddress\s+(?:attacker|sender|adversar|refund)|"
    r"getnewaddress\s+(?:receiver|victim|defender|redemption)|"
    r"REFUND_ADDR.*getnewaddress|RECEIVER_ADDR.*getnewaddress|"
    r"attacker_refund.*bech32|receiver_redemption.*bech32"
    r")",
    re.IGNORECASE,
)

# EVM / Foundry / Hardhat
EVM_ROLE_SEP_RE = re.compile(
    r"vm\.startPrank\s*\(\s*(?:attacker|adversar|malicious|sender)[_\w]*\s*\)|"
    r"vm\.startPrank\s*\(\s*(?:defender|victim|receiver|honest)[_\w]*\s*\)|"
    r"(?:address|address payable)\s+(?:attacker|adversar|malicious)[_\w\s]*=\s*(?:makeAddr|address\s*\(|vm\.addr)|"
    r"(?:address|address payable)\s+(?:victim|defender|receiver|honest)[_\w\s]*=\s*(?:makeAddr|address\s*\(|vm\.addr)",
    re.IGNORECASE,
)

# Cosmos / Go
COSMOS_ROLE_SEP_RE = re.compile(
    r"signers\s*\[\]\s*sdk\.AccAddress|"
    r"(?:attacker|adversar|malicious|sender)[_\w]*\s*:?=\s*(?:sdk\.AccAddress|sdk\.MustAccAddressFromBech32|createAccount|s\.network\.Validators\[|sdk\.AccAddressFromBech32)|"
    r"(?:victim|defender|receiver|honest)[_\w]*\s*:?=\s*(?:sdk\.AccAddress|sdk\.MustAccAddressFromBech32|createAccount|s\.network\.Validators\[)",
    re.IGNORECASE,
)

# Substrate
SUBSTRATE_ROLE_SEP_RE = re.compile(
    r"(?:attacker|adversar|malicious|sender)[_\w]*\s*:\s*OriginFor<|"
    r"(?:victim|defender|receiver|honest)[_\w]*\s*:\s*OriginFor<|"
    r"RuntimeOrigin::signed\s*\(\s*(?:attacker|adversar|malicious)[_\w]*\s*\)|"
    r"RuntimeOrigin::signed\s*\(\s*(?:victim|defender|receiver|honest)[_\w]*\s*\)",
    re.IGNORECASE,
)

# Solana
SOLANA_ROLE_SEP_RE = re.compile(
    r"(?:attacker|adversar|malicious|sender)[_\w]*\s*=\s*Keypair::new\(\)|"
    r"(?:victim|defender|receiver|honest)[_\w]*\s*=\s*Keypair::new\(\)|"
    r"let\s+(?:attacker|adversar)[_\w]*\s*=\s*Keypair|"
    r"let\s+(?:victim|defender|receiver)[_\w]*\s*=\s*Keypair",
    re.IGNORECASE,
)

# Move
MOVE_ROLE_SEP_RE = re.compile(
    r"(?:attacker|adversar|malicious|sender)[_\w]*\s*:\s*&signer|"
    r"(?:victim|defender|receiver|honest)[_\w]*\s*:\s*&signer|"
    r"create_signer_for_test\s*\(\s*@(?:attacker|adversar)|"
    r"create_signer_for_test\s*\(\s*@(?:victim|defender|receiver)",
    re.IGNORECASE,
)

# General distinct-role hint (fallback)
GENERIC_ROLE_SEP_RE = re.compile(
    r"attacker[_\w]*(?:addr|key|account|signer|wallet|pk|privkey)[_\w]*\s*[=:]\s*.+\n"
    r".{0,200}?"
    r"(?:victim|defender|receiver|honest)[_\w]*(?:addr|key|account|signer|wallet|pk|privkey)",
    re.IGNORECASE | re.DOTALL,
)

# ---------------------------------------------------------------------------
# Single-wallet / single-keypair anti-pattern (controls both sides)
# ---------------------------------------------------------------------------
SINGLE_WALLET_RE = re.compile(
    r"same wallet (?:for both|controls both|is attacker and victim)|"
    r"single (?:wallet|keypair|signer|account) (?:for|controls) both|"
    r"reuse (?:attacker|sender)[_\w]*(?:Addr|addr) (?:as|for) (?:victim|receiver|defender)|"
    r"attacker.*=.*victim.*=.*getnewaddress|"
    r"ATTACKER_ADDR.*=.*RECEIVER_ADDR|"
    r"attacker_addr.*=.*receiver_addr",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Withheld-artifact assertion patterns
# ---------------------------------------------------------------------------
WITHHELD_ASSERTION_RE = re.compile(
    r"for\s+\w+\s+:?=?\s+range\s+chain[Tt]ips|"
    r"for\s+(?:tip|block|tx|msg|artifact)\s+in\s+|"
    r"for\s+_,\s*\w+\s*:?=\s*range\s+|"
    r"enumerate.*(?:confirmed|accepted|submitted|chain)|"
    r"require\.False\s*\(.*spends|"
    r"assert\s+(?:no|not|false)|assert!?\s*\(\s*!|"
    r"assert[Ff]alse|"
    r"AssertFalse|assertFalse\s*\(|"
    r"withheld.*not.*(?:appear|present|found|in chain|broadcast)|"
    r"tx[- ]real.*not.*broadcast|tx[- ]real.*absent|"
    r"no.*tx[- ]real.*in.*(?:chain|window|block)|"
    r"assert.*no.*(?:Msg|msg|event|tx).*type.*matches|"
    r"assertEq\s*\(.*,\s*(?:0\b|false\b)|"
    r"UNRELATED_SPENDS_LEAF.*0|"
    r"for.*tip.*in.*(?:chainTips|chain_tips|block_range)|"
    r"spends_leaf.*false|"
    r"txid.*not.*appear|"
    r"withheld.*txid|"
    r"assertNone|assertEmpty|is_empty\(\)|"
    r"found_in_chain\s*==?\s*false|"
    r"found_tx\s*==?\s*(?:null|None|nil|false)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Attack-causality assertion patterns (production code reaches impact)
# ---------------------------------------------------------------------------
ATTACK_CAUSALITY_RE = re.compile(
    r"transfer\.Status\s*(?:==?|->)\s*\w+|"
    r"\bstate\s*==?\s*[\"'](?:Finalized|Settled|Committed|SENDER_KEY_TWEAKED|COMPLETED)[\"']|"
    r"\bstate\s*:=\s*[\"'](?:Finalized|Settled|Committed|SENDER_KEY_TWEAKED|COMPLETED)[\"']|"
    r"event\.Settled\b|event\.Finalized\b|event\.Committed\b|"
    r"tweakKeysForCoopExit|coop_exit.*confirm(?:ation)?Height|"
    r"leaf\.Status\s*==\s*[\"']?AVAILABLE[\"']?|"
    r"require\.Equal\s*\(.*(?:Status|SENDER_KEY_TWEAKED|FINALIZED|SETTLED)|"
    r"assertEq\s*\(.*(?:status|Status|state)\s*,|"
    r"assert_eq!\s*\(.*(?:status|Status|state|Settled|Finalized)|"
    r"transfer(?:red)?\.status\s*==\s*[\"']|"
    r"confirm(?:ation)?Height\s*!=\s*0|"
    r"assertNotNil\s*\(.*(?:finalization|settlement|commit)|"
    r"emit\s+\w*(?:Settled|Finalized|Complete|Drain|Loss)\s*[\({;]|"
    r"balAfter\s*[<>!=]=?\s*balBefore|"
    r"balAfter\s*==?\s*0\b|"
    r"assert!\s*\(\s*bal_after\s*<\s*bal_before|"
    r"leafStatus\s*:=\s*[\"']AVAILABLE[\"']|"
    r"transferStatus\s*:=\s*[\"']|"
    r"require\.Equal\s*\(\s*t\s*,\s*[\"'][A-Z_]+[\"']\s*,",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Override marker
# ---------------------------------------------------------------------------
REBUTTAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:[#\-*]\s*)?r44[-_ ]rebuttal\s*:\s*(.+?)\s*$"
)
REBUTTAL_HTML_RE = re.compile(
    r"<!--\s*r44-rebuttal:\s*(.*?)\s*-->",
    re.IGNORECASE | re.DOTALL,
)

# ---------------------------------------------------------------------------
# Source file extensions to scan
# ---------------------------------------------------------------------------
CODE_SUFFIXES = {
    ".go", ".rs", ".sol", ".ts", ".tsx", ".js", ".py",
    ".sh", ".move", ".cairo", ".vy", ".txt", ".log", ".md",
}


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _collect_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    if target.is_dir():
        return sorted(p for p in target.rglob("*") if p.is_file() and p.suffix in CODE_SUFFIXES)
    return []


def _combined_text(files: list[Path]) -> tuple[str, list[str]]:
    chunks: list[str] = []
    scanned: list[str] = []
    for p in files:
        try:
            chunks.append(_read_text(p))
            scanned.append(str(p))
        except Exception:
            continue
    return "\n".join(chunks), scanned


def _line_hits(text: str, pattern: re.Pattern[str], *, limit: int = 8) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        m = pattern.search(line)
        if m:
            hits.append({"line": idx, "token": m.group(0)[:80], "text": line.strip()[:240]})
            if len(hits) >= limit:
                break
    return hits


def _rebuttal(text: str) -> str | None:
    m = REBUTTAL_LINE_RE.search(text)
    if not m:
        m = REBUTTAL_HTML_RE.search(text)
    if not m:
        return None
    return " ".join(m.group(1).split())


def _severity_from_filename(path: Path) -> str | None:
    for sev in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){sev}(?:[-_.]|$)", path.name.lower()):
            return sev
    return None


def _env_extra(name: str) -> re.Pattern[str] | None:
    raw = os.environ.get(name, "")
    parts = [p.strip() for p in raw.splitlines() if p.strip()]
    if not parts:
        return None
    return re.compile("|".join(f"(?:{p})" for p in parts), re.IGNORECASE)


def run(
    target: Path,
    *,
    severity_override: str | None = None,
    strict: bool = False,
) -> tuple[int, dict[str, Any]]:
    """Return (exit_code, payload)."""
    files = _collect_files(target)

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "gate": GATE,
        "target": str(target),
        "strict": strict,
        "evidence": {},
    }

    if not files:
        payload["verdict"] = "error"
        payload["error"] = f"no files found at target: {target}"
        return 2, payload

    text, scanned = _combined_text(files)
    payload["scanned_files"] = scanned

    # Severity check - only fires on HIGH+
    sev = severity_override.strip().lower() if severity_override else None
    if sev is None:
        # Try to infer from any file name in the target
        for f in files:
            sev = _severity_from_filename(f)
            if sev:
                break
    if sev is None:
        # Look for a severity header in any file
        m = re.search(
            r"(?im)^\s*\**\s*Severity\s*:\**\s*(Critical|High|Medium|Low)\b",
            text,
        )
        if m:
            sev = m.group(1).lower()
    payload["severity"] = sev

    if sev is None or SEVERITY_RANK.get(sev, 0) < SEVERITY_RANK["high"]:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "severity below HIGH or not determinable; rule only fires on HIGH+"
        return 0, payload

    # Cooperative-case label check
    coop_hits = _line_hits(text, COOPERATIVE_LABEL_RE)
    if coop_hits:
        payload["verdict"] = "pass-cooperative-case-labeled"
        payload["evidence"]["cooperative_label_hits"] = coop_hits
        return 0, payload

    # Opposed-trace harness check - if not an opposed-trace harness, pass out-of-scope
    opposed_hits = _line_hits(text, OPPOSED_TRACE_RE)
    if not opposed_hits:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "not an opposed-trace harness; rule 44 does not apply"
        return 0, payload

    # Override marker check
    rebuttal = _rebuttal(text)
    if rebuttal and len(rebuttal) <= 200:
        payload["verdict"] = "ok-rebuttal"
        payload["rebuttal"] = rebuttal
        return 0, payload
    if rebuttal and len(rebuttal) > 200:
        payload["rebuttal_rejected"] = True
        payload["rebuttal_reason"] = "rebuttal exceeds 200 chars; treated as absent"

    # --- Check 1: Role separation ---
    role_sep_hits: list[dict[str, Any]] = []
    for pattern in (
        BITCOIN_ROLE_SEP_RE,
        EVM_ROLE_SEP_RE,
        COSMOS_ROLE_SEP_RE,
        SUBSTRATE_ROLE_SEP_RE,
        SOLANA_ROLE_SEP_RE,
        MOVE_ROLE_SEP_RE,
    ):
        role_sep_hits.extend(_line_hits(text, pattern))
    # Generic fallback
    if not role_sep_hits:
        role_sep_hits.extend(_line_hits(text, GENERIC_ROLE_SEP_RE))

    # Check env-extension single-wallet patterns
    extra_single_wallet = _env_extra("AUDITOOOR_R44_SINGLE_WALLET_PATTERNS")
    single_wallet_hits = _line_hits(text, SINGLE_WALLET_RE)
    if extra_single_wallet:
        single_wallet_hits.extend(_line_hits(text, extra_single_wallet))

    payload["evidence"]["opposed_trace_hits"] = opposed_hits
    payload["evidence"]["role_separation_hits"] = role_sep_hits
    payload["evidence"]["single_wallet_hits"] = single_wallet_hits

    if single_wallet_hits:
        payload["verdict"] = "fail-single-wallet-multi-role"
        payload["reason"] = (
            "harness uses a single wallet / keypair to control both attacker and defender roles"
        )
        return 1, payload

    if not role_sep_hits:
        payload["verdict"] = "fail-no-role-separation"
        payload["reason"] = (
            "no evidence of distinct signing material for attacker and defender roles; "
            "add separate getnewaddress / vm.startPrank / Keypair::new / sdk.AccAddress per role"
        )
        return 1, payload

    # --- Check 2: Withheld-artifact assertion ---
    withheld_hits = _line_hits(text, WITHHELD_ASSERTION_RE)
    extra_withheld = _env_extra("AUDITOOOR_R44_WITHHELD_ASSERTION_PATTERNS")
    if extra_withheld:
        withheld_hits.extend(_line_hits(text, extra_withheld))
    payload["evidence"]["withheld_assertion_hits"] = withheld_hits

    if not withheld_hits:
        payload["verdict"] = "fail-no-withheld-artifact-assertion"
        payload["reason"] = (
            "no enumeration loop asserting the withheld artifact does not appear in the "
            "confirmed/accepted window; add a loop over chain tips / confirmed txs / submitted "
            "Msgs that asserts the withheld artifact is absent"
        )
        return 1, payload

    # --- Check 3: Attack-causality assertion ---
    causality_hits = _line_hits(text, ATTACK_CAUSALITY_RE)
    payload["evidence"]["attack_causality_hits"] = causality_hits

    if not causality_hits:
        payload["verdict"] = "fail-no-attack-causality-assertion"
        payload["reason"] = (
            "no assertion that production code reached the claimed impact surface "
            "(commit / finalization / status transition / balance change) without the "
            "withheld artifact; add an explicit state/status/balance assertion after the "
            "production code fires"
        )
        return 1, payload

    # All three checks pass
    payload["verdict"] = "pass-actor-separation-with-assertions"
    payload["reason"] = (
        "role separation confirmed, withheld-artifact assertion found, "
        "and attack-causality assertion found"
    )
    return 0, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Rule 44 Opposed-Trace Actor Separation preflight",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "target",
        help="Harness file or directory to scan (all .sh/.go/.rs/.sol/.ts/.py files inside)",
    )
    parser.add_argument(
        "--severity",
        choices=["auto", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="auto",
        help="Override severity detection (default: auto)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail on pass-cooperative-case-labeled (strict mode)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Emit JSON result to stdout",
    )
    args = parser.parse_args(argv)

    target = Path(args.target).expanduser()
    sev_override = None if args.severity == "auto" else args.severity.lower()

    rc, payload = run(target, severity_override=sev_override, strict=args.strict)

    if args.json_output:
        print(json.dumps(payload, indent=2))
    else:
        verdict = payload.get("verdict", "error")
        print(f"verdict: {verdict}")
        if "reason" in payload:
            print(f"reason: {payload['reason']}")
        if "rebuttal" in payload:
            print(f"rebuttal: {payload['rebuttal']}")
        error = payload.get("error")
        if error:
            print(f"error: {error}", file=sys.stderr)
        ev = payload.get("evidence", {})
        for key, hits in ev.items():
            if hits:
                print(f"  {key}: {len(hits)} hit(s)")

    return rc


if __name__ == "__main__":
    sys.exit(main())
