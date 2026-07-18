#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Optional


SCHEMA = "auditooor.go_ast_fee_redirect_user_controlled_sink.v1"

FEE_CONTEXT_RE = re.compile(
    r"(fee|fees|feeCollector|protocolFee|tradingFee|makerFee|takerFee"
    r"|rebate|commission|reward|rewards|distribute|collector|treasury"
    r"|affiliate|integrator|referrer|accru|accrual)",
    re.IGNORECASE,
)

FEE_VALUE_RE = re.compile(
    r"(fee|fees|protocolFee|tradingFee|makerFee|takerFee|rebate|commission"
    r"|reward|rewards|collector|treasury|affiliate|integrator|referrer"
    r"|accrued|accrual)",
    re.IGNORECASE,
)

USER_FIELD_RE = re.compile(
    r"\b(?:msg|req|request|order|trade|settlement|input|payload)\."
    r"[A-Za-z_]\w*(?:Recipient|Receiver|Address|Addr|Sink|Referrer"
    r"|Affiliate|Integrator|Beneficiary|Payout|Payee|User|Collector)"
    r"[A-Za-z_]*\b"
)

SIGNER_SOURCE_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:(?:msg|req|request|payload|input)\."
    r"(?:GetSigners?|Signer|Sender|Creator|FromAddress|FromAddr)"
    r"(?:\s*\(\s*\))?(?:\s*\[[^\]]+\])?"
    r"|ctx\.MsgSender\s*\(\s*\))"
)

USER_PARAM_NAME_RE = re.compile(
    r"^(?:to|recipient|receiver|sink|payee|beneficiary|referrer|affiliate"
    r"|integrator|feeRecipient|feeSink|rebateRecipient|rebateAddr"
    r"|commissionRecipient|commissionAddr|rewardRecipient|rewardAddr"
    r"|payoutRecipient|payoutAddr)$",
    re.IGNORECASE,
)

ADDRESS_PARAM_RE = re.compile(
    r"(?P<names>[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+"
    r"(?:(?:sdk|common|types)\.)?"
    r"(?:AccAddress|Address|Addr|string)\b"
)

ASSIGN_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?::=|=)\s*([^;\n]+)")

SINK_CALL_PREFIX_RE = re.compile(
    r"\b(?P<name>SendCoinsFromModuleToAccount|SendCoins|Transfer"
    r"|PayFee|PayFees|PayRebate|PayCommission|PayReward|PayRewards"
    r"|CreditFee|CreditRebate|CreditCommission|CreditReward|CreditRewards"
    r"|PayoutFee|PayoutRebate|PayoutCommission|PayoutReward|PayoutRewards"
    r"|DistributeRewards|SendReward|SendRewards)\s*\(",
    re.IGNORECASE,
)

RECIPIENT_ARG_INDEXES = {
    "sendcoinsfrommoduletoaccount": (2,),
    "sendcoins": (2,),
    "transfer": (0, 1),
    "payfee": (0, 1, 2),
    "payfees": (0, 1, 2),
    "payrebate": (0, 1, 2),
    "paycommission": (0, 1, 2),
    "payreward": (0, 1, 2),
    "payrewards": (0, 1, 2),
    "creditfee": (0, 1, 2),
    "creditrebate": (0, 1, 2),
    "creditcommission": (0, 1, 2),
    "creditreward": (0, 1, 2),
    "creditrewards": (0, 1, 2),
    "payoutfee": (0, 1, 2),
    "payoutrebate": (0, 1, 2),
    "payoutcommission": (0, 1, 2),
    "payoutreward": (0, 1, 2),
    "payoutrewards": (0, 1, 2),
    "distributerewards": (0, 1, 2),
    "sendreward": (0, 1, 2),
    "sendrewards": (0, 1, 2),
}

AMOUNT_ARG_INDEXES = {
    "sendcoinsfrommoduletoaccount": (1, 3),
    "sendcoins": (1, 3),
    "transfer": (1, 2),
    "payfee": (1, 2, 3),
    "payfees": (1, 2, 3),
    "payrebate": (1, 2, 3),
    "paycommission": (1, 2, 3),
    "payreward": (1, 2, 3),
    "payrewards": (1, 2, 3),
    "creditfee": (1, 2, 3),
    "creditrebate": (1, 2, 3),
    "creditcommission": (1, 2, 3),
    "creditreward": (1, 2, 3),
    "creditrewards": (1, 2, 3),
    "payoutfee": (1, 2, 3),
    "payoutrebate": (1, 2, 3),
    "payoutcommission": (1, 2, 3),
    "payoutreward": (1, 2, 3),
    "payoutrewards": (1, 2, 3),
    "distributerewards": (1, 2, 3),
    "sendreward": (1, 2, 3),
    "sendrewards": (1, 2, 3),
}

CONFIGURED_SINK_RE = re.compile(
    r"(FeeCollector|feeCollector|ProtocolFeeCollector|CollectorAddress"
    r"|ConfiguredFee|ConfiguredCollector|CanonicalFee|CanonicalRecipient"
    r"|ExpectedFee|ExpectedRecipient|Treasury|CommunityPool|RewardCollector"
    r"|RewardModule|GetFeeCollector|GetCollector|GetTreasury"
    r"|GetModuleAddress|FeeCollectorName|ModuleAccount|ModuleName"
    r"|AllowedFeeRecipient|AllowedRewardRecipient|AllowlistedSink)",
    re.IGNORECASE,
)

NAMED_GUARD_RE = re.compile(
    r"(ValidateFeeRecipient|ValidateFeeSink|ValidateCollectorRecipient"
    r"|ValidateRewardRecipient|ValidateCanonicalRecipient"
    r"|ValidateModuleAccountRecipient|EnsureFeeRecipient|EnsureFeeSink"
    r"|EnsureCollectorRecipient|EnsureRewardRecipient"
    r"|AssertFeeRecipient|AssertCollectorRecipient|AllowedFeeRecipient"
    r"|AllowedRewardRecipient|IsAllowedFeeRecipient"
    r"|IsAllowedRewardRecipient|IsConfiguredFeeRecipient"
    r"|IsConfiguredRewardRecipient|IsModuleAccount|GetModuleAccount"
    r"|GetModuleAddress|BlockedAddr|IsBlockedAddr|IsAllowlistedSink)",
    re.IGNORECASE,
)

COMPARISON_RE = re.compile(r"(?:==|!=|\.Equal\s*\(|\.Equals\s*\(|bytes\.Equal\s*\()")
FUNC_DECL_RE = re.compile(
    r"^\s*func\s+(?:\((?P<recv>[^)]*)\)\s+)?(?P<name>[A-Za-z_]\w*)\s*\("
)


@dataclass
class Candidate:
    file: str
    line: int
    function: str
    snippet: str
    severity_hint: str
    reason: str


def _strip_strings_and_comments(line: str) -> str:
    out: list[str] = []
    i = 0
    in_str: str | None = None
    while i < len(line):
        c = line[i]
        if in_str:
            if c == "\\" and i + 1 < len(line):
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in ('"', "'", "`"):
            in_str = c
            i += 1
            continue
        if c == "/" and i + 1 < len(line) and line[i + 1] == "/":
            break
        out.append(c)
        i += 1
    return "".join(out)


def _iter_funcs(lines: list[str]):
    i = 0
    n = len(lines)
    while i < n:
        m = FUNC_DECL_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group("name")
        depth = 0
        body_start = -1
        opened = False
        j = i
        while j < n:
            stripped = _strip_strings_and_comments(lines[j])
            for ch in stripped:
                if ch == "{":
                    if not opened:
                        opened = True
                        body_start = j
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if opened and depth == 0:
                        yield name, i, body_start, j
                        i = j + 1
                        break
            else:
                j += 1
                continue
            break
        else:
            return


def _split_call_args(call_text: str) -> list[str]:
    start = call_text.find("(")
    end = call_text.rfind(")")
    if start < 0 or end <= start:
        return []
    args_text = call_text[start + 1 : end]
    args: list[str] = []
    current: list[str] = []
    depth = 0
    for ch in args_text:
        if ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
        if ch in "([{":
            depth += 1
        elif ch in ")]}" and depth > 0:
            depth -= 1
    if current or args_text.strip():
        args.append("".join(current).strip())
    return args


def _function_header(fn_text: str) -> str:
    return fn_text.split("{", 1)[0]


def _address_params(fn_text: str) -> set[str]:
    params: set[str] = set()
    for match in ADDRESS_PARAM_RE.finditer(_function_header(fn_text)):
        for name in match.group("names").split(","):
            name = name.strip()
            if USER_PARAM_NAME_RE.match(name):
                params.add(name)
    return params


def _clean_expr(expr: str) -> str:
    return expr.strip().strip("&*").strip()


def _expr_mentions_any(expr: str, terms: set[str]) -> bool:
    for term in terms:
        if "." in term or "(" in term or "[" in term:
            if term in expr:
                return True
            continue
        if re.search(rf"\b{re.escape(term)}\b", expr):
            return True
    return False


def _is_configured_sink(expr: str) -> bool:
    expr = _clean_expr(expr)
    if USER_FIELD_RE.search(expr) or SIGNER_SOURCE_RE.search(expr):
        return False
    return bool(CONFIGURED_SINK_RE.search(expr))


def _seed_user_terms(fn_text: str, body_text: str) -> set[str]:
    terms = set(USER_FIELD_RE.findall(body_text))
    terms.update(match.group(0).strip() for match in SIGNER_SOURCE_RE.finditer(body_text))
    terms.update(_address_params(fn_text))
    return terms


def _expand_user_aliases(body_text: str, terms: set[str]) -> set[str]:
    aliases = set(terms)
    for line in body_text.splitlines():
        match = ASSIGN_RE.search(line)
        if not match:
            continue
        lhs = match.group(1)
        rhs = match.group(2)
        if _is_configured_sink(rhs):
            aliases.discard(lhs)
            continue
        if USER_FIELD_RE.search(rhs) or SIGNER_SOURCE_RE.search(rhs) or _expr_mentions_any(rhs, aliases):
            aliases.add(lhs)
        elif lhs in aliases and USER_PARAM_NAME_RE.match(lhs):
            continue
        elif lhs in aliases:
            aliases.discard(lhs)
    return aliases


def _call_spans(body_lines: list[str], first_line: int) -> list[tuple[str, int]]:
    spans: list[tuple[str, int]] = []
    current: list[str] = []
    current_line = first_line
    depth = 0
    for offset, raw in enumerate(body_lines):
        line_no = first_line + offset
        line = _strip_strings_and_comments(raw)
        if current:
            current.append(line)
            depth += line.count("(") - line.count(")")
            if depth <= 0:
                spans.append(("\n".join(current), current_line))
                current = []
            continue
        if not SINK_CALL_PREFIX_RE.search(line):
            continue
        current = [line]
        current_line = line_no
        depth = line.count("(") - line.count(")")
        if depth <= 0:
            spans.append((line, line_no))
            current = []
    return spans


def _fee_like_transfer(call_name: str, args: list[str]) -> bool:
    indexes = AMOUNT_ARG_INDEXES.get(call_name.lower(), ())
    if any(idx < len(args) and FEE_VALUE_RE.search(args[idx]) for idx in indexes):
        return True
    return bool(FEE_VALUE_RE.search(call_name))


def _user_recipient_args(call_name: str, args: list[str], terms: set[str]) -> list[str]:
    recipient_args: list[str] = []
    indexes = RECIPIENT_ARG_INDEXES.get(call_name.lower(), ())
    for idx in indexes:
        if idx >= len(args):
            continue
        expr = _clean_expr(args[idx])
        if _is_configured_sink(expr):
            continue
        if USER_FIELD_RE.search(expr) or SIGNER_SOURCE_RE.search(expr) or _expr_mentions_any(expr, terms):
            recipient_args.append(expr)
    return recipient_args


def _has_configured_guard(body_text: str, user_terms: set[str]) -> bool:
    for line in body_text.splitlines():
        if not _expr_mentions_any(line, user_terms) and not SIGNER_SOURCE_RE.search(line):
            continue
        if NAMED_GUARD_RE.search(line):
            return True
        if CONFIGURED_SINK_RE.search(line) and COMPARISON_RE.search(line):
            return True
    return False


def _fee_redirect_reason(
    body_lines: list[str], first_line: int, terms: set[str]
) -> tuple[str, int, str] | None:
    for call_text, line_no in _call_spans(body_lines, first_line):
        match = SINK_CALL_PREFIX_RE.search(call_text)
        if not match:
            continue
        call_name = match.group("name")
        args = _split_call_args(call_text)
        if not _fee_like_transfer(call_name, args):
            continue
        recipients = _user_recipient_args(call_name, args, terms)
        if recipients:
            return (
                f"{call_name} routes fee-like value to user-controlled sink `{recipients[0]}`",
                line_no,
                call_text.splitlines()[0].strip()[:240],
            )
    return None


def scan_file(path: Path) -> list[Candidate]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return []
    lines = text.splitlines()
    out: list[Candidate] = []
    for name, decl_line, body_start, body_end in _iter_funcs(lines):
        fn_text = "\n".join(lines[decl_line : body_end + 1])
        body_lines = lines[body_start + 1 : body_end]
        body_text = "\n".join(_strip_strings_and_comments(line) for line in body_lines)
        fn_text_clean = "\n".join(
            _strip_strings_and_comments(line) for line in lines[decl_line : body_end + 1]
        )

        if not (FEE_CONTEXT_RE.search(name) or FEE_CONTEXT_RE.search(fn_text_clean)):
            continue

        terms = _expand_user_aliases(body_text, _seed_user_terms(fn_text, body_text))
        if not terms:
            continue
        if _has_configured_guard(body_text, terms):
            continue

        reason = _fee_redirect_reason(body_lines, body_start + 2, terms)
        if reason is None:
            continue
        reason_text, line_no, snippet = reason
        out.append(
            Candidate(
                file=str(path),
                line=line_no,
                function=name,
                snippet=snippet,
                severity_hint="HIGH",
                reason=(
                    f"{reason_text} without checking it against the configured "
                    "collector, treasury, module account, or allowlisted sink"
                ),
            )
        )
    return out


def walk_repo(root: Path) -> Iterable[Path]:
    for p in root.rglob("*.go"):
        parts = set(p.parts)
        if "vendor" in parts or "testdata" in parts or ".auditooor" in parts:
            continue
        if p.name.endswith("_test.go"):
            continue
        if p.name.endswith(".pb.go") or p.name.endswith(".pb.gw.go"):
            continue
        yield p


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Go detector: user-controlled fee collector or fee sink"
    )
    ap.add_argument("repo", type=Path, help="repo root or Go file to scan")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--threshold", type=int, default=0, help="min candidates to exit 1")
    args = ap.parse_args(argv)

    root = args.repo
    if not root.exists():
        print(f"error: {root} does not exist", file=sys.stderr)
        return 2

    candidates: list[Candidate] = []
    if root.is_file() and root.suffix == ".go":
        candidates.extend(scan_file(root))
    else:
        for p in walk_repo(root):
            candidates.extend(scan_file(p))

    payload = {
        "schema": SCHEMA,
        "root": str(root),
        "count": len(candidates),
        "candidates": [asdict(c) for c in candidates],
    }
    out_text = json.dumps(payload, indent=2)
    if args.out:
        args.out.write_text(out_text, encoding="utf-8")
    else:
        print(out_text)
    if args.threshold and len(candidates) < args.threshold:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
