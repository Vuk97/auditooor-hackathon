#!/usr/bin/env python3
"""Go detector for bridge proof handlers missing recipient/domain binding.

Source-backed lift:
  - Local Go miss `go-bridge-message-recipient-validation-missing-positive`
    demonstrated bridge value release to a message recipient without the
    canonical recipient binding used by the sibling clean fixture.
  - This Fire9 detector narrows the lift to bridge proof-domain handlers:
    proof or message verification must precede transfer, mint, release, or
    dispatch, and the handler must carry receiver-domain material that is not
    checked before the sink.

RELATED TOOLS:
  - detectors/go_wave1/go-bridge-message-recipient-validation-missing.py catches
    memo/payload recipients that are not equality-bound to canonical recipients.
  - detectors/go_wave1/go-bridge-transferout-recipient-binding-missing.py catches
    THORChain-style transfer-out memo recipient mismatches.
  - This detector fills the Go-specific proof-domain gap where verification
    exists but does not bind recipient and receiver-domain fields before value
    movement or dispatch.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Optional


SCHEMA = "auditooor.go_ast_bridge_message_recipient_domain_missing_fire9.v1"
SOURCE_MISS_ID = "go-bridge-message-recipient-validation-missing-positive"
ATTACK_CLASS = "bridge-proof-domain-bypass"

FUNC_DECL_RE = re.compile(
    r"^\s*func\s+(?:\((?P<recv>[^)]*)\)\s+)?(?P<name>[A-Za-z_]\w*)\s*\("
)

BRIDGE_CONTEXT_RE = re.compile(
    r"(bridge|relay|packet|cross.?chain|interchain|message|msg|proof|vaa|attestation"
    r"|receipt|root|commitment|mint|release|dispatch|transfer|domain|chain|receiver"
    r"|recipient)",
    re.IGNORECASE,
)

VERIFY_CALL_RE = re.compile(
    r"\b(?:Verify|Validate|Authenticate|Check|Confirm|Prove)[A-Za-z_]*"
    r"(?:Proof|Message|Msg|Packet|Payload|Attestation|Receipt|VAA|Commitment|Root|Merkle)"
    r"\s*\("
    r"|\b[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\."
    r"(?:Verify|Validate|Authenticate|Check)[A-Za-z_]*"
    r"(?:Proof|Message|Msg|Packet|Payload|Attestation|Receipt|VAA|Commitment|Root|Merkle)?"
    r"\s*\(",
    re.IGNORECASE,
)

_ACTOR_PREFIX = (
    r"(?:msg|message|payload|packet|proof|receipt|event|evt|attestation|vaa|envelope"
    r"|claim|request|req|body|parsed|bridgeMsg|bridgeMessage|inbound|outbound)"
)

RECIPIENT_FIELD_RE = re.compile(
    r"\b" + _ACTOR_PREFIX + r"\."
    r"(?:Recipient|Receiver|To|ToAddress|Destination|DestinationAddress"
    r"|Target|TargetAddress|Beneficiary|Account|Address)\b"
)

DOMAIN_FIELD_RE = re.compile(
    r"\b" + _ACTOR_PREFIX + r"\."
    r"(?:ReceiverDomain|RecipientDomain|DestinationDomain|DestDomain|TargetDomain"
    r"|SourceDomain|RemoteDomain|HomeDomain|Domain|ReceiverChain|RecipientChain"
    r"|DestinationChain|DestChain|TargetChain|SourceChain|ChainID|ChainId|Chain"
    r"|EID|Eid|EndpointID|EndpointId|DstEid|DstEID)\b"
)

ASSIGN_RE = re.compile(r"\b(?P<lhs>[A-Za-z_]\w*)\s*(?::=|=)\s*(?P<rhs>[^;\n]+)")

SINK_CALL_PREFIX_RE = re.compile(
    r"\b(?P<name>SendCoinsFromModuleToAccount|SendCoins|SendAsset|Transfer"
    r"|SafeTransfer|TransferFrom|MintTo|Mint|BridgeMint|Credit|CreditAccount"
    r"|CreditRecipient|Release|ReleaseTo|CompleteTransfer|FinalizeTransfer"
    r"|Dispatch|DispatchMessage|RouteMessage|ExecuteMessage|Execute|CallReceiver"
    r"|Deliver|DeliverMessage|SendPacket)\s*\(",
    re.IGNORECASE,
)

RECIPIENT_ARG_INDEXES = {
    "sendcoinsfrommoduletoaccount": (2,),
    "sendcoins": (2,),
    "sendasset": (1, 2),
    "transfer": (0, 1, 2),
    "safetransfer": (0, 1, 2),
    "transferfrom": (1, 2),
    "mintto": (0, 1),
    "mint": (0, 1),
    "bridgemint": (0, 1),
    "credit": (0, 1, 2),
    "creditaccount": (0, 1, 2),
    "creditrecipient": (0, 1, 2),
    "release": (0, 1, 2),
    "releaseto": (0, 1, 2),
    "completetransfer": (0, 1, 2),
    "finalizetransfer": (0, 1, 2),
    "dispatch": (0, 1, 2),
    "dispatchmessage": (0, 1, 2),
    "routemessage": (0, 1, 2),
    "executemessage": (0, 1, 2),
    "execute": (0, 1, 2),
    "callreceiver": (0, 1),
    "deliver": (0, 1, 2),
    "delivermessage": (0, 1, 2),
    "sendpacket": (0, 1, 2),
}

BINDING_HELPER_RE = re.compile(
    r"\b(?:Validate|Ensure|Assert|Bind|Check|Require|Confirm|Verify)[A-Za-z_]*"
    r"(?:(?:Recipient|Receiver)[A-Za-z_]*(?:Domain|Chain|EID|Binding|Match|Matches)"
    r"|(?:Domain|Chain|EID)[A-Za-z_]*(?:Recipient|Receiver|Binding|Match|Matches))"
    r"\s*\("
    r"|\b(?:ValidateDestinationDomain|ValidateReceiverDomain|EnsureDestinationDomain"
    r"|EnsureReceiverDomain|AssertDestinationDomain|AssertReceiverDomain"
    r"|ValidateRecipientBinding|AssertRecipientMatches|EnsureRecipientMatches)"
    r"\s*\(",
    re.IGNORECASE,
)

COMPARISON_RE = re.compile(
    r"(?:==|!=|\.Equal\s*\(|\.Equals\s*\(|bytes\.Equal\s*\(|strings\.EqualFold\s*\()"
)

TRUSTED_RECIPIENT_RE = re.compile(
    r"(expected|canonical|verified|proof|claim|route|settlement|commitment|public"
    r"|bound|configured|params)",
    re.IGNORECASE,
)

TRUSTED_DOMAIN_RE = re.compile(
    r"(expected|canonical|verified|proof|claim|route|commitment|public|bound"
    r"|configured|params|localDomain|homeDomain|localChain|homeChain|chainConfig"
    r"|expectedDomain|canonicalDomain|configuredDomain|expectedChain|canonicalChain"
    r"|configuredChain|expectedEID|canonicalEID)",
    re.IGNORECASE,
)


@dataclass
class Candidate:
    file: str
    line: int
    function: str
    snippet: str
    severity_hint: str
    source_miss_id: str
    attack_class: str
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
        match = FUNC_DECL_RE.match(lines[i])
        if not match:
            i += 1
            continue
        name = match.group("name")
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


def _term_pattern(term: str) -> str:
    return r"(?<![\w.])" + re.escape(term) + r"(?![\w.])"


def _mentions_any(text: str, terms: set[str]) -> bool:
    return any(re.search(_term_pattern(term), text) for term in terms)


def _matching_terms(text: str, terms: set[str]) -> set[str]:
    return {term for term in terms if re.search(_term_pattern(term), text)}


def _collect_aliases(body_text: str) -> tuple[set[str], set[str]]:
    recipient_aliases: set[str] = set()
    domain_aliases: set[str] = set()

    for line in body_text.splitlines():
        match = ASSIGN_RE.search(line)
        if not match:
            continue
        lhs = match.group("lhs")
        rhs = match.group("rhs")
        if RECIPIENT_FIELD_RE.search(rhs) or _mentions_any(rhs, recipient_aliases):
            recipient_aliases.add(lhs)
        elif lhs in recipient_aliases:
            recipient_aliases.discard(lhs)

        if DOMAIN_FIELD_RE.search(rhs) or _mentions_any(rhs, domain_aliases):
            domain_aliases.add(lhs)
        elif lhs in domain_aliases:
            domain_aliases.discard(lhs)

    return recipient_aliases, domain_aliases


def _recipient_terms(body_text: str, aliases: set[str]) -> set[str]:
    terms = set(aliases)
    terms.update(match.group(0) for match in RECIPIENT_FIELD_RE.finditer(body_text))
    return terms


def _domain_terms(body_text: str, aliases: set[str]) -> set[str]:
    terms = set(aliases)
    terms.update(match.group(0) for match in DOMAIN_FIELD_RE.finditer(body_text))
    return terms


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


def _call_uses_recipient(call_text: str, recipient_terms: set[str]) -> bool:
    match = SINK_CALL_PREFIX_RE.search(call_text)
    if not match:
        return False
    args = _split_call_args(call_text)
    indexes = RECIPIENT_ARG_INDEXES.get(match.group("name").lower(), range(len(args)))
    return any(idx < len(args) and _mentions_any(args[idx], recipient_terms) for idx in indexes)


def _find_sink(
    body_lines: list[str],
    first_line: int,
    recipient_terms: set[str],
) -> tuple[int, str] | None:
    for call_text, line_no in _call_spans(body_lines, first_line):
        if _call_uses_recipient(call_text, recipient_terms):
            return line_no, call_text.splitlines()[0].strip()[:240]
    return None


def _has_verification_before(body_lines: list[str], first_line: int, sink_line: int) -> bool:
    for offset, raw in enumerate(body_lines):
        line_no = first_line + offset
        if line_no >= sink_line:
            break
        if VERIFY_CALL_RE.search(_strip_strings_and_comments(raw)):
            return True
    return False


def _has_named_binding(guard_text: str, recipient_terms: set[str], domain_terms: set[str]) -> bool:
    if not BINDING_HELPER_RE.search(guard_text):
        return False
    return _mentions_any(guard_text, recipient_terms) or _mentions_any(guard_text, domain_terms)


def _has_explicit_binding(
    guard_text: str,
    terms: set[str],
    trusted_re: re.Pattern[str],
) -> bool:
    for line in guard_text.splitlines():
        if not COMPARISON_RE.search(line):
            continue
        matches = _matching_terms(line, terms)
        if len(matches) >= 2:
            return True
        if matches and trusted_re.search(line):
            return True
    return False


def _has_binding_guard(
    body_lines: list[str],
    first_line: int,
    sink_line: int,
    recipient_terms: set[str],
    domain_terms: set[str],
) -> bool:
    guard_lines = [
        _strip_strings_and_comments(raw)
        for offset, raw in enumerate(body_lines)
        if first_line + offset < sink_line
    ]
    guard_text = "\n".join(guard_lines)

    if _has_named_binding(guard_text, recipient_terms, domain_terms):
        return True

    has_recipient = _has_explicit_binding(guard_text, recipient_terms, TRUSTED_RECIPIENT_RE)
    has_domain = _has_explicit_binding(guard_text, domain_terms, TRUSTED_DOMAIN_RE)
    return has_recipient and has_domain


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

        if not BRIDGE_CONTEXT_RE.search(name) and not BRIDGE_CONTEXT_RE.search(fn_text_clean):
            continue
        if not VERIFY_CALL_RE.search(fn_text_clean):
            continue

        recipient_aliases, domain_aliases = _collect_aliases(body_text)
        recipients = _recipient_terms(body_text, recipient_aliases)
        domains = _domain_terms(body_text, domain_aliases)
        if not recipients or not domains:
            continue

        sink = _find_sink(body_lines, body_start + 2, recipients)
        if sink is None:
            continue
        line_no, snippet = sink
        if not _has_verification_before(body_lines, body_start + 2, line_no):
            continue
        if _has_binding_guard(body_lines, body_start + 2, line_no, recipients, domains):
            continue

        out.append(
            Candidate(
                file=str(path),
                line=line_no,
                function=name,
                snippet=snippet,
                severity_hint="HIGH",
                source_miss_id=SOURCE_MISS_ID,
                attack_class=ATTACK_CLASS,
                reason=(
                    "bridge proof or message verification is followed by a value sink "
                    "using a message recipient while receiver-domain material is present "
                    "but recipient and domain binding checks are absent before the sink"
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
    parser = argparse.ArgumentParser(
        description="Go detector: bridge proof/message recipient domain missing"
    )
    parser.add_argument("repo", type=Path, help="repo root or Go file to scan")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--threshold", type=int, default=0, help="min candidates to exit 1")
    args = parser.parse_args(argv)

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
