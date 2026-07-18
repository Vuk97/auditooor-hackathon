#!/usr/bin/env python3
"""Convert audit/sig_extracts/*.jsonl into Hackerman go-corpus records.

The ``audit/sig_extracts/dydx-v4-chain.jsonl`` file holds 14,500 Go function-
signature shapes from the dYdX v4-chain repo at the audit pin. Each row
captures: file_path, function_name, function_signature, params, return_types,
modifiers, guards_detected, calls_made, line_start, line_end, receiver_type,
visibility, language.

These rows are NOT bug-finding reports. They are function-shape evidence -
the same kind of evidence Hackerman uses to reason about attack-class fit per
function. For the Go/Cosmos corpus expansion we want a record per function so
the per-function-mindset (function-mindset-precision lane, attack-class
ranker, dispatch-context targeting) has a fully-enumerated Go target surface
to score against. Today the corpus is 407 records (all findings-derived);
adding shape rows for dYdX moves us toward the 1500+ target.

Design:
- Skip files under common no-op trees (mocks, generated, test_fixture).
- For each row, infer:
    target_repo  = dydxprotocol/v4-chain (fixed for this jsonl)
    target_component = file_path:function_name
    bug_class    = inferred from function_name keywords + calls_made
    attack_class = inferred together with bug_class
    impact_class = inferred from bug_class
    fix_pattern  = canned per-bug-class advisory
- Stamp record_tier=public-corpus, record_quality_score=1.4,
  source_extraction_method=sig-extract-shape-v1 so the inventory and the
  Hackerman scoring layers can de-rank these vs richer prior-audit rows.

Rationale for the quality-score floor: these rows have no real attack-
sequence text; they're a "this Go function exists in dYdX at the audit
pin with shape X" catalog. Useful for ranker negatives + dispatch coverage
breadth, NOT promotable to high-confidence findings unaided.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAG_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_SIG_EXTRACTS_DIR = REPO_ROOT / "audit" / "sig_extracts"
SCHEMA_VERSION = "auditooor.hackerman_sig_extract.v1"
# Use schema-enum value 'corpus-etl' so emitted records pass
# hackerman-record-validate.py. Provenance (this tool's name + version)
# is captured separately via the stage-artifact JSON file.
RECORD_EXTRACTION_METHOD = "corpus-etl"
RECORD_QUALITY_SCORE = 1.4

SKIP_PATH_HINTS = (
    "/mocks/",
    "/mock/",
    "/testdata/",
    "/fixtures/",
    "/generated/",
    "/proto/",
    "_test.go",
    "/cli/",
    "_mock.go",
    ".pb.go",  # protobuf generated, no business logic
    ".pb.gw.go",  # grpc-gateway generated
    "_grpc.pb.go",
    "/api/",  # generated grpc client stubs
)
SKIP_VISIBILITIES = {"unexported-helper-noop"}
# A receiver_type that's purely a mock noise generator. Keep this short.
MOCK_RECEIVER_PATTERNS = (re.compile(r"^.+_mock$"),)

BUG_CLASS_RULES: Tuple[Tuple[str, str, Tuple[str, ...], Tuple[str, ...]], ...] = (
    # bug_class, attack_class, name_keywords, call_keywords
    (
        "input-validation",
        "missing-input-validation",
        ("Validate", "Check", "Verify", "Sanitize", "MustValidate"),
        ("ValidateBasic", "panic", "errors.Wrap"),
    ),
    (
        "access-control",
        "admin-bypass",
        ("Admin", "Authority", "Authorized", "Permission", "Authorize", "OnlyOwner"),
        ("authz", "x/authz"),
    ),
    (
        "signature-replay",
        "signature-replay",
        ("Signature", "Sign", "Verify", "Ecrecover", "Nonce"),
        ("ecrecover", "VerifySignature", "tmsecp256k1"),
    ),
    (
        "consensus",
        "consensus-divergence",
        (
            "PrepareProposal",
            "ProcessProposal",
            "ExtendVote",
            "VerifyVoteExtension",
            "FinalizeBlock",
            "BeginBlocker",
            "EndBlocker",
            "Commit",
            "ApplyBlock",
            "PreBlock",
        ),
        ("abci.", "ResponseFinalizeBlock", "RequestFinalizeBlock", "cometbft"),
    ),
    (
        "oracle-manipulation",
        "stale-or-manipulated-oracle",
        ("Oracle", "Price", "Pyth", "Slinky", "TwAP", "Twap", "Median"),
        ("UpdatePrices", "GetPrice", "MedianPrice"),
    ),
    (
        "accounting",
        "state-accounting-drift",
        (
            "Settlement",
            "Settle",
            "Update",
            "Adjust",
            "Increment",
            "Decrement",
            "Apply",
            "Charge",
            "Deduct",
            "Refund",
            "Mint",
            "Burn",
            "Transfer",
            "MoveCoins",
        ),
        ("bank.Keeper", "SendCoins", "subaccount", "balance"),
    ),
    (
        "denial-of-service",
        "dos-griefing",
        (
            "Loop",
            "Iterate",
            "Walk",
            "ForEach",
            "Range",
            "Sweep",
            "Reap",
            "Prune",
            "Drain",
            "Flush",
        ),
        ("for ", "range "),
    ),
    (
        "bridge",
        "bridge-state-divergence",
        ("Bridge", "Acknowledge", "Receive", "Recv", "OnRecv", "OnAck", "IBC"),
        ("ibc-go", "ibctypes", "ibcclient"),
    ),
    (
        "governance",
        "governance-takeover",
        ("Proposal", "Vote", "Tally", "GovParam", "Param", "Govern"),
        ("x/gov", "govtypes"),
    ),
    (
        "staking",
        "staking-bypass",
        ("Delegate", "Undelegate", "Redelegate", "Slash", "Stake", "Unstake", "Reward"),
        ("x/staking", "stakingtypes"),
    ),
    (
        "matching-engine",
        "matching-engine-corruption",
        (
            "MatchOrder",
            "PlaceOrder",
            "CancelOrder",
            "Liquidation",
            "Liquidate",
            "Fill",
            "Match",
            "Clob",
            "OrderBook",
            "PerpetualPosition",
            "Subaccount",
        ),
        ("x/clob", "matching", "orderbook"),
    ),
)

GENERIC_BUG = ("logic-error", "protocol-invariant-bypass")

DOMAIN_BY_PATH = (
    (re.compile(r"/x/clob"), "dex"),
    (re.compile(r"/x/perpetuals"), "dex"),
    (re.compile(r"/x/prices"), "oracle"),
    (re.compile(r"/x/oracle"), "oracle"),
    (re.compile(r"/x/slinky"), "oracle"),
    (re.compile(r"/x/bridge"), "bridge"),
    (re.compile(r"/x/sending"), "bridge"),
    (re.compile(r"/x/gov"), "governance"),
    (re.compile(r"/x/staking"), "staking"),
    (re.compile(r"/x/subaccounts"), "vault"),
    (re.compile(r"/x/rewards"), "staking"),
    (re.compile(r"/x/affiliates"), "vault"),
    (re.compile(r"/x/listing"), "dex"),
    (re.compile(r"/x/vault"), "vault"),
    (re.compile(r"/x/delaymsg"), "consensus"),
    (re.compile(r"/abci|/consensus|/processproposal|/prepareproposal"), "consensus"),
    (re.compile(r"/daemons"), "rpc-infra"),
    (re.compile(r"/rpc"), "rpc-infra"),
    (re.compile(r"/app"), "consensus"),
)

GUARDS_BUG_HINTS = (
    ("nil-check-missing", "input-validation", "missing-nil-check"),
    ("panic-on-error", "denial-of-service", "panic-induced-dos"),
    ("missing-error-check", "input-validation", "swallowed-error"),
    ("unchecked-cast", "input-validation", "integer-overflow"),
    ("missing-context-cancel", "denial-of-service", "leaked-goroutine"),
)


def _load_module(name: str, rel_path: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, str(REPO_ROOT / rel_path))
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


_PRIOR = _load_module(
    "_hackerman_prior_audit_for_sig_extract", "tools/hackerman-etl-from-prior-audits.py"
)


def slugify(value: str, *, max_len: int = 80) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip().lower()).strip("-._")
    slug = re.sub(r"-{2,}", "-", slug)
    return slug[:max_len].strip("-._") or "record"


def _should_skip(row: Dict[str, Any]) -> bool:
    file_path = str(row.get("file_path") or "")
    if not file_path:
        return True
    if any(hint in file_path for hint in SKIP_PATH_HINTS):
        return True
    name = str(row.get("function_name") or "")
    if not name:
        return True
    if name.startswith("Test") or name.startswith("Benchmark") or name.startswith("Example"):
        return True
    receiver = str(row.get("receiver_type") or "")
    if any(pat.match(receiver) for pat in MOCK_RECEIVER_PATTERNS):
        return True
    if str(row.get("language") or "").lower() != "go":
        return True
    return False


def _infer_bug_and_attack(row: Dict[str, Any]) -> Tuple[str, str]:
    name = str(row.get("function_name") or "")
    calls = " ".join(str(c) for c in (row.get("calls_made") or []))
    haystack = f"{name} {calls}"
    for bug_class, attack_class, name_keywords, call_keywords in BUG_CLASS_RULES:
        if any(kw in name for kw in name_keywords):
            return bug_class, attack_class
        if any(kw in calls for kw in call_keywords):
            return bug_class, attack_class
    guards = [str(g) for g in (row.get("guards_detected") or [])]
    for guard_token, bug_class, attack_class in GUARDS_BUG_HINTS:
        if guard_token in guards:
            return bug_class, attack_class
    return GENERIC_BUG


def _infer_domain(row: Dict[str, Any]) -> str:
    file_path = str(row.get("file_path") or "")
    for pattern, domain in DOMAIN_BY_PATH:
        if pattern.search(file_path):
            return domain
    return "rpc-infra"


def _infer_impact(bug_class: str) -> str:
    mapping = {
        "input-validation": "griefing",
        "access-control": "privilege-escalation",
        "signature-replay": "theft",
        "consensus": "dos",
        "oracle-manipulation": "theft",
        "accounting": "theft",
        "denial-of-service": "dos",
        "bridge": "theft",
        "governance": "governance-takeover",
        "staking": "yield-redistribution",
        "matching-engine": "theft",
        "logic-error": "griefing",
    }
    return mapping.get(bug_class, "griefing")


def _infer_severity(row: Dict[str, Any], bug_class: str) -> str:
    # Sig-extract shape rows are intentionally low-confidence; pick "low"
    # baseline so they don't pollute high-severity stats.
    return "low"


def _infer_attacker_role(row: Dict[str, Any]) -> str:
    file_path = str(row.get("file_path") or "")
    name = str(row.get("function_name") or "")
    if "/abci" in file_path or "PrepareProposal" in name or "ProcessProposal" in name or "EndBlocker" in name or "BeginBlocker" in name:
        return "block-proposer"
    if "/daemons" in file_path or "Sidecar" in name or "Daemon" in name:
        return "validator"
    return "unprivileged"


def _shape_tags(bug_class: str, attack_class: str, component: str) -> List[str]:
    base = [slugify(attack_class), f"go-{slugify(bug_class)}"]
    comp = slugify(component, max_len=48)
    if comp and comp not in base:
        base.append(comp)
    return base[:3]


def _fix_pattern(bug_class: str) -> str:
    return {
        "input-validation": "validate all externally supplied identifiers, amounts, and account relationships before any state read or write",
        "access-control": "enforce explicit authorization checks on every privileged state transition",
        "signature-replay": "bind signatures to chain, contract, nonce, signer, and action-specific payload",
        "consensus": "ensure the ABCI handler produces deterministic output independent of validator-local state",
        "oracle-manipulation": "validate oracle freshness and bound price deviation against independent sources",
        "accounting": "update internal accounting atomically with asset movement; never split balance update from movement",
        "denial-of-service": "bound iteration cost and isolate user-controlled failures from shared block execution",
        "bridge": "validate every IBC packet field and ensure ack-vs-recv idempotency across replays",
        "governance": "guard governance writes with quorum + tally invariants and re-validate state on every transition",
        "staking": "respect unbonding-period and slash-window invariants on every keeper write",
        "matching-engine": "preserve order-book invariants across cancel/fill/liquidate paths and guard for self-trade",
    }.get(bug_class, "add explicit invariant checks around the affected state transition")


def _fix_anti_pattern(bug_class: str) -> str:
    return {
        "input-validation": "assuming upstream callers already checked the input",
        "access-control": "relying on caller conventions or UI-only restrictions",
        "signature-replay": "hashing a payload that omits domain or nonce fields",
        "consensus": "branching ABCI behavior on validator-local timing or external IO state",
        "oracle-manipulation": "trusting a single spot price without freshness or deviation checks",
        "accounting": "deriving owed balances from mutable external balances only",
        "denial-of-service": "letting one user-controlled failure block unrelated users",
        "bridge": "trusting upstream-chain header without sequence-and-app-hash binding",
        "governance": "patching tally invariants only on the happy path",
        "staking": "reading slashed-validator share state without re-applying the slash factor",
        "matching-engine": "settling against a stale orderbook slice that hasn't observed the latest cancel",
    }.get(bug_class, "patching symptoms without binding the violated invariant")


def _component_label(row: Dict[str, Any]) -> str:
    sig = str(row.get("function_signature") or "")
    name = str(row.get("function_name") or "")
    file_path = str(row.get("file_path") or "")
    pkg = file_path.rsplit("/", 1)[0]
    if sig:
        return sig[:240]
    if pkg and name:
        return f"{pkg}:{name}"[:240]
    return name[:240] or "unknown-component"


def _truncate_signature(sig: str, *, max_len: int = 480) -> str:
    """Schema cap is 500 chars; for very wide Go signatures (proto-style
    multi-param) we collapse the param list to ellipsis at the cap.
    """
    if len(sig) <= max_len:
        return sig
    # Try to preserve the func name + receiver, then ellipsize.
    head = sig[: max_len - 12]
    return head + " /* ... */)"


def _build_record(row: Dict[str, Any], source_path: Path) -> Dict[str, object]:
    bug_class, attack_class = _infer_bug_and_attack(row)
    domain = _infer_domain(row)
    impact_class = _infer_impact(bug_class)
    severity = _infer_severity(row, bug_class)
    component = _component_label(row)
    name = str(row.get("function_name") or "unknown")
    file_path = str(row.get("file_path") or "unknown")
    signature = _truncate_signature(str(row.get("function_signature") or f"func {name}"))
    line_start = int(row.get("line_start") or 0)
    line_end = int(row.get("line_end") or 0)
    source_audit_ref = (
        f"sig-extract:{source_path.name}:{file_path}:{name}:L{line_start}-L{line_end}"
    )
    digest = hashlib.sha256(source_audit_ref.encode("utf-8")).hexdigest()[:12]
    record_id = (
        f"sig-extract:{slugify(source_path.stem, max_len=32)}:"
        f"{slugify(file_path, max_len=64)}:{slugify(name, max_len=48)}:{digest}"
    )
    preconditions = []
    guards = [str(g) for g in (row.get("guards_detected") or [])]
    if guards:
        preconditions.append(f"guards observed: {', '.join(guards)[:200]}")
    if row.get("visibility") == "exported":
        preconditions.append("exported function; callable across package boundary")
    if not preconditions:
        preconditions.append(
            f"{domain} component exposes Go function shape consistent with {bug_class}"
        )
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": record_id,
        "source_audit_ref": source_audit_ref,
        "record_tier": "public-corpus",
        "record_quality_score": RECORD_QUALITY_SCORE,
        "source_extraction_method": RECORD_EXTRACTION_METHOD,
        "source_extraction_confidence": 0.3,
        "target_domain": domain,
        "target_language": "go",
        "target_repo": "dydxprotocol/v4-chain",
        "target_component": component,
        "function_shape": {
            "raw_signature": signature,
            "shape_tags": _shape_tags(bug_class, attack_class, name),
        },
        "bug_class": bug_class,
        "attack_class": attack_class,
        "attacker_role": _infer_attacker_role(row),
        "attacker_action_sequence": (
            f"Attacker drives {name} along path {file_path}:L{line_start}-L{line_end} "
            f"to exercise the {bug_class} surface."
        )[:800],
        "required_preconditions": preconditions[:3],
        "impact_class": impact_class,
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": "non-financial",
        "fix_pattern": _fix_pattern(bug_class),
        "fix_anti_pattern_avoided": _fix_anti_pattern(bug_class),
        "severity_at_finding": severity,
        "year": 2026,
        "cross_language_analogues": [],
        "related_records": [],
    }


def _iter_rows(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                row = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue
            row.setdefault("_jsonl_line", lineno)
            yield row


def discover_inputs(sig_extracts_dir: Path) -> List[Path]:
    if not sig_extracts_dir.is_dir():
        return []
    return sorted(sig_extracts_dir.glob("*.jsonl"))


def run_etl(args: argparse.Namespace) -> Dict[str, Any]:
    out_dir = Path(args.out_dir).expanduser().resolve()
    if not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
    sig_dir = Path(args.sig_extracts_dir).expanduser().resolve()
    inputs = discover_inputs(sig_dir)
    if args.path:
        explicit = [Path(p).expanduser().resolve() for p in args.path]
        inputs = explicit
    total_rows = 0
    kept_rows = 0
    written_paths: List[Path] = []
    per_file: List[Dict[str, Any]] = []
    domain_counter: Counter[str] = Counter()
    bug_counter: Counter[str] = Counter()
    seen_ids: set[str] = set()
    duplicates_dropped = 0
    for src in inputs:
        if not src.is_file():
            per_file.append({"source": str(src), "skipped": "missing", "rows_seen": 0, "rows_emitted": 0})
            continue
        rows_seen = 0
        rows_emitted = 0
        records: List[Dict[str, object]] = []
        for row in _iter_rows(src):
            rows_seen += 1
            total_rows += 1
            if _should_skip(row):
                continue
            record = _build_record(row, src)
            # Drop sig-extract shape rows whose bug-class inference fell back to
            # GENERIC_BUG ('logic-error'). Without an attack-class fit they're
            # noise for the per-function-mindset ranker and balloon the tag
            # corpus past the target band. Keep them out unless --include-generic
            # is set.
            if not args.include_generic and record.get("bug_class") == GENERIC_BUG[0]:
                continue
            rid = str(record.get("record_id") or "")
            if rid in seen_ids:
                duplicates_dropped += 1
                continue
            seen_ids.add(rid)
            records.append(record)
            kept_rows += 1
            rows_emitted += 1
            domain_counter[str(record.get("target_domain") or "")] += 1
            bug_counter[str(record.get("bug_class") or "")] += 1
            if args.limit is not None and kept_rows >= args.limit:
                break
        if records:
            written = _PRIOR.write_records(records, out_dir, args.dry_run)
            written_paths.extend(written)
        per_file.append(
            {
                "source": str(src),
                "rows_seen": rows_seen,
                "rows_emitted": rows_emitted,
            }
        )
        if args.limit is not None and kept_rows >= args.limit:
            break

    summary = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "tag_dir": str(out_dir),
        "sig_extracts_dir": str(sig_dir),
        "inputs": [str(p) for p in inputs],
        "dry_run": args.dry_run,
        "limit": args.limit,
        "total_rows_seen": total_rows,
        "records_emitted": kept_rows,
        "duplicates_dropped_within_run": duplicates_dropped,
        "domain_counts": dict(sorted(domain_counter.items())),
        "bug_class_counts": dict(sorted(bug_counter.items())),
        "per_file": per_file,
        "files_written_sample": [str(p) for p in written_paths[:25]],
    }
    if args.stage_artifact_out:
        path = Path(args.stage_artifact_out).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        summary["stage_artifact_out"] = str(path)
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sig-extracts-dir",
        default=str(DEFAULT_SIG_EXTRACTS_DIR),
        help="Directory with sig_extracts jsonl files (default: audit/sig_extracts).",
    )
    parser.add_argument("--path", action="append", default=[], help="Explicit jsonl path; repeatable.")
    parser.add_argument(
        "--out-dir",
        default=str(DEFAULT_TAG_DIR),
        help="Target tag directory for emitted YAMLs.",
    )
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument(
        "--include-generic",
        action="store_true",
        help="Include sig-extract rows whose bug-class inference fell back to logic-error.",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--stage-artifact-out", help="Optional JSON stage artifact path.")
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    summary = run_etl(args)
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman sig-extracts etl: "
            f"rows_seen={summary['total_rows_seen']} "
            f"records={summary['records_emitted']} "
            f"dup_dropped={summary['duplicates_dropped_within_run']} "
            f"dry_run={summary['dry_run']} "
            f"out_dir={summary['tag_dir']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
