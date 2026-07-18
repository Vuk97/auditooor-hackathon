#!/usr/bin/env python3
"""Base Rust Swival-shape scanner.

Turns the Swival rust-stdlib mining output into a small, runnable scanner for
Base-native Rust code. This is intentionally conservative and candidate-only:
it emits detector rows that require a harness task before any report language.

Covered families in this first slice:

* integer/length truncation in consensus or protocol parsers;
* length-prefixed network/consensus allocation without an obvious cap;
* consensus decode/from_bytes functions that do not visibly mention a version,
  fork, capability, or guard.
* unsafe pointer/length primitives in Base-native production paths;
* relaxed atomic state transitions on consensus/proof/execution state tokens.

The tool never claims severity. It creates scan evidence for the automation
closure flow and is meant to feed a harness-task generator.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

try:
    from lib.project_source_roots import rust_crate_scan_roots
except ModuleNotFoundError:  # pragma: no cover - direct import from test loaders.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from lib.project_source_roots import rust_crate_scan_roots


SCHEMA_VERSION = "auditooor.base_rust_swival_shape_scan.v1"

DEFAULT_SCAN_ROOTS = ("external/base/crates", "crates")

SKIP_PATH_TOKENS = (
    "/target/",
    "/tests/",
    "/test_",
    "_tests.rs",
    "/benches/",
    "/examples/",
    "/fuzz/",
)

CONSENSUS_PATH_TOKENS = (
    "/consensus/",
    "/protocol/",
    "/derive/",
    "/engine/",
    "/execution/",
    "/rpc-types-engine/",
    "/batcher/",
    "/proof/",
)

SAFE_CAP_TOKENS = (
    "MAX_",
    "MAXIMUM_",
    "_MAX",
    "LIMIT",
    "limit",
    "bound",
    "ensure!",
    "checked_",
    "try_from",
    "saturating_",
    ".min(",
    "min(",
)


@dataclass
class Row:
    pattern_id: str
    file: str
    line: int
    function: str
    source_swival_family: str
    snippet: str
    attacker_input_source: str
    impact_hypothesis: str
    selected_impact: str
    severity: str
    impact_contract_required: bool
    impact_contract_id: str
    candidate_kind: str
    submission_posture: str
    harness_task: str
    kill_criteria: str


def _iter_rs_files(workspace: Path, scan_roots: list[str]) -> list[Path]:
    files: list[Path] = []
    for rel in scan_roots:
        root = workspace / rel
        if not root.exists():
            continue
        for path in root.rglob("*.rs"):
            norm = "/" + path.relative_to(workspace).as_posix()
            if any(tok in norm for tok in SKIP_PATH_TOKENS):
                continue
            files.append(path)
    return sorted(files)


def _line_no(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _function_at(text: str, pos: int) -> str:
    prefix = text[:pos]
    matches = list(re.finditer(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", prefix))
    return matches[-1].group(1) if matches else "<module>"


def _source_hint(rel: str) -> str:
    lowered = rel.lower()
    if "/gossip/" in lowered or "/p2p/" in lowered or "/network/" in lowered:
        return "p2p_or_gossip"
    if "/rpc-types-engine/" in lowered or "/engine/" in lowered:
        return "engine_api"
    if "/consensus/" in lowered or "/derive/" in lowered or "/batch" in lowered:
        return "untrusted_l1_or_consensus_payload"
    if "/proof/" in lowered:
        return "proof_or_attestation_input"
    return "unknown"


def _has_visible_cap(body: str) -> bool:
    return any(tok in body for tok in SAFE_CAP_TOKENS)


def _body_window(text: str, pos: int, span: int = 1200) -> str:
    start = max(0, pos - span // 3)
    end = min(len(text), pos + span)
    return text[start:end]


def _mask_cfg_test_modules(text: str) -> str:
    """Replace `#[cfg(test)] mod tests { ... }` bodies with spaces.

    Keeping byte offsets stable preserves line numbers while preventing fixture
    assertions inside production files from becoming detector rows.
    """
    starts = list(re.finditer(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*mod\s+tests\s*\{", text))
    if not starts:
        return text
    chars = list(text)
    for match in starts:
        depth = 0
        end = match.end()
        for i in range(match.end() - 1, len(chars)):
            ch = chars[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        for i in range(match.start(), end):
            if chars[i] != "\n":
                chars[i] = " "
    return "".join(chars)


TRUNCATION_RE = re.compile(
    r"\b(?:u64|u128|U256|U512|from_be_bytes|from_le_bytes|read_u(?:64|128)|"
    r"decode_[A-Za-z0-9_]*len|block_count|tx_count|transaction_count)"
    r"[\s\S]{0,160}?\bas\s+usize\b",
    re.MULTILINE,
)

LEN_ALLOC_RE = re.compile(
    r"\b(?:read_u(?:32|64)|get_u(?:32|64)|read_varint|read_leb128|"
    r"decode_length|read_length)[\s\S]{0,320}?"
    r"(?:Vec::with_capacity\s*\(|vec!\s*\[[^\]]+;\s*|read_exact\s*\()",
    re.MULTILINE,
)

DECODE_FN_RE = re.compile(
    r"\bfn\s+(decode|deserialize|from_bytes|from_wire|parse)[A-Za-z0-9_]*"
    r"\s*\([^)]*(?:&\[u8\]|Bytes|Buf|Reader|Cursor|payload|data)[^)]*\)"
    r"\s*(?:->\s*[^{]+)?\{",
    re.MULTILINE,
)

GUARD_RE = re.compile(
    r"\b(version|fork|hardfork|capability|feature|guard|schema|kind|type_id|"
    r"magic|tag|MAX_|LIMIT|ensure!|validate|checked_|try_from)\b",
    re.IGNORECASE,
)

UNSAFE_LEN_PTR_RE = re.compile(
    r"\b(?:set_len|from_raw_parts(?:_mut)?|assume_init(?:_read)?|"
    r"get_unchecked(?:_mut)?|unwrap_unchecked)\s*\(",
    re.MULTILINE,
)

ATOMIC_RELAXED_RE = re.compile(
    r"\b(?:load|store|swap|fetch_(?:add|sub|max|min|or|and|xor)|"
    r"compare_exchange(?:_weak)?)\s*\([^;\n]*Ordering::Relaxed",
    re.MULTILINE,
)

STATE_TOKEN_RE = re.compile(
    r"\b(head|block|timestamp|running|ready|valid|status|l1_head|"
    r"current_block|proof|registry|finali[sz]ed|safe|unsafe)\b",
    re.IGNORECASE,
)

METRIC_ONLY_RE = re.compile(
    r"\b(metric|metering|counter|hits|misses|call_count|opened|closed|sent|"
    r"lagged|stale)\b",
    re.IGNORECASE,
)

# --- Advisory unsafe-soundness axis (OFF by default) -----------------------
# Net-new predicate over the presence-only base scan: a hand-written
# `unsafe impl Send|Sync` whose struct holds a raw interior-mutability / raw
# pointer cell, where NO justification token (a `# Safety` rationale block or a
# Mutex/RwLock/Atomic synchronizer) is visible in the doc block or struct body.
# This is the *justification* predicate, not just presence. Text-only: it can
# never prove aliasing/provenance UB, so every hit is advisory `needs-fuzz`
# and must be confirmed by Miri/loom before any report language.
UNSAFE_IMPL_AXIS_ENV = "SWIVAL_UNSAFE_IMPL_AXIS"
UNSAFE_IMPL_SEND_SYNC_DETECTOR = "swival_unsafe_impl_send_sync_unjustified"
UNSAFE_IMPL_HYP_SCHEMA = "auditooor.swival_unsafe_impl_send_sync_unjustified.v1"

UNSAFE_IMPL_SEND_SYNC_RE = re.compile(
    r"unsafe\s+impl(?:\s*<[^>]*>)?\s+(Send|Sync)\s+for\s+([A-Za-z_][A-Za-z0-9_]*)",
)
# Raw interior-mutability / raw-pointer cell that makes an auto-Send/Sync
# derivation unsound and forces the hand-written `unsafe impl`.
UNSAFE_IMPL_RAW_CELL_RE = re.compile(r"UnsafeCell|\*\s*mut\b|\*\s*const\b|NonNull")
# Visible justification: a Safety rationale marker OR an in-struct synchronizer.
UNSAFE_IMPL_JUSTIFY_RE = re.compile(
    r"#\s*Safety|SAFETY\s*:|\bMutex\b|\bRwLock\b|\bAtomic[A-Za-z0-9_]*\b"
)


def _preceding_doc_block(text: str, pos: int) -> str:
    """Contiguous comment/attr lines immediately above the impl line at pos.

    Stops at the first blank or code line so a *neighbouring* impl's Safety
    doc cannot falsely justify this one (precise per-impl attribution).
    """
    line_start = text.rfind("\n", 0, pos) + 1
    prior_lines = text[:line_start].splitlines()
    out: list[str] = []
    for ln in reversed(prior_lines):
        s = ln.strip()
        if s.startswith("//") or s.startswith("#["):
            out.append(ln)
        else:
            break
    return "\n".join(reversed(out))


def _struct_body_for(text: str, type_name: str) -> str:
    """Best-effort source span of `struct <type_name>` (braced or tuple)."""
    m = re.search(r"\bstruct\s+" + re.escape(type_name) + r"\b", text)
    if not m:
        return ""
    brace = text.find("{", m.end())
    semi = text.find(";", m.end())
    if brace == -1 or (semi != -1 and semi < brace):
        end = semi + 1 if semi != -1 else min(len(text), m.end() + 240)
        return text[m.start():end]
    depth = 0
    for i in range(brace, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[m.start():i + 1]
    return text[m.start():]


def scan_unsafe_impl_send_sync(workspace: Path, scan_roots: list[str]) -> list[dict]:
    """Emit advisory `needs-fuzz` hypotheses for unjustified unsafe Send/Sync.

    DEDUP boundary (A1): each hit records `covered_by` by comparing its exact
    (file,line) against the named presence-only base detector
    (`swival_unsafe_len_pointer_primitive`) on the same file - the covered_by
    signal is looked up, never re-derived. An `unsafe impl` line is a distinct
    surface from a raw-pointer call site, so overlap is expected to be empty.
    """
    hyps: list[dict] = []
    for path in _iter_rs_files(workspace, scan_roots):
        text = _mask_cfg_test_modules(
            path.read_text(encoding="utf-8", errors="ignore")
        )
        presence_lines = {
            _line_no(text, mm.start()) for mm in UNSAFE_LEN_PTR_RE.finditer(text)
        }
        rel = path.relative_to(workspace).as_posix()
        for m in UNSAFE_IMPL_SEND_SYNC_RE.finditer(text):
            trait_name = m.group(1)
            type_name = m.group(2)
            body = _struct_body_for(text, type_name)
            if not UNSAFE_IMPL_RAW_CELL_RE.search(body):
                continue
            doc = _preceding_doc_block(text, m.start())
            window = doc + "\n" + body
            if UNSAFE_IMPL_JUSTIFY_RE.search(window):
                continue
            line = _line_no(text, m.start())
            snippet = text.splitlines()[line - 1].strip()
            hyps.append(
                {
                    "schema": UNSAFE_IMPL_HYP_SCHEMA,
                    "detector": UNSAFE_IMPL_SEND_SYNC_DETECTOR,
                    "axis": "unsafe_soundness",
                    "advisory": True,
                    "verdict": "needs-fuzz",
                    "file": rel,
                    "line": line,
                    "impl_trait": trait_name,
                    "impl_type": type_name,
                    "snippet": snippet,
                    "covered_by": (
                        "swival_unsafe_len_pointer_primitive"
                        if line in presence_lines
                        else ""
                    ),
                    "submission_posture": "NOT_SUBMIT_READY",
                    "fp_guard": (
                        "text-scan cannot prove aliasing/provenance UB; a plain "
                        "safety-rationale comment lacking a # Safety/SAFETY: "
                        "marker is not recognized and will over-fire. Confirm "
                        "soundness with Miri/loom before any report language."
                    ),
                    "harness_task": (
                        "Build a two-thread aliasing/data-race harness over the "
                        "raw cell and run under Miri (and loom for ordering). "
                        "Assert no UB / data race under concurrent get/set."
                    ),
                    "kill_criteria": (
                        "Kill if the raw cell is only ever accessed under an "
                        "internal lock, the value is immutable after "
                        "construction, the type is never shared across threads, "
                        "or Miri/loom show the access is sound."
                    ),
                }
            )
    return hyps


def _add_row(
    rows: list[Row],
    *,
    workspace: Path,
    path: Path,
    text: str,
    pos: int,
    pattern_id: str,
    family: str,
    impact: str,
    harness: str,
    kill: str,
) -> None:
    rel = path.relative_to(workspace).as_posix()
    line = _line_no(text, pos)
    snippet = text.splitlines()[line - 1].strip()
    rows.append(
        Row(
            pattern_id=pattern_id,
            file=rel,
            line=line,
            function=_function_at(text, pos),
            source_swival_family=family,
            snippet=snippet,
            attacker_input_source=_source_hint(rel),
            impact_hypothesis=impact,
            selected_impact="",
            severity="none",
            impact_contract_required=True,
            impact_contract_id="",
            candidate_kind="detector_harness_task_candidate",
            submission_posture="NOT_SUBMIT_READY",
            harness_task=harness,
            kill_criteria=kill,
        )
    )


def scan_workspace(workspace: Path, scan_roots: list[str]) -> list[Row]:
    rows: list[Row] = []
    for path in _iter_rs_files(workspace, scan_roots):
        rel_norm = "/" + path.relative_to(workspace).as_posix()
        if not any(tok in rel_norm for tok in CONSENSUS_PATH_TOKENS):
            continue
        text = _mask_cfg_test_modules(path.read_text(encoding="utf-8", errors="ignore"))

        for m in TRUNCATION_RE.finditer(text):
            window = _body_window(text, m.start())
            if _has_visible_cap(window):
                continue
            _add_row(
                rows,
                workspace=workspace,
                path=path,
                text=text,
                pos=m.start(),
                pattern_id="swival_integer_len_truncation",
                family="integer_overflow_or_underflow_or_truncation",
                impact=(
                    "candidate only: possible consensus/parser divergence if a "
                    "large protocol length/index truncates before validation"
                ),
                harness=(
                    "Build a boundary-value decode fixture with u64/u128 > "
                    "usize::MAX or protocol MAX and compare accept/reject "
                    "against the reference client/model."
                ),
                kill=(
                    "Kill if the value is protocol-bounded before conversion, "
                    "the conversion is unreachable on supported targets, or "
                    "no consensus/network input controls it."
                ),
            )

        for m in LEN_ALLOC_RE.finditer(text):
            window = _body_window(text, m.start())
            if _has_visible_cap(window):
                continue
            _add_row(
                rows,
                workspace=workspace,
                path=path,
                text=text,
                pos=m.start(),
                pattern_id="swival_len_prefixed_alloc_no_cap",
                family="size_or_length_or_index_validation_gap",
                impact=(
                    "candidate only: possible resource or liveness impact from "
                    "length-prefixed allocation before a protocol cap"
                ),
                harness=(
                    "Create malformed length-prefix input at cap+1 and huge "
                    "boundary values; assert bounded error before allocation."
                ),
                kill=(
                    "Kill if a max message/batch/body cap is enforced before "
                    "allocation or if the length is internally generated."
                ),
            )

        for m in DECODE_FN_RE.finditer(text):
            window = _body_window(text, m.start(), span=1800)
            if GUARD_RE.search(window):
                continue
            _add_row(
                rows,
                workspace=workspace,
                path=path,
                text=text,
                pos=m.start(),
                pattern_id="swival_decode_without_visible_guard",
                family="cfg_or_target_feature_or_capability_skip",
                impact=(
                    "candidate only: possible unversioned decode path that "
                    "accepts data without visible fork/capability/schema guard"
                ),
                harness=(
                    "Feed old/new/future tagged payloads through the decode "
                    "function and assert unsupported versions fail closed."
                ),
                kill=(
                    "Kill if the caller performs the version/fork/capability "
                    "check before this decode function or the format is "
                    "intentionally unversioned and fixed-size."
                ),
            )

        for m in UNSAFE_LEN_PTR_RE.finditer(text):
            window = _body_window(text, m.start(), span=1000)
            if "unsafe" not in window:
                continue
            _add_row(
                rows,
                workspace=workspace,
                path=path,
                text=text,
                pos=m.start(),
                pattern_id="swival_unsafe_len_pointer_primitive",
                family="use_after_free_or_uninit_or_layout_unsoundness",
                impact=(
                    "candidate only: possible memory-safety or parser-safety "
                    "issue if unsafe length/pointer primitive is reachable from "
                    "network, consensus, proof, or attestation input"
                ),
                harness=(
                    "Build a minimal malformed input around the unsafe call and "
                    "assert it returns a bounded error rather than UB, panic, or "
                    "process abort. Include Miri/ASAN only as extra evidence."
                ),
                kill=(
                    "Kill if the unsafe primitive is test-only, length is fixed "
                    "by construction, pointer is non-null and initialized by a "
                    "trusted allocator, or no attacker-controlled input reaches it."
                ),
            )

        for m in ATOMIC_RELAXED_RE.finditer(text):
            window = _body_window(text, m.start(), span=1200)
            if not STATE_TOKEN_RE.search(window):
                continue
            # Keep metrics-only relaxed atomics out of the high-signal queue.
            if METRIC_ONLY_RE.search(window) and not re.search(
                r"\b(head|block|timestamp|running|ready|valid|finali[sz]ed|safe|unsafe)\b",
                window,
                re.IGNORECASE,
            ):
                continue
            _add_row(
                rows,
                workspace=workspace,
                path=path,
                text=text,
                pos=m.start(),
                pattern_id="swival_relaxed_atomic_state_transition",
                family="atomic_or_ordering_or_concurrency_hazard",
                impact=(
                    "candidate only: possible stale or reordered state transition "
                    "if Relaxed atomic access guards consensus, proof, txpool, or "
                    "liveness state"
                ),
                harness=(
                    "Build a two-task interleaving test around the state token and "
                    "assert stale reads cannot change validation, proof, or liveness "
                    "decisions. Loom/shuttle is useful but not required."
                ),
                kill=(
                    "Kill if the atomic is metrics-only, debug-only, monotonic and "
                    "stale-tolerant by documented design, or paired with an Acquire/"
                    "Release edge on the actual decision path."
                ),
            )

    # Stable de-dupe by pattern/file/line/function.
    seen: set[tuple[str, str, int, str]] = set()
    out: list[Row] = []
    for row in rows:
        key = (row.pattern_id, row.file, row.line, row.function)
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def _write_markdown(path: Path, rows: list[Row]) -> None:
    lines = [
        "# Base Rust Swival-Shape Scan",
        "",
        f"Rows: **{len(rows)}**",
        "",
        "| Pattern | File | Function | Line | Posture | Severity |",
        "|---|---|---:|---:|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| `{r.pattern_id}` | `{r.file}` | `{r.function}` | {r.line} | `{r.submission_posture}` | `{r.severity}` |"
        )
    lines.append("")
    lines.append(
        "All rows are detector/harness-task candidates only. A row requires an "
        "`impact_contract` selecting one exact program impact sentence before "
        "harness, PoC, severity, or finding language."
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument(
        "--scan-root",
        action="append",
        default=None,
        help="Relative scan root; repeatable. Defaults to Base Rust roots.",
    )
    parser.add_argument("--print-json", action="store_true")
    parser.add_argument("--out-json", type=Path, default=None)
    parser.add_argument("--out-md", type=Path, default=None)
    parser.add_argument("--strict", action="store_true")
    parser.add_argument(
        "--unsafe-impl-axis",
        action="store_true",
        help=(
            "Advisory unsafe-soundness axis (OFF by default; also enabled by "
            f"{UNSAFE_IMPL_AXIS_ENV}=1). Emits needs-fuzz hypotheses."
        ),
    )
    parser.add_argument("--out-unsafe-impl-jsonl", type=Path, default=None)
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[base-rust-swival-shape-scan] ERR workspace not found: {workspace}", file=sys.stderr)
        return 2

    scan_roots = args.scan_root or rust_crate_scan_roots(workspace, DEFAULT_SCAN_ROOTS)
    rows = scan_workspace(workspace, scan_roots)
    payload = {
        "schema": SCHEMA_VERSION,
        "workspace": str(workspace),
        "row_count": len(rows),
        "rows": [asdict(r) for r in rows],
    }

    default_dir = workspace / "critical_hunt" / "swival_shape_scan"
    default_dir.mkdir(parents=True, exist_ok=True)
    out_json = args.out_json or (default_dir / "base_rust_swival_shape_scan.json")
    out_md = args.out_md or (default_dir / "base_rust_swival_shape_scan.md")
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_markdown(out_md, rows)

    run_unsafe_axis = args.unsafe_impl_axis or os.environ.get(UNSAFE_IMPL_AXIS_ENV) == "1"
    unsafe_hyps: list[dict] = []
    if run_unsafe_axis:
        unsafe_hyps = scan_unsafe_impl_send_sync(workspace, scan_roots)
        out_hyp = args.out_unsafe_impl_jsonl or (
            default_dir / "unsafe_impl_send_sync_hypotheses.jsonl"
        )
        out_hyp.write_text(
            "".join(json.dumps(h, sort_keys=True) + "\n" for h in unsafe_hyps),
            encoding="utf-8",
        )

    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"[base-rust-swival-shape-scan] wrote {out_json}")
        print(f"[base-rust-swival-shape-scan] wrote {out_md}")
        print(f"[base-rust-swival-shape-scan] {len(rows)} candidate row(s)")
        if run_unsafe_axis:
            print(
                "[base-rust-swival-shape-scan] unsafe-impl axis: "
                f"{len(unsafe_hyps)} needs-fuzz hypothesis(es)"
            )

    return 1 if args.strict and rows else 0


if __name__ == "__main__":
    raise SystemExit(main())
