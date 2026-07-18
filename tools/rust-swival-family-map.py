#!/usr/bin/env python3
"""Cluster Swival Rust stdlib rows into implementation-ready family queues.

This tool emits advisory mining artifacts only. It does not prove a Base,
Rust/DLT, or project vulnerability. Rows remain implementation tasks until a
separate project-bound proof/replay/invariant demonstrates impact.
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


SCHEMA = "auditooor.rust_swival_family_map.v1"
DEFAULT_OUT_DIR = Path(".audit_logs") / "rust_corpus_mining"
DEFAULT_INDEX = DEFAULT_OUT_DIR / "rust_corpus_index.json"
DEFAULT_TASKS = DEFAULT_OUT_DIR / "rust_corpus_fixture_tasks.json"
EXPECTED_TOTAL = 151
EXPECTED_SEVERITIES = {"High": 27, "Medium": 115, "Low": 9}


@dataclass(frozen=True)
class FamilyDef:
    family_id: str
    title: str
    regex: re.Pattern[str]
    predicate: str
    mining_value: str
    static_detector: bool
    invariant: bool
    replay: bool
    runtime_blocker: bool
    detector_task: str
    invariant_task: str
    replay_task: str
    blocker_task: str


@dataclass(frozen=True)
class Item:
    item_id: str
    title: str
    corpus_severity: str
    component: str
    source_family: str
    task_id: str
    task_kind: str
    assigned_family: str
    source_pointers: list[str]
    writeup_pointers: list[str]
    proof_status: str
    submission_posture: str


FAMILIES: list[FamilyDef] = [
    FamilyDef(
        "path_filesystem_canonicalization",
        "Path and filesystem canonicalization escapes",
        re.compile(r"\b(tar|remove.dir|dot.entries|path|pathname|chdir|nul|terminal.name|directory|file.name|reparse)\b", re.I),
        "Attacker-controlled path/name bytes cross a filesystem boundary before dot-entry, NUL, traversal, reparse, or canonicalization constraints are enforced.",
        "Rust services, node CLIs, archive importers, relayers, and operator tooling that unpack or canonicalize user/operator paths.",
        True,
        True,
        True,
        False,
        "Implement a Rust detector for archive extraction, path joins, terminal-name paths, and C/Windows path conversions that lack canonicalization or NUL rejection before the filesystem boundary.",
        "Add fixture-pair invariants proving sanitized path components cannot escape the intended root and cannot truncate at interior NUL bytes.",
        "Replay malicious archive entries, dot entries, drive-only paths, and interior-NUL names in hermetic Rust fixtures.",
        "Block Base/DLT promotion when the only affected path is host/test tooling with no project runtime or operator-impact path.",
    ),
    FamilyDef(
        "buffer_io_accounting_mismatch",
        "I/O buffer accounting mismatches",
        re.compile(r"\b(read|write|vectored|flush|sink|copied|uncopied|excess|receive|send|count|bufwriter|cursor)\b", re.I),
        "A read/write API reports or sums byte counts that can diverge from the actual copied buffer length or per-iovec capacity.",
        "Rust RPC, mempool, p2p, database, precompile host glue, and replay-log code where byte-count divergence can corrupt framing or gas/state accounting.",
        True,
        True,
        True,
        True,
        "Build a detector for read/write/vectored count arithmetic that lacks checked_add, min(buffer.len), or post-copy equality checks.",
        "Add properties that returned byte counts never exceed source/destination capacity and empty vectors cannot bypass accounting.",
        "Replay short-read, short-write, empty-iovec, oversized-count, and partial-copy cases against fixture pairs.",
        "Require runtime semantic adjudication when byte counts feed gas, receipts, state roots, consensus logs, or persistent replay output.",
    ),
    FamilyDef(
        "parser_format_table_bounds",
        "Parser, format, and table bounds failures",
        re.compile(r"\b(exponent|mantissa|leb128|uleb128|sleb128|uleb|sleb|xml|json|auxv|hwcap|string.table|terminfo|dns|parse|parser|decode|division|modulo)\b", re.I),
        "A decoder, serializer, or table lookup trusts encoded length, shift, delimiter, index, or divisor fields before proving they are in range.",
        "Rust/DLT wire formats, trie/proof codecs, transaction envelopes, RPC JSON, receipt logs, and VM instruction decoders.",
        True,
        True,
        True,
        True,
        "Implement parser-bound detectors for unchecked shift/length/index/divisor use after decoding untrusted fields.",
        "Add malformed-input invariants for truncated tables, overlong LEB128, zero divisors, and unescaped serialized attributes.",
        "Generate corpus replay cases for malformed codecs and compare fixed/vulnerable behavior without project-impact claims.",
        "Block DLT promotion until malformed input is accepted on a production path and affects consensus, funds, liveness, or durable state.",
    ),
    FamilyDef(
        "unsafe_pointer_reference_boundary",
        "Unsafe pointer, reference, and slice boundary violations",
        re.compile(r"\b(pointer|reference|slice|from.raw.parts|raw|deref|userspace|enclave|lsda|instruction.pointer|self.referential|global.pointer|argv|argc|abi)\b", re.I),
        "Unsafe code constructs references, slices, function pointers, or self-referential structures from untrusted/movable memory without proving provenance, aliasing, length, or lifetime.",
        "Unsafe Rust host functions, VM imports, enclave/TEE bridges, syscall shims, and runtime adapters with external memory views.",
        True,
        True,
        True,
        True,
        "Add detectors for from_raw_parts, raw pointer deref, static slice creation, and ABI pointer arithmetic without checked provenance/length gates.",
        "Create Miri-ready fixture pairs for aliasing, null pointer, movable self-reference, and externally mutable slice cases.",
        "Replay crafted external-memory or ABI inputs in isolated fixtures before impact framing.",
        "Require runtime blocker evidence when VM/enclave/userspace memory semantics are not captured by static matching.",
    ),
    FamilyDef(
        "allocation_layout_realloc_boundary",
        "Allocation layout and realloc boundary failures",
        re.compile(r"\b(realloc|allocation|layout|alignment|memalign|undersized.buffer|zero.new.size|capacity|vec.length|set.vec.length)\b", re.I),
        "Allocation, deallocation, or Vec length mutation uses a layout/size/alignment value not proven equivalent to the original allocation contract.",
        "Rust allocators, custom arenas, host memory managers, database pages, VM heaps, and precompile scratch buffers.",
        True,
        True,
        True,
        True,
        "Build detectors for Layout::from_size_align unchecked paths, realloc on mismatched predicates, and set_len after stale/attacker-controlled counts.",
        "Add allocator invariants for size/alignment round trips, zero-size realloc behavior, and Vec length never exceeding initialized capacity.",
        "Replay allocation edge cases with sanitizers or Miri where possible.",
        "Block promotion when behavior depends on target-specific allocators, VM memory model, or FFI allocation ownership.",
    ),
    FamilyDef(
        "concurrency_lock_atomic_state",
        "Concurrency, lock, and atomic state invariants",
        re.compile(r"\b(race|atomic|mutex|lock|wait|waiter|notify|contended|spin|synchronization|poison|relaxed|ordering|thread|tls)\b", re.I),
        "A concurrent transition omits acquire/release, poison, rollback, waiter, or lock-state invariants after error or contended paths.",
        "Rust node runtimes, async services, mempool workers, database caches, sequencers, and relayers.",
        False,
        True,
        True,
        True,
        "Use static matching only as a candidate finder for suspicious Ordering::Relaxed, lock error paths, and waiter counter changes.",
        "Write Loom/proptest invariants for waiter counts, lock ownership after errors, acquire synchronization, and no lost notification.",
        "Create deterministic scheduler/Loom replays before mining live runtime impact.",
        "Require runtime semantic blocker evidence until the race is reproducible or model-checked.",
    ),
    FamilyDef(
        "os_handle_descriptor_lifecycle",
        "OS handle, descriptor, and process lifecycle leaks",
        re.compile(r"\b(handle|fd|descriptor|stdio|stdin|stdout|stderr|pidfd|child|listener|socket.clone|orphan|leak|rollback|environment)\b", re.I),
        "Error, clone, callback, or rebinding paths fail to restore or close OS/process resources before inheritance, leakage, or incorrect reuse.",
        "Rust daemons, operator tooling, signer processes, relayers, subprocess managers, and node launchers.",
        True,
        True,
        True,
        False,
        "Add detectors for early returns after open/dup/spawn/redirect without close/rollback and clone paths that skip descriptor isolation.",
        "Add resource lifecycle tests asserting descriptors/env/stdio are restored after every error branch.",
        "Replay failing spawn, callback, accept, and redirect branches with descriptor counting instrumentation.",
        "Block Base/DLT promotion unless leaked resource control crosses a project runtime, signer, relayer, or operator security boundary.",
    ),
    FamilyDef(
        "codegen_build_argument_injection",
        "Codegen, build, and argument injection",
        re.compile(r"\b(cargo|rustflags|generated|identifier|argument.injection|directive.injection|remote.git|download|compiler.rt|linker|intrinsic.name|library.filename|unescaped)\b", re.I),
        "Build/codegen surfaces interpolate untrusted names, flags, filenames, remotes, or messages without escaping, pinning, or argument-boundary enforcement.",
        "Rust build scripts, prover/verifier code generation, generated bindings, plugin systems, and release pipelines.",
        True,
        True,
        True,
        False,
        "Implement detectors for println!(cargo:...), RUSTFLAGS/linker construction, generated identifiers, and unpinned remote fetches from mutable inputs.",
        "Add fixture pairs proving arguments remain atomic and generated names/messages are escaped.",
        "Replay malicious filenames, env vars, intrinsic names, and remote refs in isolated build fixtures.",
        "Block runtime vulnerability language unless the build/codegen path is in scope and reachable by a non-privileged actor.",
    ),
    FamilyDef(
        "platform_cpu_simd_precondition",
        "Platform, CPU, and SIMD precondition drift",
        re.compile(r"\b(cpuid|rdrand|avx|simd|vsx|svld|svst|vnum|firmware|uefi|target.feature|immediate|subword|rcpc)\b", re.I),
        "Platform-specific code assumes CPU feature, vector lane, firmware, or instruction preconditions that are not checked on every target-specific path.",
        "Rust cryptography, VM accelerators, precompile implementations, and architecture-specific node optimizations.",
        True,
        True,
        True,
        True,
        "Add target-feature detectors for unsafe arch intrinsics, vector lane indices, vnum offsets, and CPU feature gates missing runtime/cfg guards.",
        "Create cross-target fixture plans comparing scalar and accelerated semantics for edge lanes and unsupported feature combinations.",
        "Replay under target/cfg emulation or compile-only matrices.",
        "Require runtime blocker evidence for architecture availability, build flags, and production deployment targets before Base impact claims.",
    ),
    FamilyDef(
        "runtime_unwind_stack_control_flow",
        "Runtime unwind, stack, and control-flow metadata",
        re.compile(r"\b(unwind|alternate.stack|stack|call.site|call-site|frame.pointer|instruction.pointer|lsda|resume|abort|recursive.tls)\b", re.I),
        "Unwind, stack mapping, TLS, or exception metadata is trusted across control-flow boundaries without preserving abort, bounds, or pointer-validity invariants.",
        "Rust runtimes, WASM/VM hosts, FFI exception bridges, enclave runtimes, and panic/unwind adapters.",
        False,
        True,
        True,
        True,
        "Use static scans as triage for unwind/stack/TLS metadata but require semantic review before detector promotion.",
        "Add panic/unwind/TLS invariants asserting no invalid pointer, skipped abort, or active alternate-stack unmap reaches safe APIs.",
        "Replay panic/unwind and metadata corruption cases in hermetic fixtures first.",
        "Require runtime blocker rows for target ABI, unwinder, and panic strategy before Base/DLT transfer.",
    ),
    FamilyDef(
        "numeric_edge_sentinel_boundary",
        "Numeric edge and sentinel boundary failures",
        re.compile(r"\b(overflow|underflow|truncat|usize|u64|u128|isize|i32|minimum|index|off.by.one|zero|empty|oversized|negative|clamp|nonzero|shift|parameter)\b", re.I),
        "An integer, index, sentinel, or empty-input edge is used before checked arithmetic or explicit zero/empty/min/max handling proves it safe.",
        "Broad Rust/DLT mining for gas, balances, limits, table indices, batch sizes, and protocol parameter decoding.",
        True,
        True,
        True,
        False,
        "Implement checked-arithmetic detectors for unchecked add/sub/mul/shift/cast/index/zero-divisor patterns on externally influenced values.",
        "Add boundary fixtures for min/max integers, empty slices, zero-sized chunks, zero divisors, and oversized protocol fields.",
        "Replay edge-value inputs against vulnerable/clean fixture pairs.",
        "Block promotion when no non-privileged project input controls the edge value.",
    ),
]

FALLBACK = FamilyDef(
    "manual_runtime_semantic_review",
    "Manual runtime semantic review",
    re.compile(r".*"),
    "The row needs source review before it can be reduced to a detector, invariant, or replay predicate.",
    "Holding lane only; split after source reading.",
    False,
    True,
    False,
    True,
    "Do not implement a static detector until concrete syntax/data-flow is known.",
    "Write a one-sentence invariant and move or kill the row with evidence.",
    "No replay until source review identifies a bounded input sequence.",
    "Keep as runtime semantic blocker until the predicate is known.",
)


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _rows(payload: Any, key: str) -> list[dict[str, Any]]:
    if isinstance(payload, dict) and isinstance(payload.get(key), list):
        return [row for row in payload[key] if isinstance(row, dict)]
    return []


def _list(value: Any) -> list[str]:
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return []


def _component(value: Any) -> str:
    text = re.sub(r"[^a-z0-9]+", "_", str(value or "unknown").lower()).strip("_")
    if not text or text.endswith("_md"):
        return "unknown"
    return text[:80]


def _task_lookup(payload: Any) -> dict[str, dict[str, Any]]:
    return {str(r.get("source_item_id")): r for r in _rows(payload, "tasks") if r.get("source_item_id")}


def _family(record: dict[str, Any]) -> FamilyDef:
    hay = " ".join(str(record.get(k) or "") for k in ("item_id", "title", "family", "category", "rel_path"))
    for family in FAMILIES:
        if family.regex.search(hay):
            return family
    return FALLBACK


def _count(rows: Iterable[Item], attr: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in rows:
        key = str(getattr(row, attr))
        out[key] = out.get(key, 0) + 1
    return dict(sorted(out.items()))


def _defs() -> dict[str, FamilyDef]:
    return {f.family_id: f for f in [*FAMILIES, FALLBACK]}


def _queue_task(family: dict[str, Any], lane: str, definition: FamilyDef, priority: int) -> dict[str, Any]:
    if lane == "detector":
        task = definition.detector_task
        suitable = definition.static_detector
    elif lane == "invariant":
        task = definition.invariant_task
        suitable = definition.invariant
    elif lane == "replay":
        task = definition.replay_task
        suitable = definition.replay
    else:
        task = definition.blocker_task
        suitable = definition.runtime_blocker
    return {
        "queue_id": f"swival-{lane}-{priority:02d}-{family['family_id']}",
        "family_id": family["family_id"],
        "priority": priority,
        "count": family["count"],
        "severity_distribution": family["severity_distribution"],
        "affected_components": family["affected_components"],
        "root_cause_predicate": family["root_cause_predicate"],
        "suitable": suitable,
        "task": task,
        "fixture_task_ids": [item["task_id"] for item in family["items"] if item["task_id"]],
        "source_item_ids": [item["item_id"] for item in family["items"]],
        "validation": "must add vulnerable and clean fixture coverage plus no-proof/no-submit posture checks",
    }


def build_payload(workspace: Path, index_path: Path, task_path: Path | None, expected_total: int = EXPECTED_TOTAL) -> dict[str, Any]:
    records = _rows(_read_json(index_path), "records")
    tasks = _task_lookup(_read_json(task_path) if task_path else None)
    items: list[Item] = []
    for record in records:
        item_id = str(record.get("item_id") or record.get("id") or "").strip()
        if not item_id:
            continue
        task = tasks.get(item_id, {})
        family = _family(record)
        items.append(
            Item(
                item_id=item_id,
                title=str(record.get("title") or item_id).strip(),
                corpus_severity=str(record.get("corpus_severity") or "unknown").strip(),
                component=_component(record.get("component")),
                source_family=str(record.get("family") or record.get("category") or "unknown").strip(),
                task_id=str(task.get("task_id") or ""),
                task_kind=str(task.get("task_kind") or "fixture_pair_task").strip(),
                assigned_family=family.family_id,
                source_pointers=_list(record.get("source_pointers")) or _list(record.get("rel_path")),
                writeup_pointers=_list(task.get("writeup_pointers")),
                proof_status=str(task.get("proof_status") or "not_proved"),
                submission_posture=str(record.get("submission_posture") or task.get("submission_posture") or "NOT_SUBMIT_READY"),
            )
        )
    grouped: dict[str, list[Item]] = {}
    for item in sorted(items, key=lambda r: (r.assigned_family, r.item_id)):
        grouped.setdefault(item.assigned_family, []).append(item)
    defs = _defs()
    families: list[dict[str, Any]] = []
    for family_id, rows in sorted(grouped.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        d = defs.get(family_id, FALLBACK)
        families.append(
            {
                "family_id": family_id,
                "title": d.title,
                "count": len(rows),
                "root_cause_predicate": d.predicate,
                "mining_value": d.mining_value,
                "affected_components": _count(rows, "component"),
                "severity_distribution": _count(rows, "corpus_severity"),
                "task_kind_distribution": _count(rows, "task_kind"),
                "suitability": {
                    "static_detector": d.static_detector,
                    "invariant": d.invariant,
                    "replay": d.replay,
                    "runtime_semantic_blocker": d.runtime_blocker,
                },
                "exact_next_implementation_tasks": [d.detector_task, d.invariant_task, d.replay_task, d.blocker_task],
                "items": [asdict(row) for row in rows],
            }
        )
    queues = {"detector": [], "invariant": [], "replay": [], "runtime_semantic_blocker": []}
    for priority, family in enumerate(families, 1):
        d = defs.get(family["family_id"], FALLBACK)
        if d.static_detector:
            queues["detector"].append(_queue_task(family, "detector", d, priority))
        if d.invariant:
            queues["invariant"].append(_queue_task(family, "invariant", d, priority))
        if d.replay:
            queues["replay"].append(_queue_task(family, "replay", d, priority))
        if d.runtime_blocker:
            queues["runtime_semantic_blocker"].append(_queue_task(family, "runtime-semantic-blocker", d, priority))
    blockers: list[dict[str, Any]] = []
    if len(items) != expected_total:
        blockers.append(
            {
                "blocker_id": "swival-family-map-incomplete-coverage",
                "expected_total": expected_total,
                "observed_total": len(items),
                "why_not_closed": "family map must preserve every validated Swival rust-stdlib finding",
                "next_commands": ["rerun rust-corpus-ingest and rust-corpus-fixture-tasks from the validated 151-row corpus"],
            }
        )
    summary = {
        "source_index": str(index_path),
        "source_fixture_tasks": str(task_path) if task_path else "",
        "source_item_count": len(items),
        "expected_swival_rust_stdlib_total": expected_total,
        "coverage_complete_for_expected_swival_total": len(items) == expected_total,
        "expected_swival_severities": EXPECTED_SEVERITIES,
        "severity_distribution": _count(items, "corpus_severity"),
        "family_count": len(families),
        "top_recurring_root_cause_predicates": [
            {"family_id": f["family_id"], "count": f["count"], "predicate": f["root_cause_predicate"]}
            for f in families[:8]
        ],
        "top_families": [{"family_id": f["family_id"], "count": f["count"]} for f in families[:8]],
        "fixture_pair_task_count": sum(1 for row in items if row.task_kind == "fixture_pair_task"),
        "replay_task_count": sum(1 for row in items if row.task_kind == "replay_task"),
        "queue_counts": {key: len(value) for key, value in queues.items()},
        "cross_linked_fixture_task_count": sum(1 for row in items if row.task_id),
        "proof_claims": 0,
        "base_vulnerability_proof_claimed": False,
        "submission_ready_count": sum(1 for row in items if row.submission_posture != "NOT_SUBMIT_READY"),
        "blocker_count": len(blockers),
    }
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "workspace": str(workspace),
        "summary": summary,
        "blockers": blockers,
        "families": families,
        "implementation_queues": queues,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    s = payload["summary"]
    lines = [
        "# Swival Rust Stdlib Family Map",
        "",
        f"_Schema: `{payload['schema']}`_",
        "",
        "Advisory mining map only. This does not claim Base vulnerability proof, exploitability, severity, or submission readiness.",
        "",
        "## Counts",
        "",
        f"- source rows clustered: `{s['source_item_count']}`",
        f"- expected Swival rust-stdlib rows: `{s['expected_swival_rust_stdlib_total']}`",
        f"- complete for expected total: `{s['coverage_complete_for_expected_swival_total']}`",
        f"- severity distribution: `{s['severity_distribution']}`",
        f"- family count: `{s['family_count']}`",
        f"- fixture-pair tasks: `{s['fixture_pair_task_count']}`",
        f"- replay tasks: `{s['replay_task_count']}`",
        f"- cross-linked fixture tasks: `{s['cross_linked_fixture_task_count']}`",
        f"- queue counts: `{s['queue_counts']}`",
        f"- proof claims: `{s['proof_claims']}`",
        f"- Base vulnerability proof claimed: `{s['base_vulnerability_proof_claimed']}`",
        f"- submission-ready rows: `{s['submission_ready_count']}`",
        "",
        "## Top Recurring Root-Cause Predicates",
        "",
    ]
    for row in s["top_recurring_root_cause_predicates"]:
        lines.append(f"- `{row['family_id']}` (`{row['count']}`): {row['predicate']}")
    lines.extend(["", "## Family Summary", ""])
    lines.append("| Family | Count | Severity | Components | Suitable For |")
    lines.append("|---|---:|---|---|---|")
    for f in payload["families"]:
        suitable = ", ".join(k for k, v in f["suitability"].items() if v)
        lines.append(f"| `{f['family_id']}` | {f['count']} | `{f['severity_distribution']}` | `{f['affected_components']}` | {suitable or 'manual'} |")
    lines.extend(["", "## Implementation Queues", ""])
    for lane, rows in payload["implementation_queues"].items():
        lines.extend([f"### {lane}", ""])
        if not rows:
            lines.append("_No rows._")
            lines.append("")
            continue
        for row in rows:
            lines.append(f"- `{row['queue_id']}`: {row['task']}")
            lines.append(f"  Fixture tasks: `{len(row['fixture_task_ids'])}`; source items: `{len(row['source_item_ids'])}`; validation: {row['validation']}")
        lines.append("")
    lines.extend(["## Family Details", ""])
    for f in payload["families"]:
        lines.extend([
            f"### {f['title']}",
            "",
            f"- family id: `{f['family_id']}`",
            f"- count: `{f['count']}`",
            f"- root-cause predicate: {f['root_cause_predicate']}",
            f"- mining value: {f['mining_value']}",
            f"- severity distribution: `{f['severity_distribution']}`",
            f"- affected components: `{f['affected_components']}`",
            f"- task kinds: `{f['task_kind_distribution']}`",
            f"- suitability: `{f['suitability']}`",
            "",
            "Exact next implementation tasks:",
            "",
        ])
        for task in f["exact_next_implementation_tasks"]:
            lines.append(f"- {task}")
        lines.extend(["", "Representative rows:"])
        for item in f["items"][:12]:
            task_ref = f", task `{item['task_id']}`" if item["task_id"] else ""
            lines.append(f"- `{item['item_id']}` ({item['corpus_severity']}, `{item['component']}`{task_ref}): {item['title']}")
        if f["count"] > 12:
            lines.append(f"- ... `{f['count'] - 12}` more rows in JSON")
        lines.append("")
    if payload["blockers"]:
        lines.extend(["## Blockers", ""])
        for b in payload["blockers"]:
            lines.append(f"- `{b['blocker_id']}`: {b['why_not_closed']}")
    return "\n".join(lines)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--workspace", type=Path, default=Path.cwd())
    p.add_argument("--index", type=Path)
    p.add_argument("--fixture-tasks", type=Path)
    p.add_argument("--out-dir", type=Path)
    p.add_argument("--expected-total", type=int, default=EXPECTED_TOTAL)
    p.add_argument("--print-json", action="store_true")
    return p.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    ws = args.workspace.expanduser().resolve()
    index = (args.index or (ws / DEFAULT_INDEX)).expanduser().resolve()
    tasks = (args.fixture_tasks or (ws / DEFAULT_TASKS)).expanduser().resolve()
    payload = build_payload(ws, index, tasks if tasks.is_file() else None, args.expected_total)
    out_dir = (args.out_dir or (ws / DEFAULT_OUT_DIR)).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    out_json = out_dir / "rust_swival_family_map.json"
    out_md = out_dir / "rust_swival_family_map.md"
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    out_json.write_text(text, encoding="utf-8")
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    aud = ws / ".auditooor"
    if aud.is_dir():
        (aud / "rust_swival_family_map.json").write_text(text, encoding="utf-8")
        (aud / "rust_swival_family_map.md").write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps({"summary": payload["summary"], "blockers": payload["blockers"]}, indent=2, sort_keys=True))
    else:
        print(f"[rust-swival-family-map] wrote {out_json}")
        print(f"[rust-swival-family-map] rows={payload['summary']['source_item_count']} families={payload['summary']['family_count']} queues={payload['summary']['queue_counts']}")
    return 0 if not payload["blockers"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
