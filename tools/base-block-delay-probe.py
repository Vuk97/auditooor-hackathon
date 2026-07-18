#!/usr/bin/env python3
"""Base A6 block-delay candidate probe (PR #546 Wave 10 / Lane H).

Scope: Blockchain/DLT impact rubric A6 — "Temporary freezing of network
transactions by delaying block validation/production by 500% or more"
(threshold: 10s+ on a Base block-time of 2s).

Lane G (Wave 9) flagged A6 as **zero-coverage**: ``flashblocks/`` has no
upstream peer and no pre-existing latency-injection harness exists for the
Base node code. This probe is the first scanner to surface candidate
validation paths whose CPU/IO cost can plausibly scale with attacker
controlled input — i.e. proof verification, trie traversal, payload
decoding, or RPC handlers. The probe is grep-grade and **advisory**: it
emits candidate rows compatible with ``base-critical-candidate-matrix.py``
that downstream agents can use as benchmark seeds.

The companion artifact lives at::

    <ws>/critical_hunt/block_delay/
      a6_block_delay_results.md          # this scanner's plan + scan output
      expected_thresholds.md             # Base block-time + A6 rubric
      harness/
        Cargo.toml                        # operator-driven scaffold
        benches/block_delay.rs            # bench template (NOT auto-run)

The benchmark scaffold is **operator-driven**: CI never runs the Cargo
harness. Only the operator runs the actual Criterion benchmarks against
real upstream code (paid by `path = ...` deps in the harness Cargo.toml).

Hard rules:
  * Stdlib-only Python.
  * Probe is offline-safe. It only reads files; it never compiles or
    executes Rust.
  * Threshold = 10s (= 5x Base 2s block-time) per the A6 rubric.
  * Default-to-flag-only: every emitted row goes through
    ``base-critical-candidate-matrix.py`` decide_status() before any
    Critical claim is honored. The probe never claims Critical itself.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.base_block_delay_probe.v1"

# A6 rubric constants (Base Blockchain/DLT). Source:
# docs/CLAUDE_BASE_CRITICAL_HUNT_CONTINUATION_PLAN_2026-04-30.md and the
# Base Immunefi rubric.
BASE_BLOCK_TIME_SECONDS = 2.0
A6_THRESHOLD_RATIO = 5.0  # 500% delay threshold per program rubric.
A6_THRESHOLD_SECONDS = BASE_BLOCK_TIME_SECONDS * A6_THRESHOLD_RATIO  # 10s.

# Patterns: each entry is (pattern_id, regex, attacker_input_hint,
# baseline_op, hypothesized_scaling). All regexes are stdlib `re`.
#
# These are deliberately conservative — every pattern targets a specific
# code shape that has historically been a delay/DoS source in EL/CL
# stacks. False positives are expected; downstream candidate-matrix
# filtering kills anything without a rubric-grounded impact.
SCAN_PATTERNS: list[dict[str, Any]] = [
    {
        "pattern_id": "unbounded_payload_decode",
        # Decoding a Vec<u8>/Bytes/&[u8] in a loop without a length cap
        # against the same input field. Matches `for _ in 0..n {` or
        # `while ... { ... decode ... }` body shapes.
        "regex": re.compile(
            r"\bfor\s+\w+\s+in\s+0\.\.(?:[a-zA-Z_][\w\.]*\.len\(\)|"
            r"[a-zA-Z_][\w\.]*)\s*\{[^{}]*?\b(?:decode|deserialize|"
            r"from_bytes|read_)[a-zA-Z_]*\s*\(",
            re.DOTALL,
        ),
        "attacker_input_hint": (
            "Vec<u8> / &[u8] payload field passed in via "
            "engine_newPayload, RPC eth_call, or tx data."
        ),
        "baseline_op": "single decode() call (~10-50us amortized)",
        "hypothesized_scaling": (
            "O(N) decode where N is attacker-chosen; a 10MB payload at "
            "1us/byte = 10s, hitting the A6 threshold."
        ),
    },
    {
        "pattern_id": "recursive_proof_verification",
        # Recursive call inside a function whose name hints at proof /
        # verify / merkle. Detects `fn verify_*` body that calls itself
        # OR a *_recursive helper.
        "regex": re.compile(
            r"\bfn\s+(verify|prove|check_proof|merkle)[a-zA-Z_]*\s*"
            r"<?[^>]*>?\s*\([^)]*\)[^{]*\{[^}]*?\b(verify|prove|"
            r"check_proof|merkle)[a-zA-Z_]*_(?:recursive|inner|step)\s*\(",
            re.DOTALL,
        ),
        "attacker_input_hint": (
            "proof bytes / inclusion path / state proof — depth chosen "
            "by attacker via crafted block or RPC."
        ),
        "baseline_op": "single Poseidon/keccak hash + branch compare",
        "hypothesized_scaling": (
            "O(d) where d = proof depth; attacker can pad depth so "
            "verification time crosses 10s."
        ),
    },
    {
        "pattern_id": "expensive_trie_traversal",
        # state.iter() / trie.walk over an unbounded range with no
        # limit param. We require BOTH the iter symbol AND a hash/keccak
        # call inside the same loop body to filter out cheap iterators.
        "regex": re.compile(
            r"\b(?:state|trie|storage|account)\s*\.\s*"
            r"(?:iter|walk|range|all_keys|keys|values)\s*\([^)]*\)"
            r"[^{}]*?\.(?:for_each|map|filter|fold)\s*\([^{]*\{"
            r"[^{}]*?(?:keccak|hash|verify)",
            re.DOTALL,
        ),
        "attacker_input_hint": (
            "block touching state under attacker-controlled key range, "
            "or RPC scan over storage."
        ),
        "baseline_op": "single trie node lookup (~100us)",
        "hypothesized_scaling": (
            "O(K) where K = visited keys; attacker grows K via state "
            "growth or RPC range params."
        ),
    },
    {
        "pattern_id": "derivation_loop_no_bound",
        # Derivation/payload pipeline loop calling expensive op without
        # an explicit `if i > MAX || break` guard. Matches `loop { ...
        # decode_frame|process_batch|build_payload ... }` whose body
        # contains no `break` or `if .* > .*MAX`.
        "regex": re.compile(
            r"\bloop\s*\{(?:(?!\bbreak\b)(?!\bif\s+[^{}]*MAX)[\s\S])*?"
            r"\b(?:decode_frame|process_batch|build_payload|"
            r"derive_block|consume_channel)\s*\(",
            re.DOTALL,
        ),
        "attacker_input_hint": (
            "L1 batch / channel frame / payload attribute supplied by "
            "sequencer or attacker-built derivation input."
        ),
        "baseline_op": "single derivation step (~1ms per frame)",
        "hypothesized_scaling": (
            "O(F) where F = frame count; unbounded loop over a "
            "sequencer-crafted batch can stall block production."
        ),
    },
    {
        "pattern_id": "rpc_handler_unbounded_iter",
        # RPC handler (fn that takes self.<provider|state|client>) that
        # iterates a Vec<...> argument with no `if vec.len() > N` guard
        # before a hash/decode call.
        "regex": re.compile(
            r"\b(?:async\s+)?fn\s+(?:eth_|debug_|trace_|engine_)"
            r"[a-zA-Z_]+\s*<?[^>]*>?\s*\([^)]*Vec\s*<\s*"
            r"(?:u8|H256|B256|Bytes|Address)\s*>[^)]*\)[^{]*\{"
            r"(?:(?!if\s+[^{}]*\.len\(\)\s*>)[\s\S])*?"
            r"\b(?:keccak|decode|verify|hash)",
            re.DOTALL,
        ),
        "attacker_input_hint": (
            "RPC call payload (Vec<u8>, Vec<H256>, Vec<Address>) "
            "supplied by anonymous external client."
        ),
        "baseline_op": "single hash / decode call (~10us)",
        "hypothesized_scaling": (
            "O(N) RPC body where N is unbounded by Rust type alone; "
            "JSON-RPC framing typically allows multi-MB requests."
        ),
    },
]

# File extensions to scan and directories to skip.
RUST_EXTENSIONS = (".rs",)
SKIP_DIRS = {
    "target",
    ".git",
    "node_modules",
    "_archive",
    "_archived",
    "tests",  # most tests are bounded harnesses, not the real path
    "benches",
}


@dataclass
class Candidate:
    candidate_id: str
    pattern_id: str
    file: str
    line: int
    scope_asset: str
    attacker_input_hint: str
    baseline_op: str
    hypothesized_scaling: str
    impact_mapping: str = (
        "Temporary freezing of network transactions by delaying one block "
        "by 500% or more"
    )
    severity: str = "candidate"
    candidate_status: str = "needs_benchmark"
    required_proof: str = (
        "Run the Cargo benchmark harness under "
        "critical_hunt/block_delay/harness against this code path with a "
        "pessimistic attacker input. A6 threshold = 10s (>= 5x the 2s Base "
        "block time). Promote to executable only after operator records a "
        "real-component measurement >=10s in poc_execution/."
    )
    notes: list[str] = field(default_factory=list)
    snippet: str = ""

    def to_matrix_row(self) -> dict[str, Any]:
        """Shape compatible with base-critical-candidate-matrix.py."""
        return {
            "candidate_id": self.candidate_id,
            "scope_asset": self.scope_asset,
            "impact_mapping": self.impact_mapping,
            "production_path": f"{self.file}:{self.line}",
            "required_proof": self.required_proof,
            "severity": self.severity,
            "artifact_refs": [
                "critical_hunt/block_delay/a6_block_delay_results.md",
                "critical_hunt/block_delay/expected_thresholds.md",
            ],
            "notes": self.notes,
            "_a6_pattern_id": self.pattern_id,
            "_a6_attacker_input_hint": self.attacker_input_hint,
            "_a6_baseline_op": self.baseline_op,
            "_a6_hypothesized_scaling": self.hypothesized_scaling,
        }


# ---------------------------------------------------------------------------
# Filesystem walk
# ---------------------------------------------------------------------------


def _iter_rust_files(root: Path) -> list[Path]:
    """Walk ``root`` and return all .rs files outside skip dirs."""
    out: list[Path] = []
    if root.is_file() and root.suffix in RUST_EXTENSIONS:
        return [root]
    if not root.is_dir():
        return out
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in RUST_EXTENSIONS:
            continue
        parts = set(path.parts)
        if parts & SKIP_DIRS:
            continue
        out.append(path)
    return sorted(out)


def _line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _snippet(text: str, offset: int, max_len: int = 200) -> str:
    start = max(0, offset)
    end = min(len(text), offset + max_len)
    snippet = text[start:end].replace("\n", " ").replace("\r", " ")
    return re.sub(r"\s+", " ", snippet).strip()


def _scope_asset_for(path: Path, root: Path) -> str:
    """Best-effort: top-level crate dir under ``root``.

    Examples::

        root=/audits/base/external/base-execution-evm,
        path=/audits/base/external/base-execution-evm/crates/foo/src/lib.rs
        -> "base-execution-evm/crates/foo"
    """
    try:
        rel = path.relative_to(root)
    except ValueError:
        return path.name
    parts = rel.parts
    # Heuristic: keep the first crate-level slug (up to 3 path segments).
    if len(parts) >= 3:
        return "/".join(parts[:3])
    if len(parts) >= 1:
        return parts[0]
    return path.name


# ---------------------------------------------------------------------------
# Scanner core
# ---------------------------------------------------------------------------


def scan_file(path: Path, root: Path) -> list[Candidate]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
    scope_asset = _scope_asset_for(path, root)
    out: list[Candidate] = []
    for pat in SCAN_PATTERNS:
        for match in pat["regex"].finditer(text):
            offset = match.start()
            line = _line_for_offset(text, offset)
            cand_id = "a6:{pid}:{rel}:{line}".format(
                pid=pat["pattern_id"], rel=rel, line=line
            )
            out.append(
                Candidate(
                    candidate_id=cand_id,
                    pattern_id=pat["pattern_id"],
                    file=rel,
                    line=line,
                    scope_asset=scope_asset,
                    attacker_input_hint=pat["attacker_input_hint"],
                    baseline_op=pat["baseline_op"],
                    hypothesized_scaling=pat["hypothesized_scaling"],
                    notes=[
                        "advisory: grep-shape match; benchmark required to "
                        "promote out of needs_benchmark",
                    ],
                    snippet=_snippet(text, offset),
                )
            )
    return out


def scan_workspace(root: Path) -> list[Candidate]:
    """Scan a workspace root recursively for A6 candidates."""
    candidates: list[Candidate] = []
    for path in _iter_rust_files(root):
        candidates.extend(scan_file(path, root))
    # Stable order for idempotency.
    candidates.sort(key=lambda c: (c.file, c.line, c.pattern_id))
    return candidates


# ---------------------------------------------------------------------------
# Output rendering
# ---------------------------------------------------------------------------


def render_results_md(
    candidates: list[Candidate], scan_root: Path, workspace: Path
) -> str:
    lines: list[str] = []
    lines.append("# A6 Block-Delay Probe — Scan Results")
    lines.append("")
    lines.append(f"_Schema: `{SCHEMA_VERSION}`_")
    lines.append("")
    lines.append(
        "Probe target: Base Blockchain/DLT rubric A6 — "
        "_Temporary freezing of network transactions by delaying one block "
        "by 500% or more_."
    )
    lines.append("")
    lines.append(f"- Base block time: **{BASE_BLOCK_TIME_SECONDS}s**")
    lines.append(
        f"- A6 threshold: **{A6_THRESHOLD_SECONDS}s** "
        f"(= {A6_THRESHOLD_RATIO}x block time)"
    )
    lines.append(f"- Scan root: `{scan_root}`")
    lines.append(f"- Candidates emitted: **{len(candidates)}**")
    lines.append("")
    lines.append("## Benchmark plan")
    lines.append("")
    lines.append(
        "Each candidate below is **advisory** until the operator runs the "
        "Cargo benchmark scaffold under "
        "`critical_hunt/block_delay/harness/` against the real upstream "
        "crate (path-dep'd into the harness `Cargo.toml`). The harness is "
        "**not** auto-executed by CI — A6 confirmation is operator-driven."
    )
    lines.append("")
    lines.append("Workflow:")
    lines.append("")
    lines.append(
        "1. Pick a candidate row whose `pattern_id` matches a believable "
        "attacker-controlled input field."
    )
    lines.append(
        "2. Edit `harness/Cargo.toml` so its `path = \"...\"` deps point at "
        "the in-scope upstream Base node crate (e.g. "
        "`base-execution-evm`, `base-derive`, `flashblocks`)."
    )
    lines.append(
        "3. Replicate the candidate code path inside "
        "`harness/benches/block_delay.rs`, parametrize the attacker input, "
        "and run `cargo bench`."
    )
    lines.append(
        "4. Record the wall-clock measurement plus the input size that "
        f"produced it. Promote ONLY if the time crosses {A6_THRESHOLD_SECONDS}s "
        "for a believable on-chain payload size."
    )
    lines.append(
        "5. Write the execution_manifest.json into "
        "`<ws>/poc_execution/a6_block_delay/<candidate_id>/` and rerun "
        "`make base-critical-matrix WS=<ws>` to promote the row."
    )
    lines.append("")
    lines.append("## Candidates")
    lines.append("")
    if not candidates:
        lines.append("_No A6 candidates found._")
        return "\n".join(lines) + "\n"
    lines.append(
        "| candidate_id | pattern_id | file:line | scope_asset | "
        "attacker_input | baseline_op | hypothesized_scaling |"
    )
    lines.append("|---|---|---|---|---|---|---|")
    for cand in candidates:
        lines.append(
            "| `{cid}` | `{pid}` | `{file}:{line}` | {asset} | {input} "
            "| {base} | {scale} |".format(
                cid=cand.candidate_id,
                pid=cand.pattern_id,
                file=cand.file,
                line=cand.line,
                asset=cand.scope_asset,
                input=cand.attacker_input_hint,
                base=cand.baseline_op,
                scale=cand.hypothesized_scaling,
            )
        )
    lines.append("")
    lines.append("### Snippets")
    lines.append("")
    for cand in candidates:
        lines.append(f"#### `{cand.candidate_id}`")
        lines.append("")
        lines.append("```rust")
        lines.append(cand.snippet or "<empty match>")
        lines.append("```")
        lines.append("")
    return "\n".join(lines) + "\n"


def render_thresholds_md() -> str:
    return (
        "# A6 Block-Delay Thresholds\n"
        "\n"
        f"_Schema: `{SCHEMA_VERSION}`_\n"
        "\n"
        "Source: Base program rubric (Blockchain/DLT scope).\n"
        "\n"
        f"- **Base block time**: {BASE_BLOCK_TIME_SECONDS}s.\n"
        f"- **A6 threshold ratio**: {A6_THRESHOLD_RATIO}x "
        f"(\"500% or more\").\n"
        f"- **A6 threshold (seconds)**: "
        f"{A6_THRESHOLD_SECONDS}s minimum wall-clock delay for a single "
        "block.\n"
        "\n"
        "## Measurement method\n"
        "\n"
        "Use `cargo bench` (Criterion) or a `std::time::Instant::now()` "
        "harness to measure end-to-end wall-clock time for the validation "
        "step under attacker-chosen input. The recorded time MUST be the "
        "wall-clock time of the production code path (not just the inner "
        "loop) — block delay is observed by peers as block-to-block "
        "latency, not as CPU-only cost.\n"
        "\n"
        "## Promotion rule\n"
        "\n"
        f"A candidate may be promoted to `executable` only when:\n"
        "\n"
        "1. The benchmark harness was run against the real upstream crate "
        "(no mock substitutions for the costly inner op).\n"
        f"2. The recorded wall-clock crossed {A6_THRESHOLD_SECONDS}s.\n"
        "3. The triggering input is reachable on the live production path "
        "(documented in `production_path` and supported by an "
        "execution_manifest.json under `<ws>/poc_execution/`).\n"
        "4. The impact_mapping verbatim-matches the workspace SEVERITY "
        "rubric Critical bullet for A6.\n"
        "\n"
        "## Why operator-driven\n"
        "\n"
        "Auto-running cargo bench in CI would (a) require pulling and "
        "compiling the entire Base node tree on every probe run, and "
        "(b) produce noisy, flaky timings on shared CI hardware. The "
        "harness is structured so an operator can invoke "
        "`cargo bench --bench block_delay` locally with reproducible "
        "results.\n"
    )


def render_harness_cargo_toml() -> str:
    return (
        "# A6 block-delay benchmark harness scaffold (operator-driven).\n"
        "#\n"
        "# This Cargo.toml is intentionally not wired into the auditooor\n"
        "# Python build. The operator must set `path = \"...\"` deps below\n"
        "# to point at the upstream Base node crates that contain the\n"
        "# candidate code path emitted by tools/base-block-delay-probe.py.\n"
        "#\n"
        "# Run:\n"
        "#   cd <ws>/critical_hunt/block_delay/harness\n"
        "#   cargo bench --bench block_delay\n"
        "#\n"
        "# Threshold: 10.0s (= 5x the 2.0s Base block time, A6 rubric).\n"
        "[package]\n"
        "name = \"a6-block-delay-harness\"\n"
        "version = \"0.0.0\"\n"
        "edition = \"2021\"\n"
        "publish = false\n"
        "\n"
        "[dependencies]\n"
        "# Operator: replace these with `path = \"...\"` references to the\n"
        "# upstream Base crate(s) under test. Examples:\n"
        "#\n"
        "# base-execution-evm = { path = \"../../../external/base-execution-evm/crates/evm\" }\n"
        "# base-derive       = { path = \"../../../external/base-derive\" }\n"
        "# flashblocks       = { path = \"../../../external/base/crates/optimism/flashblocks\" }\n"
        "\n"
        "[dev-dependencies]\n"
        "criterion = { version = \"0.5\", features = [\"html_reports\"] }\n"
        "\n"
        "[[bench]]\n"
        "name = \"block_delay\"\n"
        "harness = false\n"
    )


def render_harness_bench_rs() -> str:
    return (
        "// A6 block-delay benchmark template. Operator-driven.\n"
        "//\n"
        "// Threshold (per Base A6 rubric):\n"
        "//   Base block time     = 2.0 s\n"
        "//   A6 ratio            = 5.0x  (\"500% or more\")\n"
        "//   A6 wall-clock floor = 10.0 s\n"
        "//\n"
        "// Promotion rule: the benchmark must demonstrate that for some\n"
        "// reachable, attacker-chosen input size N, end-to-end wall-clock\n"
        "// time exceeds 10.0 s when measured against the real upstream\n"
        "// crate (no mock substitutions for the costly inner op).\n"
        "//\n"
        "// Usage:\n"
        "//   cd <ws>/critical_hunt/block_delay/harness\n"
        "//   cargo bench --bench block_delay\n"
        "//\n"
        "// The Criterion harness below is a SCAFFOLD only. Operator must:\n"
        "//   1. Wire real upstream deps in ../Cargo.toml.\n"
        "//   2. Replace `victim_under_test` with the candidate code path\n"
        "//      from tools/base-block-delay-probe.py output.\n"
        "//   3. Parametrize the attacker input (e.g. payload bytes,\n"
        "//      proof depth, RPC vector size) to find the minimum N that\n"
        "//      crosses the 10s threshold.\n"
        "\n"
        "use criterion::{black_box, criterion_group, criterion_main, "
        "Criterion};\n"
        "use std::time::{Duration, Instant};\n"
        "\n"
        "/// Operator: replace this stub with a call into the in-scope\n"
        "/// upstream code path. The stub deliberately panics so an\n"
        "/// accidentally-unconfigured harness does not silently report\n"
        "/// \"all green\" for A6 candidates.\n"
        "fn victim_under_test(_input_size: usize) -> Duration {\n"
        "    panic!(\"a6 harness not wired: edit benches/block_delay.rs and "
        "Cargo.toml to point at the real upstream crate\");\n"
        "}\n"
        "\n"
        "fn bench_a6(c: &mut Criterion) {\n"
        "    let mut group = c.benchmark_group(\"a6_block_delay\");\n"
        "    // Operator: extend / shrink this list to find the smallest N\n"
        "    // that crosses 10s.\n"
        "    for &n in &[1_000usize, 10_000, 100_000, 1_000_000, 10_000_000] {\n"
        "        group.bench_function(format!(\"n={}\", n), |b| {\n"
        "            b.iter_custom(|iters| {\n"
        "                let start = Instant::now();\n"
        "                for _ in 0..iters {\n"
        "                    let _ = victim_under_test(black_box(n));\n"
        "                }\n"
        "                start.elapsed()\n"
        "            });\n"
        "        });\n"
        "    }\n"
        "    group.finish();\n"
        "}\n"
        "\n"
        "criterion_group!(benches, bench_a6);\n"
        "criterion_main!(benches);\n"
    )


# ---------------------------------------------------------------------------
# Output orchestration
# ---------------------------------------------------------------------------


def write_outputs(
    workspace: Path,
    scan_root: Path,
    candidates: list[Candidate],
) -> dict[str, Path]:
    out_dir = workspace / "critical_hunt" / "block_delay"
    harness_dir = out_dir / "harness"
    bench_dir = harness_dir / "benches"
    candidates_dir = workspace / "critical_hunt" / "candidates"
    out_dir.mkdir(parents=True, exist_ok=True)
    harness_dir.mkdir(parents=True, exist_ok=True)
    bench_dir.mkdir(parents=True, exist_ok=True)
    candidates_dir.mkdir(parents=True, exist_ok=True)

    results_md = out_dir / "a6_block_delay_results.md"
    thresholds_md = out_dir / "expected_thresholds.md"
    harness_toml = harness_dir / "Cargo.toml"
    bench_rs = bench_dir / "block_delay.rs"
    candidates_json = candidates_dir / "a6_block_delay.json"

    results_md.write_text(
        render_results_md(candidates, scan_root, workspace), encoding="utf-8"
    )
    thresholds_md.write_text(render_thresholds_md(), encoding="utf-8")
    harness_toml.write_text(render_harness_cargo_toml(), encoding="utf-8")
    bench_rs.write_text(render_harness_bench_rs(), encoding="utf-8")

    # Emit candidates as a JSON array compatible with
    # base-critical-candidate-matrix.py loader (it accepts both list and
    # dict-with-`candidates` shapes).
    payload = {
        "schema": SCHEMA_VERSION,
        "scan_root": str(scan_root),
        "base_block_time_seconds": BASE_BLOCK_TIME_SECONDS,
        "a6_threshold_ratio": A6_THRESHOLD_RATIO,
        "a6_threshold_seconds": A6_THRESHOLD_SECONDS,
        "candidates": [c.to_matrix_row() for c in candidates],
    }
    candidates_json.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    return {
        "results_md": results_md,
        "thresholds_md": thresholds_md,
        "harness_toml": harness_toml,
        "bench_rs": bench_rs,
        "candidates_json": candidates_json,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="base-block-delay-probe.py",
        description=(
            "Scan a Base node Rust workspace for A6 block-delay "
            "candidates and emit a benchmark harness scaffold. "
            "Stdlib-only, idempotent, offline-safe."
        ),
    )
    parser.add_argument(
        "--workspace",
        required=True,
        type=Path,
        help="Audit workspace dir; outputs go under "
        "<ws>/critical_hunt/block_delay/.",
    )
    parser.add_argument(
        "--scan-root",
        type=Path,
        default=None,
        help=(
            "Directory tree to scan recursively for .rs files. "
            "Defaults to <workspace>/external."
        ),
    )
    parser.add_argument(
        "--print-json",
        action="store_true",
        help="Echo the candidates JSON to stdout in addition to writing "
        "files.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 if any candidate is emitted (useful in CI to keep "
        "an A6-clean baseline; promote-or-kill workflow is operator's "
        "responsibility).",
    )
    args = parser.parse_args(argv)

    workspace: Path = args.workspace
    if not workspace.is_dir():
        print(
            f"[base-block-delay-probe] ERR workspace not a directory: {workspace}",
            file=sys.stderr,
        )
        return 2

    scan_root: Path = args.scan_root or (workspace / "external")
    if not scan_root.exists():
        # Fall back to the workspace itself; the probe is still useful
        # against a workspace that does not yet have an external/ tree.
        scan_root = workspace

    candidates = scan_workspace(scan_root)
    paths = write_outputs(workspace, scan_root, candidates)

    print(
        f"[base-block-delay-probe] scanned root: {scan_root} "
        f"(candidates={len(candidates)})"
    )
    for label, path in paths.items():
        try:
            rel = path.relative_to(workspace)
        except ValueError:
            rel = path
        print(f"[base-block-delay-probe] wrote {label} -> {rel}")

    if args.print_json:
        sys.stdout.write(paths["candidates_json"].read_text(encoding="utf-8"))

    if args.strict and candidates:
        print(
            f"[base-block-delay-probe] STRICT FAIL: {len(candidates)} A6 "
            "candidate(s) emitted; benchmark + promote or kill them.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
