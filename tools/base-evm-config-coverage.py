#!/usr/bin/env python3
"""base-evm-config-coverage.py — PR #546 Wave 10 Lane G (A11 zero-coverage).

Surfaces the Base / Azul fork's EVM-level differences from upstream `reth` so
the operator has an enumerated, machine-readable matrix of *places where Base
behaviour can diverge from a stock reth/revm node*. The Wave 9 lane-G triage
flagged that A11 ("EVM/precompile differential surface") had **zero
detector coverage** even though the Azul tree adds at least three EVM-config
deltas:

  * EIP-7939  — `CLZ` (count-leading-zeros) opcode
  * EIP-7951  — `secp256r1` precompile (P-256 verification)
  * Base-specific Account-Balances-and-Receipts removal vs upstream reth

Wave 10 ships the **scanner + fixture corpus**. The actual differential
execution against revm is operator follow-up (revm is not part of the
auditooor stdlib-only stack). The scanner is therefore designed to be
deterministic, offline-safe, and emits rows in the same shape that
`tools/base-critical-candidate-matrix.py` already understands.

Tier discipline
---------------
* Tier B / advisory.
* No row is auto-promoted to ``executable``; every row is seeded as a
  candidate JSON under ``<ws>/critical_hunt/candidates/`` with a
  ``required_proof`` that demands the differential exec.
* Stdlib-only Python. No new pip deps. No network.

What it does
------------
1. Walk the workspace's Rust sources rooted at
   ``<ws>/external/base/`` (Azul fork) **plus** any sibling ``-rs`` Rust
   crates the operator chose to vendor. Identify Cargo crates that depend
   on ``revm`` / ``reth`` / ``alloy`` via ``Cargo.toml`` parsing.

2. For each crate, enumerate *Base-specific EVM modifications* by regex
   over ``src/**.rs`` (and ``build.rs``):

   * Precompile registry entries (``Precompile::new``, ``precompiles!``,
     ``custom_precompiles``, ``InspectorEvmConfig``).
   * Modified gas tables (``GAS_TABLE``, ``constants::*GAS*``).
   * Hardfork activation conditions (``Hardfork::``, ``Spec::*``,
     ``timestamp >=``).
   * Custom opcodes / op handlers (``OpCode::``, ``opcodes!``,
     ``InstructionResult``).
   * Custom EVM config (``EvmConfig``, ``ConfigureEvm``,
     ``ChainSpec::``).
   * Account-Balances-and-Receipts removal markers
     (``account_balances_and_receipts``, ``ReceiptsRoot``,
     ``compute_balances_root``).

3. For each enumerated delta, emit a row with the columns the lane-G
   spec requires:

   * ``precompile_name``     — symbolic name (e.g. ``secp256r1_p256``)
   * ``address``             — precompile address if extractable
                                (``0x...``), else ``""``
   * ``hardfork_active_at_timestamp`` — first ``timestamp >=`` constant
                                that gates this delta, else ``""``
   * ``upstream_reth_pin``   — the ``revm`` / ``reth`` version the
                                workspace pins to in ``Cargo.toml``
   * ``base_modification``   — short tag chosen from a fixed enum

4. Emit candidate rows compatible with
   ``tools/base-critical-candidate-matrix.py`` so a follow-up
   ``make base-critical-matrix`` pass picks them up automatically.

Outputs
-------
``<ws>/critical_hunt/precompile_diff/a11_precompile_diff_matrix.json``
``<ws>/critical_hunt/precompile_diff/a11_precompile_diff_matrix.md``
``<ws>/critical_hunt/candidates/a11_precompile_diff_seed.json``

The differential test inputs (positive control + Base-specific) are
*not* emitted by this scanner. They are static fixtures shipped under
``tools/baselines/a11_precompile_diff/differential_test_inputs/`` and
copied into the workspace by the orchestrator make target if missing.

Usage
-----

    python3 tools/base-evm-config-coverage.py --workspace <ws>
    python3 tools/base-evm-config-coverage.py --workspace <ws> --print-json
    python3 tools/base-evm-config-coverage.py --workspace <ws> --strict

Exit codes
----------
  0  normal (even when zero deltas were found)
  1  ``--strict`` and at least one delta was found without an
     ``upstream_reth_pin`` (which means the scanner cannot ground the
     differential) — used in CI to flag silent un-pinned drift
  2  argument or filesystem error
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

try:
    from lib.project_source_roots import declared_rust_project_roots
except ModuleNotFoundError:  # pragma: no cover - direct import from test loaders.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from lib.project_source_roots import declared_rust_project_roots


SCHEMA_VERSION = "auditooor.base_evm_config_coverage.v1"
TIER = "B"

# Maximum bytes of any single source file we'll scan. Avoids accidental
# pathological reads on vendored generated code.
MAX_FILE_BYTES = 2 * 1024 * 1024

# Historical fallback locations when the workspace has not declared validated
# project_source_roots.
DEFAULT_RUST_ROOTS = (
    "external/base",
    "external/base-rs",
    "external/op-reth",
)

# Fixed enum of base_modification tags we emit. Keep this stable — it's
# what downstream consumers (base-critical-candidate-matrix) match on.
MOD_TAG_PRECOMPILE_ADD = "precompile_add"
MOD_TAG_PRECOMPILE_GAS = "precompile_gas_change"
MOD_TAG_OPCODE_ADD = "opcode_add"
MOD_TAG_OPCODE_GAS = "opcode_gas_change"
MOD_TAG_HARDFORK = "hardfork_activation"
MOD_TAG_RECEIPTS_REMOVAL = "account_balances_and_receipts_removal"
MOD_TAG_EVM_CONFIG = "evm_config_override"

VALID_MOD_TAGS = (
    MOD_TAG_PRECOMPILE_ADD,
    MOD_TAG_PRECOMPILE_GAS,
    MOD_TAG_OPCODE_ADD,
    MOD_TAG_OPCODE_GAS,
    MOD_TAG_HARDFORK,
    MOD_TAG_RECEIPTS_REMOVAL,
    MOD_TAG_EVM_CONFIG,
)

# ---------------------------------------------------------------------------
# Regex catalog. Keep these conservative — false negatives are fine here, the
# row gets re-verified by hand. False positives would be more painful because
# they'd show up as candidate seeds without grounding.
# ---------------------------------------------------------------------------

# Cargo.toml deps we treat as upstream pins.
RE_CARGO_DEP = re.compile(
    r'^\s*(revm|reth|alloy|reth-evm|reth-primitives|alloy-primitives|alloy-consensus|revm-primitives|revm-precompile)'
    r'\s*=\s*(?:\{[^}]*version\s*=\s*"([^"]+)"[^}]*\}|"([^"]+)")\s*$',
    re.MULTILINE,
)

# Precompile registration. We accept several common shapes seen in
# revm/reth/op-reth/Base forks.
RE_PRECOMPILE_DECL = re.compile(
    r"\b(?:Precompile(?:Output|Result|s)?(?:::new)?|precompile\!|"
    r"custom_precompiles|register_precompile|InspectorEvmConfig)\b",
)

# Best-effort precompile address extraction. Looks for hex constants
# nearby a precompile declaration.
RE_PRECOMPILE_ADDR = re.compile(
    r"(?:address!?\s*\(\s*\")?(0x[0-9a-fA-F]{2,40})(?:\"\s*\))?",
)

# Custom opcode / instruction handlers.
RE_OPCODE_DECL = re.compile(
    r"\b(?:OpCode::[A-Z_0-9]+|opcodes\!|InstructionResult|"
    r"InstructionTable|register_opcode|custom_opcodes)\b",
)

# Gas-table changes.
RE_GAS_TABLE = re.compile(
    r"\b(?:GAS_TABLE|gas_costs?|constant_gas|gas::[A-Z_]+|"
    r"GAS_BASE_COST|BASE_GAS|MIN_GAS_COST|gas_cost\s*[:=])",
)

# Hardfork activation. These vary by codebase but consistently mention
# `Hardfork::`, `Spec`, or a `_TIMESTAMP`-style activation gate.
RE_HARDFORK = re.compile(
    r"(?:Hardfork::[A-Z][A-Za-z0-9_]*|"
    r"Spec(?:Id|::[A-Z][A-Za-z0-9_]*)|"
    r"\btimestamp\s*>=\s*\w+|"
    r"\b\w*timestamp\b|"
    r"\b\w*TIMESTAMP\w*|"
    r"\bis_active_at_timestamp\b|"
    r"\bactivation_timestamp\b)",
)

# Activation timestamp constant (best-effort). Matches a typed-numeric
# Rust literal like `: u64 = 1700000000` or `const FOO: u64 = ..`.
RE_TIMESTAMP_CONST = re.compile(
    r"const\s+([A-Z][A-Z0-9_]*)\s*:\s*u\d+\s*=\s*([0-9_]+)\s*;",
)

# Specific markers for the three known A11 deltas. Trailing word-boundary
# is intentionally relaxed so that `secp256r1_verify`, `clz_opcode`, etc.
# all fire (Rust convention is `_verify`/`_opcode` suffixing).
RE_CLZ = re.compile(r"\b(?:CLZ|count_leading_zeros|EIP[-_]?7939)")
RE_SECP256R1 = re.compile(
    r"\b(?:secp256r1|p256|EIP[-_]?7951|P256_VERIFY|p256_verify)",
    re.IGNORECASE,
)
RE_ABR_REMOVAL = re.compile(
    r"\b(?:account_balances_and_receipts|"
    r"AccountBalancesAndReceipts|"
    r"compute_balances_root|"
    r"ReceiptsRoot::Removed|"
    r"NoBalancesRoot)\b",
)

# EVM config override.
RE_EVM_CONFIG = re.compile(
    r"\b(?:ConfigureEvm(?:Env)?|EvmConfig|ChainSpec::|BaseChainSpec|"
    r"BaseEvmConfig|OptimismEvmConfig)\b",
)

# Files we never scan (vendored deps, generated, tests).
SKIP_PATH_TOKENS = (
    "/target/",
    "/.git/",
    "/node_modules/",
    "/_archive/",
    "/tests/",
    "/test/",
    "/benches/",
    "/examples/",
)


@dataclass
class Delta:
    delta_id: str
    crate: str
    file: str
    line: int
    precompile_name: str
    address: str
    hardfork_active_at_timestamp: str
    upstream_reth_pin: str
    base_modification: str
    snippet: str = ""
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Cargo dependency parsing
# ---------------------------------------------------------------------------


def parse_cargo_pins(cargo_toml: Path) -> dict[str, str]:
    """Return mapping of dep -> version string for upstream pins.

    Looks at top-level deps (``[dependencies]`` / ``[workspace.dependencies]``).
    Accepts both the inline-table form (``revm = { version = "..." }``) and
    the bare-string form (``revm = "..."``). When the crate's own
    Cargo.toml does not pin upstream deps directly (common in Cargo
    workspaces where each member just inherits ``workspace = true``), the
    function walks parent directories looking for a Cargo.toml that does
    define the workspace-level pin and merges those in.
    """
    pins: dict[str, str] = {}
    seen: set[Path] = set()
    cursor: Path | None = cargo_toml
    # Walk up at most 8 parents to find the workspace root.
    hops = 0
    while cursor is not None and hops < 8:
        if cursor in seen:
            break
        seen.add(cursor)
        if cursor.is_file():
            try:
                text = cursor.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            for match in RE_CARGO_DEP.finditer(text):
                dep = match.group(1)
                version = match.group(2) or match.group(3) or ""
                if version:
                    pins.setdefault(dep, version)
        # Step up to parent dir's Cargo.toml.
        if cursor.parent == cursor:
            break
        parent_dir = cursor.parent.parent
        if parent_dir == cursor.parent:
            break
        cursor = parent_dir / "Cargo.toml"
        hops += 1
    return pins


def resolve_upstream_pin(pins: dict[str, str]) -> str:
    """Pick the most-specific upstream pin. Prefer revm > reth > alloy."""
    for key in ("revm", "revm-primitives", "revm-precompile",
                "reth", "reth-evm", "reth-primitives",
                "alloy", "alloy-primitives", "alloy-consensus"):
        if key in pins and pins[key]:
            return f"{key}={pins[key]}"
    return ""


# ---------------------------------------------------------------------------
# Source enumeration
# ---------------------------------------------------------------------------


def find_rust_roots(workspace: Path) -> list[Path]:
    roots: list[Path] = []
    for rel in declared_rust_project_roots(workspace) or list(DEFAULT_RUST_ROOTS):
        candidate = workspace / rel
        if candidate.is_dir():
            roots.append(candidate)
    return roots


def find_crates(root: Path) -> list[Path]:
    """Yield directories under root that contain a Cargo.toml."""
    out: list[Path] = []
    for cargo in root.rglob("Cargo.toml"):
        if any(tok in str(cargo).replace("\\", "/") for tok in SKIP_PATH_TOKENS):
            continue
        out.append(cargo.parent)
    return out


def iter_rs_files(crate_dir: Path) -> list[Path]:
    out: list[Path] = []
    src_dir = crate_dir / "src"
    if src_dir.is_dir():
        for path in src_dir.rglob("*.rs"):
            sp = str(path).replace("\\", "/")
            if any(tok in sp for tok in SKIP_PATH_TOKENS):
                continue
            out.append(path)
    build_rs = crate_dir / "build.rs"
    if build_rs.is_file():
        out.append(build_rs)
    return out


def safe_read(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Delta classification
# ---------------------------------------------------------------------------


def _hardfork_timestamp_in(text: str) -> str:
    """Return the first activation timestamp constant we find, else ''."""
    if not RE_HARDFORK.search(text):
        return ""
    for match in RE_TIMESTAMP_CONST.finditer(text):
        # Constants whose names mention `TIMESTAMP`, `ACTIVATION`, `BASE_`,
        # or known fork names are the most likely candidates. Fall back to
        # the first numeric literal otherwise.
        name = match.group(1).upper()
        value = match.group(2).replace("_", "")
        if any(tok in name for tok in (
            "TIMESTAMP", "ACTIVATION", "FORK", "AZUL", "BASE", "OP_",
        )):
            return value
    # Fallback: first const with u64 type.
    for match in RE_TIMESTAMP_CONST.finditer(text):
        return match.group(2).replace("_", "")
    return ""


def _extract_address_near(text: str, start: int, end: int) -> str:
    """Pull the closest plausible 0x address within +/- 200 chars."""
    window_lo = max(0, start - 200)
    window_hi = min(len(text), end + 200)
    window = text[window_lo:window_hi]
    matches = RE_PRECOMPILE_ADDR.findall(window)
    for hit in matches:
        # Reject pure 0x0/0x00 unless followed by digits (avoid false hits
        # like 0x in random hex literals).
        if hit.lower().startswith("0x") and len(hit) >= 4:
            return hit.lower()
    return ""


def classify_file(
    crate: str,
    path: Path,
    text: str,
    upstream_pin: str,
) -> list[Delta]:
    """Walk a single source file and emit one Delta per detected marker.

    Multiple markers in the same file produce multiple rows. Callers
    deduplicate by (crate, file, line, base_modification) downstream.
    """
    out: list[Delta] = []
    if not text:
        return out

    line_offsets: list[int] = [0]
    for ch in text:
        if ch == "\n":
            line_offsets.append(line_offsets[-1] + 1)

    def line_for_offset(offset: int) -> int:
        # Linear scan is fine — files are small after MAX_FILE_BYTES.
        n = 1
        for ch in text[:offset]:
            if ch == "\n":
                n += 1
        return n

    timestamp = _hardfork_timestamp_in(text)

    # 1. CLZ (EIP-7939).
    for match in RE_CLZ.finditer(text):
        line_no = line_for_offset(match.start())
        out.append(Delta(
            delta_id=f"a11.clz.{path.name}.{line_no}",
            crate=crate,
            file=str(path),
            line=line_no,
            precompile_name="clz_opcode",
            address="",
            hardfork_active_at_timestamp=timestamp,
            upstream_reth_pin=upstream_pin,
            base_modification=MOD_TAG_OPCODE_ADD,
            snippet=text[max(0, match.start() - 40):match.end() + 40].strip(),
            notes=["EIP-7939 CLZ opcode marker"],
        ))

    # 2. secp256r1 (EIP-7951).
    for match in RE_SECP256R1.finditer(text):
        line_no = line_for_offset(match.start())
        out.append(Delta(
            delta_id=f"a11.secp256r1.{path.name}.{line_no}",
            crate=crate,
            file=str(path),
            line=line_no,
            precompile_name="secp256r1_p256",
            address=_extract_address_near(text, match.start(), match.end()),
            hardfork_active_at_timestamp=timestamp,
            upstream_reth_pin=upstream_pin,
            base_modification=MOD_TAG_PRECOMPILE_ADD,
            snippet=text[max(0, match.start() - 40):match.end() + 40].strip(),
            notes=["EIP-7951 secp256r1 precompile marker"],
        ))

    # 3. Account-Balances-and-Receipts removal.
    for match in RE_ABR_REMOVAL.finditer(text):
        line_no = line_for_offset(match.start())
        out.append(Delta(
            delta_id=f"a11.abr.{path.name}.{line_no}",
            crate=crate,
            file=str(path),
            line=line_no,
            precompile_name="account_balances_and_receipts",
            address="",
            hardfork_active_at_timestamp=timestamp,
            upstream_reth_pin=upstream_pin,
            base_modification=MOD_TAG_RECEIPTS_REMOVAL,
            snippet=text[max(0, match.start() - 40):match.end() + 40].strip(),
            notes=["Base-specific Account-Balances-and-Receipts removal"],
        ))

    # 4. Generic precompile registration (catches any custom precompile we
    #    don't have a dedicated regex for).
    for match in RE_PRECOMPILE_DECL.finditer(text):
        line_no = line_for_offset(match.start())
        out.append(Delta(
            delta_id=f"a11.precompile.{path.name}.{line_no}",
            crate=crate,
            file=str(path),
            line=line_no,
            precompile_name="custom_precompile",
            address=_extract_address_near(text, match.start(), match.end()),
            hardfork_active_at_timestamp=timestamp,
            upstream_reth_pin=upstream_pin,
            base_modification=MOD_TAG_PRECOMPILE_ADD,
            snippet=text[max(0, match.start() - 40):match.end() + 40].strip(),
            notes=["Generic precompile registration site"],
        ))

    # 5. Custom opcode / instruction-table override.
    for match in RE_OPCODE_DECL.finditer(text):
        line_no = line_for_offset(match.start())
        out.append(Delta(
            delta_id=f"a11.opcode.{path.name}.{line_no}",
            crate=crate,
            file=str(path),
            line=line_no,
            precompile_name="custom_opcode",
            address="",
            hardfork_active_at_timestamp=timestamp,
            upstream_reth_pin=upstream_pin,
            base_modification=MOD_TAG_OPCODE_ADD,
            snippet=text[max(0, match.start() - 40):match.end() + 40].strip(),
            notes=["Custom opcode / instruction handler"],
        ))

    # 6. Gas-table modifications.
    for match in RE_GAS_TABLE.finditer(text):
        line_no = line_for_offset(match.start())
        out.append(Delta(
            delta_id=f"a11.gas.{path.name}.{line_no}",
            crate=crate,
            file=str(path),
            line=line_no,
            precompile_name="gas_table",
            address="",
            hardfork_active_at_timestamp=timestamp,
            upstream_reth_pin=upstream_pin,
            base_modification=MOD_TAG_OPCODE_GAS,
            snippet=text[max(0, match.start() - 40):match.end() + 40].strip(),
            notes=["Gas-table / per-opcode gas-cost reference"],
        ))

    # 7. EVM config override.
    for match in RE_EVM_CONFIG.finditer(text):
        line_no = line_for_offset(match.start())
        out.append(Delta(
            delta_id=f"a11.config.{path.name}.{line_no}",
            crate=crate,
            file=str(path),
            line=line_no,
            precompile_name="evm_config",
            address="",
            hardfork_active_at_timestamp=timestamp,
            upstream_reth_pin=upstream_pin,
            base_modification=MOD_TAG_EVM_CONFIG,
            snippet=text[max(0, match.start() - 40):match.end() + 40].strip(),
            notes=["EVM config / ConfigureEvm override"],
        ))

    return out


def dedupe_deltas(deltas: list[Delta]) -> list[Delta]:
    """Collapse exact (file, line, base_modification) repeats."""
    seen: set[tuple[str, int, str]] = set()
    out: list[Delta] = []
    for d in deltas:
        key = (d.file, d.line, d.base_modification)
        if key in seen:
            continue
        seen.add(key)
        out.append(d)
    return out


# ---------------------------------------------------------------------------
# Workspace-level scan
# ---------------------------------------------------------------------------


def scan_workspace(workspace: Path) -> tuple[list[Delta], dict[str, str]]:
    """Scan all known Rust roots in workspace. Returns (deltas, pins)."""
    deltas: list[Delta] = []
    aggregated_pins: dict[str, str] = {}

    for root in find_rust_roots(workspace):
        for crate_dir in find_crates(root):
            cargo_toml = crate_dir / "Cargo.toml"
            pins = parse_cargo_pins(cargo_toml)
            for k, v in pins.items():
                aggregated_pins.setdefault(k, v)
            upstream_pin = resolve_upstream_pin(pins)
            crate_name = str(crate_dir.relative_to(workspace))
            for rs in iter_rs_files(crate_dir):
                text = safe_read(rs)
                rel_path = rs
                try:
                    rel_path = rs.relative_to(workspace)
                except ValueError:
                    pass
                deltas.extend(
                    classify_file(crate_name, rel_path, text, upstream_pin)
                )

    return dedupe_deltas(deltas), aggregated_pins


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def render_markdown(deltas: list[Delta], pins: dict[str, str]) -> str:
    lines: list[str] = []
    lines.append("# A11 Precompile / EVM-Config Differential Matrix")
    lines.append("")
    lines.append(f"_Schema: `{SCHEMA_VERSION}`_  Tier: **{TIER}**")
    lines.append("")
    lines.append(
        "Wave 10 lane G ships the SCANNER + fixture corpus. The actual "
        "differential exec against revm is operator follow-up; every row "
        "here is a candidate seed, never an executable finding."
    )
    lines.append("")
    lines.append("## Upstream pins discovered")
    lines.append("")
    if pins:
        for k in sorted(pins):
            lines.append(f"- `{k}` = `{pins[k]}`")
    else:
        lines.append("- _(no upstream revm/reth/alloy pins found in Cargo.tomls)_")
    lines.append("")
    lines.append("## Counts")
    lines.append("")
    counts: dict[str, int] = {tag: 0 for tag in VALID_MOD_TAGS}
    for d in deltas:
        counts[d.base_modification] = counts.get(d.base_modification, 0) + 1
    for tag in VALID_MOD_TAGS:
        lines.append(f"- `{tag}`: {counts.get(tag, 0)}")
    lines.append("")
    lines.append("## Rows")
    lines.append("")
    if not deltas:
        lines.append("_No deltas detected._")
        return "\n".join(lines) + "\n"
    lines.append(
        "| precompile_name | address | hardfork_active_at_timestamp | "
        "upstream_reth_pin | base_modification | file:line |"
    )
    lines.append("|---|---|---|---|---|---|")
    for d in deltas:
        lines.append(
            "| `{name}` | {addr} | {ts} | {pin} | `{tag}` | `{file}:{line}` |".format(
                name=d.precompile_name,
                addr=d.address or "_(empty)_",
                ts=d.hardfork_active_at_timestamp or "_(empty)_",
                pin=d.upstream_reth_pin or "_(empty)_",
                tag=d.base_modification,
                file=d.file,
                line=d.line,
            )
        )
    return "\n".join(lines) + "\n"


def write_outputs(workspace: Path, deltas: list[Delta], pins: dict[str, str]) -> dict[str, Path]:
    out_dir = workspace / "critical_hunt" / "precompile_diff"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "a11_precompile_diff_matrix.json"
    md_path = out_dir / "a11_precompile_diff_matrix.md"

    payload = {
        "schema": SCHEMA_VERSION,
        "tier": TIER,
        "workspace": str(workspace),
        "upstream_pins": pins,
        "row_count": len(deltas),
        "rows": [asdict(d) for d in deltas],
    }
    json_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(deltas, pins), encoding="utf-8")

    # Candidate-matrix seed for tools/base-critical-candidate-matrix.py.
    seed_dir = workspace / "critical_hunt" / "candidates"
    seed_dir.mkdir(parents=True, exist_ok=True)
    seed_path = seed_dir / "a11_precompile_diff_seed.json"
    candidates: list[dict[str, Any]] = []
    for d in deltas:
        candidates.append({
            "candidate_id": d.delta_id,
            "scope_asset": d.crate,
            "impact_mapping": "",  # default-to-kill until operator maps it
            "production_path": f"{d.file}:{d.line}",
            "required_proof": (
                "Differential execution against an unmodified revm pin "
                f"({d.upstream_reth_pin or 'unknown'}) showing observable "
                "state divergence on at least one Base-specific input."
            ),
            "artifact_refs": [
                "critical_hunt/precompile_diff/a11_precompile_diff_matrix.json",
            ],
            "severity": "candidate",
            "_a11": {
                "precompile_name": d.precompile_name,
                "address": d.address,
                "hardfork_active_at_timestamp": d.hardfork_active_at_timestamp,
                "upstream_reth_pin": d.upstream_reth_pin,
                "base_modification": d.base_modification,
            },
        })
    seed_path.write_text(
        json.dumps({"schema": SCHEMA_VERSION, "candidates": candidates},
                   indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    return {
        "json": json_path,
        "md": md_path,
        "seed": seed_path,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="base-evm-config-coverage.py",
        description=(
            "Enumerate Base / Azul EVM-config deltas (precompiles, opcodes, "
            "gas tables, hardfork activations, ABR removal) versus upstream "
            "reth/revm. Stdlib-only. Tier B / advisory."
        ),
    )
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument(
        "--print-json",
        action="store_true",
        help="Echo the JSON matrix to stdout in addition to writing files.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 if at least one delta was found without an upstream "
             "reth/revm pin (a differential cannot be grounded without one).",
    )
    args = parser.parse_args(argv)

    workspace: Path = args.workspace
    if not workspace.is_dir():
        print(
            f"[base-evm-config-coverage] ERR workspace not a directory: {workspace}",
            file=sys.stderr,
        )
        return 2

    deltas, pins = scan_workspace(workspace)
    paths = write_outputs(workspace, deltas, pins)
    print(f"[base-evm-config-coverage] wrote {paths['json'].relative_to(workspace)}")
    print(f"[base-evm-config-coverage] wrote {paths['md'].relative_to(workspace)}")
    print(f"[base-evm-config-coverage] wrote {paths['seed'].relative_to(workspace)}")
    print(
        "[base-evm-config-coverage] counts: "
        + ", ".join(
            f"{tag}={sum(1 for d in deltas if d.base_modification == tag)}"
            for tag in VALID_MOD_TAGS
        )
    )

    if args.print_json:
        sys.stdout.write(paths["json"].read_text(encoding="utf-8"))

    if args.strict:
        unpinned = [d for d in deltas if not d.upstream_reth_pin]
        if unpinned:
            print(
                "[base-evm-config-coverage] STRICT FAIL: "
                f"{len(unpinned)} delta(s) lack upstream_reth_pin; "
                "differential cannot be grounded.",
                file=sys.stderr,
            )
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
