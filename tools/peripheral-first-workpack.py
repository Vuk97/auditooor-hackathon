#!/usr/bin/env python3
"""peripheral-first-workpack -- Rank source files/functions toward under-audited
peripherals for HACKERMAN V3 Lane G3.

Peripheral classes (binding taxonomy, per G3 spec):
  constructor   -- constructor / __init__ / initialize / setUp paths
  factory       -- create* / clone / deploy* / spawn* entry points
  adapter       -- *Adapter / *Wrapper / *Bridge-as-thin-layer files
  oracle-setup  -- oracle address setters, feed-config init, price-source
                   registration
  bridge-router -- cross-chain router / relay dispatcher / bridge entrypoint
  vault-acct    -- vault accounting periphery: fee-sweep, harvest, accounting
                   adjustments that are NOT the main deposit/withdraw core
  upgrade-init  -- proxy initializer, upgradeTo, _authorizeUpgrade, reinit
  deploy-script -- deploy / migration scripts outside src/

The tool reads the workspace source tree, classifies each file and its
functions into a peripheral class (or CORE / UNCLASSIFIED), emits a ranked
JSON workpack at:

    <workspace>/.auditooor/peripheral_first_workpack.json

If a ``target_saturation.json`` exists (Lane E output), the tool cross-checks:
files already marked ``cold_read`` or ``state_divergence_only`` by the
saturation scorer are surfaced in the peripheral-first section even when
the source tree alone would classify them as CORE.

Schema: auditooor.peripheral_first_workpack.v1
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

SCHEMA_VERSION = "auditooor.peripheral_first_workpack.v1"

# ---------------------------------------------------------------------------
# Languages + extensions
# ---------------------------------------------------------------------------

SOURCE_EXTENSIONS: dict[str, str] = {
    ".sol": "solidity",
    ".rs": "rust",
    ".go": "go",
    ".vy": "vyper",
    ".cairo": "cairo",
    ".ts": "typescript",
    ".js": "javascript",
    ".py": "python",
    ".move": "move",
}

# Directories that are almost always peripheral (deploy / script / test).
PERIPHERAL_DIRS: tuple[str, ...] = (
    "scripts",
    "script",
    "deploy",
    "deployments",
    "migrations",
    "migration",
    "adapters",
    "adapter",
    "bridges",
    "bridge",
    "oracles",
    "oracle",
    "periphery",
    "peripherals",
    "wrappers",
    "wrapper",
    "factories",
    "factory",
    "initializers",
    "initializer",
    "upgrades",
    "upgrade",
    "proxies",
    "proxy",
    "routers",
    "router",
)

# Directories that are almost always core (skip unless saturation forces it).
CORE_DIRS: tuple[str, ...] = (
    "core",
    "kernel",
    "exchange",
    "market",
    "markets",
    "settlement",
    "trading",
    "ledger",
    "accounting",
    "protocol",
    "vault",         # the MAIN vault logic is core; vault accounting *periphery* is caught by fn-level
)

# ---------------------------------------------------------------------------
# Peripheral-class taxonomy
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PeripheralClass:
    name: str           # machine-readable key
    label: str          # human label for the workpack
    rationale_fmt: str  # one-line template; {fn} = function name, {file} = relative path


CLASSES: list[PeripheralClass] = [
    PeripheralClass(
        name="constructor",
        label="Constructor / init path",
        rationale_fmt="Constructor/init logic in {file} often skips the same guards as runtime paths and is under-covered by fuzz corpora.",
    ),
    PeripheralClass(
        name="factory",
        label="Factory / clone entry point",
        rationale_fmt="Factory create/clone pattern in {file} controls deployment state; overlooked by auditors focused on core runtime.",
    ),
    PeripheralClass(
        name="adapter",
        label="Adapter / wrapper shim",
        rationale_fmt="Adapter/wrapper in {file} is a thin translation layer with its own trust assumptions, rarely in prior audit scope.",
    ),
    PeripheralClass(
        name="oracle-setup",
        label="Oracle address / feed setup",
        rationale_fmt="Oracle-config setter in {file}:{fn} controls price sources; mis-configuration bugs here are high-impact and often missed.",
    ),
    PeripheralClass(
        name="bridge-router",
        label="Bridge / cross-chain router",
        rationale_fmt="Bridge/router entrypoint in {file} is a cross-trust-boundary path; message-validation bugs are systemic.",
    ),
    PeripheralClass(
        name="vault-acct",
        label="Vault accounting periphery",
        rationale_fmt="Vault accounting hook in {file}:{fn} (fee-sweep / harvest / accounting adj.) is peripheral to the main deposit/withdraw core and often skipped.",
    ),
    PeripheralClass(
        name="upgrade-init",
        label="Proxy initializer / upgrade path",
        rationale_fmt="Upgrade/proxy-init path in {file}:{fn} runs once and is rarely tested end-to-end; state corruption bugs are permanent.",
    ),
    PeripheralClass(
        name="deploy-script",
        label="Deploy / migration script",
        rationale_fmt="Deployment script {file} encodes constructor assumptions; a bug here means mainnet is initialized wrong.",
    ),
]

_CLASS_BY_NAME: dict[str, PeripheralClass] = {c.name: c for c in CLASSES}


# ---------------------------------------------------------------------------
# File-level classification (directory + filename heuristics)
# ---------------------------------------------------------------------------

_ADAPTER_FILE_RE = re.compile(
    r"(?:adapter|wrapper|shim|bridge|relay|router|forwarder)s?",
    re.IGNORECASE,
)
_ORACLE_FILE_RE = re.compile(
    r"(?:oracle|price.?feed|chainlink|aggregator|feed)",
    re.IGNORECASE,
)
_FACTORY_FILE_RE = re.compile(
    r"(?:factory|factories|creator|spawner|deployer|cloner|blueprint)",
    re.IGNORECASE,
)
_UPGRADE_FILE_RE = re.compile(
    r"(?:proxy|upgradeable|upgradable|initializ|reinitializ)",
    re.IGNORECASE,
)
_DEPLOY_FILE_RE = re.compile(
    r"(?:deploy|migration|migrate|script|setup|fixture|install)",
    re.IGNORECASE,
)
_VAULT_ACCT_FILE_RE = re.compile(
    r"(?:harvest|fee.?sweep|accounting|rebalance|accrual|yield.?accrual)",
    re.IGNORECASE,
)


def _dir_peripheral_class(path: Path) -> Optional[str]:
    """Return a peripheral class name if the path lives in a peripheral dir."""
    parts_lower = {p.lower() for p in path.parts}
    for d in PERIPHERAL_DIRS:
        if d in parts_lower:
            if d in ("scripts", "script", "deploy", "deployments", "migrations", "migration"):
                return "deploy-script"
            if d in ("adapters", "adapter", "wrappers", "wrapper"):
                return "adapter"
            if d in ("bridges", "bridge"):
                return "bridge-router"
            if d in ("oracles", "oracle"):
                return "oracle-setup"
            if d in ("factories", "factory"):
                return "factory"
            if d in ("initializers", "initializer", "upgrades", "upgrade", "proxies", "proxy"):
                return "upgrade-init"
            if d in ("routers", "router"):
                return "bridge-router"
            if d in ("periphery", "peripherals"):
                return "vault-acct"
    return None


def _filename_peripheral_class(stem: str) -> Optional[str]:
    """Return a peripheral class name based on filename stem."""
    if _ADAPTER_FILE_RE.search(stem):
        return "adapter"
    if _ORACLE_FILE_RE.search(stem):
        return "oracle-setup"
    if _FACTORY_FILE_RE.search(stem):
        return "factory"
    if _UPGRADE_FILE_RE.search(stem):
        return "upgrade-init"
    if _DEPLOY_FILE_RE.search(stem):
        return "deploy-script"
    if _VAULT_ACCT_FILE_RE.search(stem):
        return "vault-acct"
    return None


def _is_core_file(path: Path, rel: str) -> bool:
    """True when the file is likely a saturated core module."""
    parts_lower = {p.lower() for p in path.parts}
    for d in CORE_DIRS:
        if d in parts_lower:
            return True
    # Also flag by filename terms
    stem_lower = path.stem.lower()
    for term in ("core", "kernel", "exchange", "market", "settlement", "trading", "ledger"):
        if term in stem_lower:
            return True
    return False


# ---------------------------------------------------------------------------
# Function-level classification via lightweight regex
# ---------------------------------------------------------------------------

# Solidity constructor
_SOL_CONSTRUCTOR_RE = re.compile(r"^\s*constructor\s*\(", re.MULTILINE)
# Solidity initialize / reinitialize
_SOL_INIT_RE = re.compile(r"^\s*function\s+(initialize|reinitialize|setUp)\s*\(", re.MULTILINE | re.IGNORECASE)
# Solidity upgradeTo / _authorizeUpgrade
_SOL_UPGRADE_RE = re.compile(r"^\s*function\s+(_authorizeUpgrade|upgradeTo|upgradeToAndCall)\s*\(", re.MULTILINE)
# Solidity factory create/clone
_SOL_FACTORY_RE = re.compile(r"^\s*function\s+(create[A-Z_]|clone|deploy[A-Z_]|spawn[A-Z_]|blueprint)", re.MULTILINE)
# Solidity oracle setters
_SOL_ORACLE_SET_RE = re.compile(r"^\s*function\s+(set|update|change|register|add)[A-Za-z]*(?:Oracle|Feed|Price|Source|Aggregator)\s*\(", re.MULTILINE)
# Solidity vault-acct periphery
_SOL_VAULT_ACCT_RE = re.compile(r"^\s*function\s+(harvest|sweep|collectFees?|accrueInterest|rebalance|distributeYield|claimFees?)\s*\(", re.MULTILINE)
# Solidity bridge/router dispatch
_SOL_BRIDGE_RE = re.compile(r"^\s*function\s+(relay|dispatch|bridge|route|receive[A-Z]|execute[A-Z]Message|handleMessage|processMessage)\s*\(", re.MULTILINE)

# Go constructor patterns
_GO_CONSTRUCTOR_RE = re.compile(r"^func\s+New[A-Z][A-Za-z0-9_]*\s*\(", re.MULTILINE)
_GO_INIT_RE = re.compile(r"^func\s+(?:\([^)]+\)\s+)?(?:Initialize|Init|Setup|BeginBlock)\s*\(", re.MULTILINE)
_GO_FACTORY_RE = re.compile(r"^func\s+(?:\([^)]+\)\s+)?(?:Create|Deploy|Spawn|Clone|NewFrom)[A-Z]", re.MULTILINE)
_GO_ORACLE_RE = re.compile(r"^func\s+(?:\([^)]+\)\s+)?(?:Set|Update|Register)(?:Oracle|Feed|Price|Source)\s*\(", re.MULTILINE)
_GO_UPGRADE_RE = re.compile(r"^func\s+(?:\([^)]+\)\s+)?(?:Upgrade|MigrateStore|RunMigrations)\s*\(", re.MULTILINE)
_GO_VAULT_ACCT_RE = re.compile(r"^func\s+(?:\([^)]+\)\s+)?(?:Harvest|SweepFees?|CollectFees?|AccrueInterest|Rebalance|DistributeYield)\s*\(", re.MULTILINE)
_GO_BRIDGE_RE = re.compile(r"^func\s+(?:\([^)]+\)\s+)?(?:Relay|Dispatch|BridgeSend|RouteMessage|HandleMessage|ProcessMessage)\s*\(", re.MULTILINE)

# Rust constructor / init
_RUST_CONSTRUCTOR_RE = re.compile(r"^\s*(?:pub\s+)?fn\s+(?:new|initialize|init|setup)\s*[<(]", re.MULTILINE)
_RUST_FACTORY_RE = re.compile(r"^\s*(?:pub\s+)?fn\s+(?:create|deploy|spawn|clone)_", re.MULTILINE)
_RUST_ORACLE_RE = re.compile(r"^\s*(?:pub\s+)?fn\s+(?:set|update|register)_(?:oracle|feed|price|source)\s*[<(]", re.MULTILINE)
_RUST_UPGRADE_RE = re.compile(r"^\s*(?:pub\s+)?fn\s+(?:upgrade|migrate|initialize_v\d)\s*[<(]", re.MULTILINE)
_RUST_VAULT_ACCT_RE = re.compile(r"^\s*(?:pub\s+)?fn\s+(?:harvest|sweep_fees?|collect_fees?|accrue_interest|rebalance|distribute_yield)\s*[<(]", re.MULTILINE)
_RUST_BRIDGE_RE = re.compile(r"^\s*(?:pub\s+)?fn\s+(?:relay|dispatch|bridge_send|route_message|handle_message|process_message)\s*[<(]", re.MULTILINE)


@dataclass
class FunctionHit:
    fn_name: str
    peripheral_class: str
    line_hint: int  # approximate line number


def _extract_function_hits(text: str, lang: str) -> list[FunctionHit]:
    """Lightweight regex scan for peripheral-class function patterns."""
    hits: list[FunctionHit] = []

    def _scan(pattern: re.Pattern[str], class_name: str) -> None:
        for m in pattern.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            # Try to pull the function name from the match
            fn_name = m.group(0).strip().split("(")[0].split()[-1]
            hits.append(FunctionHit(fn_name=fn_name, peripheral_class=class_name, line_hint=line_no))

    if lang == "solidity":
        _scan(_SOL_CONSTRUCTOR_RE, "constructor")
        _scan(_SOL_INIT_RE, "constructor")
        _scan(_SOL_UPGRADE_RE, "upgrade-init")
        _scan(_SOL_FACTORY_RE, "factory")
        _scan(_SOL_ORACLE_SET_RE, "oracle-setup")
        _scan(_SOL_VAULT_ACCT_RE, "vault-acct")
        _scan(_SOL_BRIDGE_RE, "bridge-router")
    elif lang == "go":
        _scan(_GO_CONSTRUCTOR_RE, "constructor")
        _scan(_GO_INIT_RE, "constructor")
        _scan(_GO_FACTORY_RE, "factory")
        _scan(_GO_ORACLE_RE, "oracle-setup")
        _scan(_GO_UPGRADE_RE, "upgrade-init")
        _scan(_GO_VAULT_ACCT_RE, "vault-acct")
        _scan(_GO_BRIDGE_RE, "bridge-router")
    elif lang == "rust":
        _scan(_RUST_CONSTRUCTOR_RE, "constructor")
        _scan(_RUST_FACTORY_RE, "factory")
        _scan(_RUST_ORACLE_RE, "oracle-setup")
        _scan(_RUST_UPGRADE_RE, "upgrade-init")
        _scan(_RUST_VAULT_ACCT_RE, "vault-acct")
        _scan(_RUST_BRIDGE_RE, "bridge-router")
    # Other languages: file-level classification only (no fn-level patterns yet)
    return hits


# ---------------------------------------------------------------------------
# Source tree walker
# ---------------------------------------------------------------------------

SKIP_DIRS: frozenset[str] = frozenset({
    ".git", "node_modules", "target", "__pycache__", ".auditooor",
    "out", "cache", "artifacts", ".cargo", "vendor", "third_party",
    "testdata", "mocks", "mock", "abis",
})

MAX_FILE_BYTES = 500_000


def _iter_source_files(src_root: Path) -> list[tuple[Path, str]]:
    """Yield (absolute_path, language) for all source files under src_root."""
    result: list[tuple[Path, str]] = []
    for p in sorted(src_root.rglob("*")):
        if not p.is_file():
            continue
        # Skip ignored dirs
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        lang = SOURCE_EXTENSIONS.get(p.suffix.lower())
        if lang is None:
            continue
        result.append((p, lang))
    return result


# ---------------------------------------------------------------------------
# Saturation cross-check
# ---------------------------------------------------------------------------

def _load_saturation_cold_reads(workspace: Path) -> set[str]:
    """Return set of module names recommended as cold_read by saturation scorer."""
    sat_path = workspace / ".auditooor" / "target_saturation.json"
    if not sat_path.exists():
        return set()
    try:
        data = json.loads(sat_path.read_text(encoding="utf-8"))
        return {
            row["module"].lower()
            for row in data.get("modules", [])
            if row.get("recommended_action") in ("cold_read", "state_divergence_only")
        }
    except Exception:
        return set()


def _saturation_boosts(rel_path: str, cold_reads: set[str]) -> bool:
    """True if any cold_read module name appears in the relative path."""
    rel_lower = rel_path.lower()
    return any(name in rel_lower for name in cold_reads)


# ---------------------------------------------------------------------------
# Workpack row builder
# ---------------------------------------------------------------------------

@dataclass
class WorkpackRow:
    file: str                   # relative path
    language: str
    peripheral_class: str       # "core" | "unclassified" | one of CLASSES.name
    label: str
    functions: list[dict[str, Any]] = field(default_factory=list)
    rationale: str = ""
    saturation_boosted: bool = False
    rank_score: float = 0.0


_CLASS_RANK: dict[str, float] = {
    "deploy-script":  10.0,
    "constructor":     9.0,
    "upgrade-init":    9.0,
    "factory":         8.5,
    "oracle-setup":    8.0,
    "bridge-router":   7.5,
    "adapter":         7.0,
    "vault-acct":      6.5,
    "unclassified":    2.0,
    "core":            1.0,
}

SATURATION_BOOST = 3.0  # added to rank when saturation scorer agrees


def _build_row(
    abs_path: Path,
    rel: str,
    lang: str,
    class_name: str,
    fn_hits: list[FunctionHit],
    saturation_boosted: bool,
) -> WorkpackRow:
    pc = _CLASS_BY_NAME.get(class_name)
    label = pc.label if pc else class_name.replace("-", " ").title()

    # Build rationale
    if pc:
        if fn_hits:
            fn_name = fn_hits[0].fn_name
        else:
            fn_name = abs_path.stem
        rationale = pc.rationale_fmt.format(fn=fn_name, file=rel)
    else:
        rationale = f"{rel} was not matched to a peripheral class; included as unclassified."

    base_rank = _CLASS_RANK.get(class_name, 2.0)
    # More function hits -> slightly higher priority within class
    fn_bonus = min(len(fn_hits) * 0.1, 1.0)
    rank_score = base_rank + fn_bonus + (SATURATION_BOOST if saturation_boosted else 0.0)

    fn_records = [
        {
            "function": h.fn_name,
            "peripheral_class": h.peripheral_class,
            "line_hint": h.line_hint,
            "rationale": _CLASS_BY_NAME.get(h.peripheral_class, pc).rationale_fmt.format(
                fn=h.fn_name, file=rel
            ) if _CLASS_BY_NAME.get(h.peripheral_class) else rationale,
        }
        for h in fn_hits
    ]

    return WorkpackRow(
        file=rel,
        language=lang,
        peripheral_class=class_name,
        label=label,
        functions=fn_records,
        rationale=rationale,
        saturation_boosted=saturation_boosted,
        rank_score=rank_score,
    )


# ---------------------------------------------------------------------------
# Main classifier
# ---------------------------------------------------------------------------

def _find_src_roots(workspace: Path) -> list[Path]:
    """Return candidate source roots: src/, contracts/, sources/, or workspace root."""
    candidates = []
    for name in ("src", "contracts", "sources", "lib", "programs"):
        p = workspace / name
        if p.is_dir():
            candidates.append(p)
    if not candidates:
        candidates.append(workspace)
    return candidates


def classify_workspace(workspace: Path) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    cold_reads = _load_saturation_cold_reads(workspace)
    src_roots = _find_src_roots(workspace)

    # Also walk deploy/script directories at workspace root directly
    extra_roots = []
    for name in ("scripts", "script", "deploy", "deployments", "migrations", "test"):
        p = workspace / name
        if p.is_dir():
            extra_roots.append(p)

    all_roots = src_roots + [r for r in extra_roots if r not in src_roots]

    rows: list[WorkpackRow] = []
    seen: set[str] = set()

    for root in all_roots:
        for abs_path, lang in _iter_source_files(root):
            try:
                rel = str(abs_path.relative_to(workspace))
            except ValueError:
                rel = str(abs_path)
            if rel in seen:
                continue
            seen.add(rel)

            # Read file (bounded)
            try:
                text = abs_path.read_text(encoding="utf-8", errors="replace")
                if len(text) > MAX_FILE_BYTES:
                    text = text[:MAX_FILE_BYTES]
            except OSError:
                text = ""

            # Classify at file level
            dir_class = _dir_peripheral_class(abs_path)
            fname_class = _filename_peripheral_class(abs_path.stem)

            # Function-level hits
            fn_hits = _extract_function_hits(text, lang)
            fn_classes = {h.peripheral_class for h in fn_hits}

            # Determine winning peripheral class
            if dir_class:
                class_name = dir_class
            elif fname_class:
                class_name = fname_class
            elif fn_classes:
                # Prefer highest-ranked class from function hits
                class_name = max(fn_classes, key=lambda c: _CLASS_RANK.get(c, 0))
            elif _is_core_file(abs_path, rel):
                class_name = "core"
            else:
                class_name = "unclassified"

            # Saturation cross-check: if saturation says cold_read, promote
            sat_boost = _saturation_boosts(rel, cold_reads)
            if sat_boost and class_name == "core":
                # Demote core to unclassified so it gets included in peripheral section
                class_name = "unclassified"

            row = _build_row(abs_path, rel, lang, class_name, fn_hits, sat_boost)
            rows.append(row)

    # Sort: peripheral rows first (rank_score desc), core last
    rows.sort(key=lambda r: r.rank_score, reverse=True)

    peripheral_rows = [r for r in rows if r.peripheral_class not in ("core",)]
    core_rows = [r for r in rows if r.peripheral_class == "core"]

    def _row_dict(r: WorkpackRow) -> dict[str, Any]:
        return {
            "file": r.file,
            "language": r.language,
            "peripheral_class": r.peripheral_class,
            "label": r.label,
            "rank_score": round(r.rank_score, 2),
            "rationale": r.rationale,
            "saturation_boosted": r.saturation_boosted,
            "functions": r.functions,
        }

    class_counts: dict[str, int] = {}
    for r in rows:
        class_counts[r.peripheral_class] = class_counts.get(r.peripheral_class, 0) + 1

    return {
        "schema": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "workspace_path": str(workspace),
        "summary": {
            "total_files": len(rows),
            "peripheral_files": len(peripheral_rows),
            "core_files": len(core_rows),
            "saturation_boosted_count": sum(1 for r in rows if r.saturation_boosted),
            "saturation_json_present": (workspace / ".auditooor" / "target_saturation.json").exists(),
            "class_counts": class_counts,
        },
        "peripheral_first": [_row_dict(r) for r in peripheral_rows],
        "core": [_row_dict(r) for r in core_rows],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def write_payload(payload: dict[str, Any], workspace: Path, out: Optional[Path] = None) -> Path:
    workspace = workspace.expanduser().resolve()
    if out is None:
        out = workspace / ".auditooor" / "peripheral_first_workpack.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Peripheral-first workpack generator (HACKERMAN V3 Lane G3)."
    )
    parser.add_argument("workspace", type=Path, help="Path to the engagement workspace.")
    parser.add_argument("--out", type=Path, help="Override output path.")
    parser.add_argument(
        "--print-json",
        action="store_true",
        help="Print payload JSON to stdout in addition to writing the file.",
    )
    parser.add_argument(
        "--no-write",
        action="store_true",
        help="Skip writing the output file (useful for testing / piping).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"error: workspace not found: {workspace}", file=sys.stderr)
        return 1

    payload = classify_workspace(workspace)

    if not args.no_write:
        out = write_payload(payload, workspace, args.out)
        print(f"[peripheral-first-workpack] wrote {out}", file=sys.stderr)

    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))

    summary = payload["summary"]
    print(
        f"[peripheral-first-workpack] {summary['peripheral_files']} peripheral / "
        f"{summary['core_files']} core / {summary['total_files']} total files | "
        f"{summary['saturation_boosted_count']} saturation-boosted",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
