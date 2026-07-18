#!/usr/bin/env python3
# r36-rebuttal: lane zkbugs-dataset-etl registered 2 files via tools/agent-pathspec-register.py at lane start
# Rule 37: this miner emits at tier-2 (tier-2-verified-public-archive).
"""hackerman-etl-from-zkbugs-dataset.py - mine the zksecurity/zkbugs DATASET
into INV-* invariant-library records + detector seeds.

The zksecurity/zkbugs dataset (https://github.com/zksecurity/zkbugs, 139
vulns / 70 circom + arkworks/halo2/gnark/... families) ships one
``dataset/<family>/<project>/<bug>/zkbugs_config.json`` per bug plus a
reproduction-command block. Each config exposes the canonical fields:

    Id, Project, Commit, Fix Commit, DSL, Vulnerability, Impact,
    Root Cause, Location{Function,Line,Path}, Reproduced,
    Short Description of the Vulnerability, Proposed Mitigation,
    Source.Audit Report.Source Link / Source.Bug Tracker.Source Link,
    Commands{Reproduce, Positive Test, Find Exploit, ...}

This is a CORPUS (public archive), not a tool. Mining it into the
invariant library helps every future ZK target. Each dataset entry that
parses with >=3 mandatory shape fields (Id, DSL, Vulnerability/Root Cause)
emits TWO promotable records:

  1. An INVARIANT record (flat JSON-embedded ``content.invariant_id`` +
     ``content.statement`` + first-class ``verification_tier``) written to
         audit/corpus_tags/derived/invariant_library_extended/<batch>/INV-*.yaml
     so the existing ``invariant_library_extended`` SOURCE_ROUTER promotes
     it to ``invariants_pilot_audited.jsonl``.

  2. A DETECTOR-SEED record (dispatch-ledger generic shape: ``task_id`` +
     ``result`` JSON-string + first-class ``verification_tier`` +
     ``status: ok``) written to
         audit/corpus_tags/derived/detector_synthesis_v2/<batch>/*.json
     so the existing ``detector_synthesis_v2`` SOURCE_ROUTER promotes it to
     ``detector_seed_library_promoted.jsonl``.

Verification tier (Rule 37, first-class field on EVERY emitted record):
    tier-2-verified-public-archive - the emit step parsed a public archive
    (the zkbugs_config.json + reproduction script) and extracted >=3
    mandatory shape fields. Records that lack the mandatory fields are
    skipped, NOT emitted at a lower tier.

attack_class is mapped from the zkbugs Root Cause / Vulnerability / Impact
to the canonical ZK attack-class taxonomy (Circuit / Prover / Verifier /
zkVM / L2-zkRollup / Other families), matching the taxonomy used by the
sibling 0xPARC catalog miner.

RELATED TOOLS (tool-duplication preflight, ~/.claude/CLAUDE.md anchor):
  * tools/hackerman-etl-from-zk-bugs.py - mines the SAME zksecurity/zkbugs
    dataset (source A) + 0xPARC/zk-bug-tracker README (source B) but emits
    ``hackerman_record.v1`` CORPUS records (a different schema family). It
    does NOT emit INV-* invariant-library records or detector seeds, and it
    does NOT route through promote-mined-to-canonical. GAP this tool fills:
    invariant + detector-seed emission into the invariant_library_extended /
    detector_synthesis_v2 derived dirs that promote-mined already routes.
  * tools/hackerman-etl-from-zkbugs-catalog.py - seed-driven Python table of
    0xPARC catalog entries (no dataset parse, no live fetch). Different
    SOURCE (hardcoded table vs the zksecurity dataset on disk) and different
    OUTPUT (hackerman_record.v1 vs INV-* invariants).
  * tools/promote-mined-to-canonical.py - the CANONICAL promote path this
    tool feeds. We do NOT build a new promote path; we write into the
    derived dirs its SOURCE_ROUTERS already scan, then the operator runs
    ``python3 tools/promote-mined-to-canonical.py`` to land the records in
    MCP-readable JSONL.
  * tools/hackerman-etl-from-corpus-mined.py - corpus->hackerman_record
    bridge; cited per preflight. Distinct: it consumes already-mined corpus
    records; this tool mines the raw zkbugs dataset.

Hard rules:
  * Real-source only (zksecurity/zkbugs dataset). No fabricated bug IDs.
  * Cross-links relative-path only.
  * Does NOT modify tools/calibration/llm_budget_log.jsonl.
  * Every emitted record carries a non-empty first-class verification_tier.

CLI::

    # Live mode: shallow git clone of zksecurity/zkbugs into a tmp dir
    python3 tools/hackerman-etl-from-zkbugs-dataset.py --json-summary

    # Offline / fixture mode (used by the test suite + dry runs):
    python3 tools/hackerman-etl-from-zkbugs-dataset.py \\
        --dataset-root tools/tests/fixtures/hackerman_etl_from_zkbugs_dataset \\
        --out-root /tmp/zkbugs-dataset-out --dry-run --json-summary
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

TOOL_NAME = "hackerman-etl-from-zkbugs-dataset"
TOOL_VERSION = "1.0.0"

REPO_ROOT = Path(__file__).resolve().parent.parent
DERIVED_ROOT = REPO_ROOT / "audit" / "corpus_tags" / "derived"
INV_BATCH_ROOT = DERIVED_ROOT / "invariant_library_extended"
DET_BATCH_ROOT = DERIVED_ROOT / "detector_synthesis_v2"

ZKBUGS_REPO_URL = "https://github.com/zksecurity/zkbugs.git"

VERIFICATION_TIER = "tier-2-verified-public-archive"

# Mandatory shape fields: an entry must expose >=3 of these to be emitted at
# tier-2 (R37 public-archive contract). Otherwise skipped.
MANDATORY_FIELDS = ("Id", "DSL", "Vulnerability", "Root Cause", "Impact",
                    "Location", "Project")
MIN_MANDATORY = 3


# --------------------------------------------------------------------------
# ZK attack-class taxonomy mapping (canonical classes, shared with the
# 0xPARC catalog miner). The dataset's free-text Root Cause / Vulnerability
# strings are normalized to one canonical class.
# --------------------------------------------------------------------------
_ZK_CLASS_RULES: List[Tuple[str, str]] = [
    # (regex over "<Vulnerability> | <Root Cause> | <Impact>", canonical class)
    (r"under[- ]?constrain|unconstrained|missing.*constraint|wrong translation.*constraint",
     "circuit-unconstrained-variable"),
    (r"range[- ]?check|overflow|out[- ]?of[- ]?range|bit.*length", "circuit-missing-range-check"),
    (r"alias|witness.*alias|non[- ]?canonical|multiple.*representation", "circuit-aliased-witness"),
    (r"frozen|constant.*substitut|hardcoded.*signal", "circuit-frozen-variable"),
    (r"public[- ]?input.*alias|public[- ]?input.*bind|input.*not.*bound", "verifier-not-binding-public-input"),
    (r"domain[- ]?separation|fiat[- ]?shamir|transcript", "fiat-shamir-domain-confusion"),
    (r"malleab", "proof-malleability"),
    (r"trusted[- ]?setup|tau|ceremony|toxic.*waste", "trusted-setup-bypass"),
    (r"lookup", "circuit-lookup-table-poisoning"),
    (r"degree|spurious.*constraint", "circuit-degree-overflow"),
    (r"verifier.*stale|stale.*(key|vk)", "verifier-stale-key"),
    (r"verifier.*input.*alias|verifier.*alias", "verifier-input-aliasing"),
    (r"precompile|opcode|zkvm|host[- ]?call|program[- ]?counter", "zkvm-opcode-incomplete"),
    (r"recursion|aggregation|batching|conflation", "proof-aggregation-incorrect"),
    (r"merkle|withdrawal.*proof|state[- ]?diff|forced[- ]?inclusion", "withdrawal-merkle-proof-spoof"),
    (r"comparison|enforce_cmp|less[- ]?than|greater[- ]?than|cmp", "circuit-missing-range-check"),
    (r"soundness", "circuit-unconstrained-variable"),
    (r"completeness", "circuit-spurious-constraint"),
]
_DEFAULT_ZK_CLASS = "circuit-unconstrained-variable"


def _map_attack_class(vuln: str, root_cause: str, impact: str) -> str:
    blob = " | ".join([vuln or "", root_cause or "", impact or ""]).lower()
    for pat, cls in _ZK_CLASS_RULES:
        if re.search(pat, blob):
            return cls
    return _DEFAULT_ZK_CLASS


def _dsl_to_target_lang(dsl: str) -> str:
    d = (dsl or "").strip().lower()
    if "circom" in d:
        return "circom"
    if "halo2" in d or "plonky" in d or "arkworks" in d or "gnark" in d or "rust" in d:
        return "rust"
    if "noir" in d:
        return "noir"
    if "cairo" in d:
        return "cairo-zk"
    if "leo" in d:
        return "leo"
    return "any"


def _ts_utc() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stderr(msg: str) -> None:
    sys.stderr.write(f"[{TOOL_NAME} {_ts_utc()}] {msg}\n")
    sys.stderr.flush()


def _slug(text: str, n: int = 40) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "-", (text or "").strip()).strip("-").lower()
    return s[:n] or "zkbug"


def _short_hash(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()[:12]


# --------------------------------------------------------------------------
# Dataset discovery + parsing
# --------------------------------------------------------------------------
def _clone_dataset(dest: Path) -> Path:
    """Shallow git clone of zksecurity/zkbugs. Returns the clone root."""
    _stderr(f"shallow-cloning {ZKBUGS_REPO_URL} -> {dest}")
    subprocess.run(
        ["git", "clone", "--depth", "1", ZKBUGS_REPO_URL, str(dest)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return dest


def _iter_config_files(dataset_root: Path) -> Iterable[Path]:
    """Yield every zkbugs_config.json under the dataset root, sorted for
    deterministic emission."""
    yield from sorted(dataset_root.rglob("zkbugs_config.json"))


def _iter_bug_entries(dataset_root: Path) -> Iterable[Tuple[Path, Dict[str, Any]]]:
    """Yield (config_path, bug_entry_dict) for each bug.

    A zkbugs_config.json maps {"<Bug Title>": {<fields>}}. Some fixtures
    nest the whole dataset in ONE json keyed by config-path; we handle both
    the per-file and the aggregate-fixture shapes.
    """
    for cfg in _iter_config_files(dataset_root):
        try:
            data = json.loads(cfg.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            _stderr(f"skip unparseable {cfg}: {exc}")
            continue
        if not isinstance(data, dict):
            continue
        # Per-file shape: {"<Bug Title>": {...fields...}}
        for _title, entry in data.items():
            if isinstance(entry, dict) and ("Id" in entry or "DSL" in entry):
                yield cfg, entry

    # Aggregate-fixture shape: a single JSON file whose values are
    # {"<config-path>": {"<Bug Title>": {...}}} maps (the test suite uses
    # this so emission is deterministic and offline-friendly).
    for agg in sorted(dataset_root.glob("*.json")):
        if agg.name == "zkbugs_config.json":
            continue
        try:
            data = json.loads(agg.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(data, dict):
            continue
        for _cfgpath, titled in data.items():
            if not isinstance(titled, dict):
                continue
            for _title, entry in titled.items():
                if isinstance(entry, dict) and ("Id" in entry or "DSL" in entry):
                    yield agg, entry


def _count_mandatory(entry: Dict[str, Any]) -> int:
    n = 0
    for f in MANDATORY_FIELDS:
        v = entry.get(f)
        if v not in (None, "", {}, []):
            n += 1
    return n


def _location_str(entry: Dict[str, Any]) -> str:
    loc = entry.get("Location")
    if isinstance(loc, dict):
        parts = []
        if loc.get("Path"):
            parts.append(str(loc["Path"]))
        if loc.get("Function"):
            parts.append(f"::{loc['Function']}")
        if loc.get("Line"):
            parts.append(f":{loc['Line']}")
        return "".join(parts)
    if isinstance(loc, str):
        return loc
    return ""


def _source_link(entry: Dict[str, Any]) -> str:
    src = entry.get("Source")
    if isinstance(src, dict):
        for key in ("Audit Report", "Bug Tracker"):
            sub = src.get(key)
            if isinstance(sub, dict) and sub.get("Source Link"):
                return str(sub["Source Link"])
    return str(entry.get("Project") or "")


def _build_invariant_statement(entry: Dict[str, Any], attack_class: str) -> str:
    """Construct an invariant statement (the canonical SHOULD-hold predicate
    derived from the bug's root cause)."""
    vuln = str(entry.get("Vulnerability") or "").strip()
    root = str(entry.get("Root Cause") or "").strip()
    desc = str(entry.get("Short Description of the Vulnerability") or "").strip()
    mitig = str(entry.get("Proposed Mitigation") or "").strip()
    loc = _location_str(entry)
    parts = [
        f"[{attack_class}] The circuit/prover/verifier MUST NOT exhibit "
        f"'{vuln or root or attack_class}'."
    ]
    if root:
        parts.append(f"Root cause to guard against: {root}.")
    if desc:
        parts.append(f"Bug: {desc}")
    if mitig:
        parts.append(f"Canonical mitigation: {mitig}")
    if loc:
        parts.append(f"Anchor location: {loc}.")
    return " ".join(parts)


# --------------------------------------------------------------------------
# Record emission
# --------------------------------------------------------------------------
def _make_invariant_record(entry: Dict[str, Any], attack_class: str,
                           batch_id: str) -> Dict[str, Any]:
    bug_id = str(entry.get("Id") or "")
    inv_id = f"INV-ZKBUGS-{_slug(bug_id)}-{_short_hash(bug_id)}"
    statement = _build_invariant_statement(entry, attack_class)
    target_lang = _dsl_to_target_lang(str(entry.get("DSL") or ""))
    return {
        "schema_version": "auditooor.invariant.v1",
        "record_id": inv_id,
        "content": {
            "invariant_id": inv_id,
            "statement": statement[:3500],
            "category": attack_class,
            "attack_class": attack_class,
            "target_lang": target_lang,
            "target_language": target_lang,
            "source_findings": [bug_id] if bug_id else [],
            "verification_tier": VERIFICATION_TIER,
            "dsl": str(entry.get("DSL") or ""),
            "impact": str(entry.get("Impact") or ""),
            "fix_commit": str(entry.get("Fix Commit") or ""),
            "vuln_commit": str(entry.get("Commit") or ""),
            "location": _location_str(entry),
            "source_link": _source_link(entry),
            "reproduced": bool(entry.get("Reproduced", False)),
        },
        "source": {
            "batch_id": batch_id,
            "dataset": "zksecurity/zkbugs",
            "bug_id": bug_id,
        },
        "ingested_at_utc": _ts_utc(),
        "generated_by": {
            "tool": TOOL_NAME,
            "tool_version": TOOL_VERSION,
        },
        "verification_tier": VERIFICATION_TIER,
    }


def _make_detector_seed_record(entry: Dict[str, Any], attack_class: str,
                               batch_id: str) -> Dict[str, Any]:
    bug_id = str(entry.get("Id") or "")
    task_id = f"zkbugs-det-{_slug(bug_id)}-{_short_hash(bug_id)}"
    vuln = str(entry.get("Vulnerability") or "")
    root = str(entry.get("Root Cause") or "")
    target_lang = _dsl_to_target_lang(str(entry.get("DSL") or ""))
    # Build a detector-sketch / worklist-predicate from the bug shape.
    det_payload = {
        "detector_id": task_id,
        "attack_class": attack_class,
        "category": attack_class,
        "target_lang": target_lang,
        "target_language": target_lang,
        "detector_sketch": (
            f"Flag {target_lang} circuit/proof code where '{vuln or root}' "
            f"can occur (root cause: {root or vuln}). "
            f"Anchor: {_location_str(entry)}."
        ),
        "worklist_predicate_sketch": _worklist_predicate(attack_class, target_lang),
        "canonical_violation_pattern": root or vuln or attack_class,
        "negative_control_pattern": (
            str(entry.get("Proposed Mitigation") or "")[:600]
            or f"Constraint enforces the {attack_class} guard."
        ),
        "known_corpus_anchor": _source_link(entry),
        "minimum_evidence_to_file": (
            "Soundness/completeness PoC against the vulnerable commit; "
            "negative control against the fix commit."
        ),
        "verification_tier_self_label": VERIFICATION_TIER,
    }
    return {
        "schema_version": "auditooor.detector_seed.v1",
        "record_id": task_id,
        "task_id": task_id,
        "task_type": "zkbugs_detector_seed",
        "status": "ok",
        "result": json.dumps(det_payload),
        "source": {
            "batch_id": batch_id,
            "dataset": "zksecurity/zkbugs",
            "bug_id": bug_id,
        },
        "ingested_at_utc": _ts_utc(),
        "generated_by": {
            "tool": TOOL_NAME,
            "tool_version": TOOL_VERSION,
        },
        "verification_tier": VERIFICATION_TIER,
    }


def _worklist_predicate(attack_class: str, target_lang: str) -> str:
    sketches = {
        "circuit-unconstrained-variable":
            r"signal output without a matching === / <== constraint",
        "circuit-missing-range-check":
            r"comparison / arithmetic on field elements without Num2Bits / range assertion",
        "circuit-aliased-witness":
            r"field-element input used without canonical / alias check",
        "verifier-not-binding-public-input":
            r"public input not folded into the verifier transcript / hash",
        "fiat-shamir-domain-confusion":
            r"transcript challenge derived without domain separation tag",
    }
    base = sketches.get(attack_class, f"pattern matching {attack_class}")
    return f"regex/AST ({target_lang}): {base}"


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------
def _write_yaml_invariant(rec: Dict[str, Any], path: Path) -> None:
    """Write the invariant record in the json-embedded YAML shape that
    promote-mined-to-canonical's _extract_invariant_library_extended reads
    (header comments + '---' + JSON body)."""
    inv_id = rec["content"]["invariant_id"]
    header = (
        "# auditooor-zkbugs-dataset record\n"
        "# schema: auditooor.invariant.v1\n"
        f"# record_id: {rec['record_id']}\n"
        f"# invariant_id: {inv_id}\n"
        "# format: json-embedded\n"
        "---\n"
    )
    path.write_text(header + json.dumps(rec, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


def run(dataset_root: Optional[Path], out_root: Path, batch_id: str,
        dry_run: bool, limit: Optional[int]) -> Dict[str, Any]:
    cleanup_tmp: Optional[tempfile.TemporaryDirectory] = None
    if dataset_root is None:
        cleanup_tmp = tempfile.TemporaryDirectory(prefix="zkbugs-clone-")
        dataset_root = _clone_dataset(Path(cleanup_tmp.name) / "zkbugs")

    inv_dir = out_root / "invariant_library_extended" / batch_id
    det_dir = out_root / "detector_synthesis_v2" / batch_id

    inv_records: List[Dict[str, Any]] = []
    det_records: List[Dict[str, Any]] = []
    skipped = 0
    seen_ids: set = set()

    for cfg, entry in _iter_bug_entries(dataset_root):
        if _count_mandatory(entry) < MIN_MANDATORY:
            skipped += 1
            continue
        bug_id = str(entry.get("Id") or "")
        dedupe_key = bug_id or f"{cfg}:{entry.get('Vulnerability')}"
        if dedupe_key in seen_ids:
            continue
        seen_ids.add(dedupe_key)
        attack_class = _map_attack_class(
            str(entry.get("Vulnerability") or ""),
            str(entry.get("Root Cause") or ""),
            str(entry.get("Impact") or ""),
        )
        inv_records.append(_make_invariant_record(entry, attack_class, batch_id))
        det_records.append(_make_detector_seed_record(entry, attack_class, batch_id))
        if limit is not None and len(inv_records) >= limit:
            break

    if not dry_run:
        inv_dir.mkdir(parents=True, exist_ok=True)
        det_dir.mkdir(parents=True, exist_ok=True)
        for rec in inv_records:
            _write_yaml_invariant(rec, inv_dir / f"{rec['record_id']}.yaml")
        for rec in det_records:
            (det_dir / f"{rec['record_id']}.json").write_text(
                json.dumps(rec, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if cleanup_tmp is not None:
        cleanup_tmp.cleanup()

    # R37 self-audit: every emitted record carries a non-empty tier.
    bad_tier = [r["record_id"] for r in (inv_records + det_records)
                if not r.get("verification_tier")]

    return {
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "batch_id": batch_id,
        "dataset_root": str(dataset_root),
        "out_root": str(out_root),
        "dry_run": dry_run,
        "records_mined": len(inv_records) + len(det_records),
        "invariant_records": len(inv_records),
        "detector_seed_records": len(det_records),
        "skipped_insufficient_fields": skipped,
        "verification_tier": VERIFICATION_TIER,
        "records_missing_tier": bad_tier,
        "inv_out_dir": str(inv_dir),
        "det_out_dir": str(det_dir),
        "promote_hint": (
            "python3 tools/promote-mined-to-canonical.py "
            f"--batch-id {batch_id}"
        ),
        "ts_utc": _ts_utc(),
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset-root", type=Path, default=None,
                    help="Path to a local zkbugs checkout (dir containing "
                         "dataset/**/zkbugs_config.json). Omit to shallow-clone "
                         "zksecurity/zkbugs into a tmp dir.")
    ap.add_argument("--out-root", type=Path, default=DERIVED_ROOT,
                    help="Derived-corpus root to write into "
                         "(default: audit/corpus_tags/derived).")
    ap.add_argument("--batch-id", default=None,
                    help="Batch id (default: zkbugs-dataset-<UTC date>).")
    ap.add_argument("--limit", type=int, default=None,
                    help="Cap the number of bugs mined (debug).")
    ap.add_argument("--dry-run", action="store_true",
                    help="Parse + count but do not write any files.")
    ap.add_argument("--json-summary", action="store_true",
                    help="Print the summary as JSON to stdout.")
    args = ap.parse_args(argv)

    batch_id = args.batch_id or f"zkbugs-dataset-{_dt.datetime.now(_dt.timezone.utc).strftime('%Y-%m-%d')}"

    try:
        summary = run(args.dataset_root, args.out_root, batch_id,
                      args.dry_run, args.limit)
    except subprocess.CalledProcessError as exc:
        _stderr(f"git clone failed: {exc.stderr.decode('utf-8', 'replace') if exc.stderr else exc}")
        return 3
    except Exception as exc:  # noqa: BLE001
        _stderr(f"error: {exc}")
        return 3

    if args.json_summary:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[{TOOL_NAME}] batch={summary['batch_id']} "
              f"records_mined={summary['records_mined']} "
              f"(inv={summary['invariant_records']} det={summary['detector_seed_records']}) "
              f"skipped={summary['skipped_insufficient_fields']} "
              f"tier={summary['verification_tier']} dry_run={summary['dry_run']}")
        print(f"  promote: {summary['promote_hint']}")

    if summary["records_missing_tier"]:
        _stderr(f"R37 VIOLATION: {len(summary['records_missing_tier'])} records missing tier")
        return 3
    if summary["records_mined"] == 0:
        _stderr("no records mined (0 entries with >=3 mandatory fields)")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
