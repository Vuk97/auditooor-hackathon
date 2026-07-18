#!/usr/bin/env python3
"""Map indexed zkBugs rows into Base-relevant detector/replay tasks.

The zkBugs ingest/brief queue proves corpus accounting. This mapper performs
the next conversion step: keep only rows that either match an existing local
detector family or touch a Base proof-verifier/TEE/SP1 glue surface, and make
the required detector/replay task explicit. Generic circuit bugs are recorded
as excluded noise so future agents do not re-triage the same rows.
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


SCHEMA = "auditooor.zkbugs_detectorization_map.v1"
REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class MappingRule:
    rule_id: str
    lane: str
    task_kind: str
    detectors: tuple[str, ...]
    keywords: tuple[str, ...]
    dsl: tuple[str, ...] = ()
    base_anchors: tuple[str, ...] = ()
    harness_task: str = ""
    kill_criteria: str = ""


DETECTOR_RULES: tuple[MappingRule, ...] = (
    MappingRule(
        rule_id="circom-num2bits-state-alias",
        lane="existing-circom-detector",
        task_kind="detector_replay_task",
        detectors=("detectors/circom_wave1/zkbugs_num2bits_254_state_alias.py",),
        dsl=("Circom",),
        keywords=("num2bits", "254", "blacklist", "state", "representable"),
        harness_task="Run the Circom detector on candidate circuits and keep only state/flag leaves with high-bit semantics.",
        kill_criteria="Kill if the Num2Bits width is not tied to state/flag encoding or the value is separately range constrained.",
    ),
    MappingRule(
        rule_id="circom-babyjubjub-suborder",
        lane="existing-circom-detector",
        task_kind="detector_replay_task",
        detectors=("detectors/circom_wave1/zkbugs_babyjubjub_suborder_tag.py",),
        dsl=("Circom",),
        keywords=("babyjub", "suborder", "subgroup", "public key"),
        harness_task="Run the BabyJubJub suborder detector and require a forged-key or subgroup-clean negative fixture.",
        kill_criteria="Kill if the key is already subgroup-cleared or the subgroup check is delegated to a proven library wrapper.",
    ),
    MappingRule(
        rule_id="circom-nullifier-disabled",
        lane="existing-circom-detector",
        task_kind="detector_replay_task",
        detectors=("detectors/circom_wave1/zkbugs_zswap_nullifier_verification_disabled.py",),
        dsl=("Circom",),
        keywords=("nullifier", "zswap", "double spend", "spent"),
        harness_task="Run the nullifier detector and require a double-use replay fixture before promotion.",
        kill_criteria="Kill if Base has no Circom nullifier circuit on the path or nullification is enforced outside the circuit.",
    ),
    MappingRule(
        rule_id="circom-comparison-range",
        lane="existing-circom-detector",
        task_kind="detector_replay_task",
        detectors=("detectors/circom_wave1/zkbugs_unirep_comparison_range_checks.py",),
        dsl=("Circom",),
        keywords=("comparison", "range", "less than", "unirep", "alias"),
        harness_task="Run the range-comparison detector and require witness values outside the intended domain.",
        kill_criteria="Kill if all compared operands are bit/range constrained before comparison.",
    ),
    MappingRule(
        rule_id="circom-blake3-nova-treepath",
        lane="existing-circom-detector",
        task_kind="detector_replay_task",
        detectors=("detectors/circom_wave1/zkbugs_blake3novatreepath_checkdepth_comparator_range.py",),
        dsl=("Circom",),
        keywords=("blake3", "nova", "tree", "depth", "merkle"),
        harness_task="Run the tree-depth detector and require clean/vulnerable path-depth fixtures.",
        kill_criteria="Kill if the tree depth is fixed by construction before the comparator path.",
    ),
    MappingRule(
        rule_id="rust-bellperson-zero-default",
        lane="existing-rust-detector",
        task_kind="detector_replay_task",
        detectors=("detectors/rust_wave1/zkbugs_bellperson_unconstrained_zero_default.py",),
        dsl=("Bellperson",),
        keywords=("zero", "default", "selector", "multicase", "pick", "lurk"),
        harness_task="Run the Bellperson detector on Rust circuit code and require a non-zero default witness replay.",
        kill_criteria="Kill if the default witness is constrained to zero or the selector path is unreachable.",
    ),
    MappingRule(
        rule_id="rust-fixed-point-field-arithmetic",
        lane="existing-rust-detector",
        task_kind="detector_replay_task",
        detectors=("detectors/rust_wave1/zkbugs_unsound_fixed_point_addition.py",),
        dsl=("Arkworks",),
        keywords=("fixed-point", "fixed point", "addition", "multiplication", "comparison", "accepted"),
        harness_task="Run the fixed-point arithmetic detector and require a concrete accepted-invalid arithmetic witness.",
        kill_criteria="Kill if arithmetic is only off-circuit bookkeeping or is constrained by a canonical field gadget.",
    ),
)


BASE_GLUE_RULES: tuple[MappingRule, ...] = (
    MappingRule(
        rule_id="base-untrusted-length-allocation",
        lane="base-rust-replay-task",
        task_kind="replay_or_detector_task",
        detectors=("tools/base-rust-swival-shape-scan.py",),
        dsl=("Plonky3", "risc0", "Bellperson", "Arkworks"),
        keywords=("allocator overflow", "allocation", "length", "capacity", "read_vec", "overflow"),
        base_anchors=("external/base-rc28-clean/crates/proof/tee/nitro-enclave/src/transport.rs",),
        harness_task="Replay oversized untrusted frame/length input against Base Rust transport/parser code and assert bounded error before allocation.",
        kill_criteria="Kill if the length is trusted/local-only, capped before allocation, or cannot be driven by a non-privileged proof/challenge path.",
    ),
    MappingRule(
        rule_id="base-sp1-verifier-metadata-binding",
        lane="base-zkverifier-invariant",
        task_kind="base_glue_invariant_task",
        detectors=(),
        dsl=("Plonky3",),
        keywords=("sp1", "vk_root", "chip_ordering", "stark verifier", "fri", "recursive", "is_complete", "verifier"),
        base_anchors=(
            "external/contracts/src/multiproof/zk/ZKVerifier.sol",
            "external/contracts/src/multiproof/AggregateVerifier.sol",
            "external/base-rc28-clean/crates/succinct/programs/aggregation/src/main.rs",
            "external/base-rc28-clean/crates/succinct/validity/src/proposer.rs",
        ),
        harness_task="Build a Base adapter invariant: invalid SP1 proof metadata must revert, and public values must bind range vkey, aggregate image id, proposer, and game context.",
        kill_criteria="Kill if the exact verifier implementation is unavailable, or source proof shows the metadata is already bound before Base accepts the proof.",
    ),
    MappingRule(
        rule_id="base-zkvm-instruction-soundness",
        lane="base-zkvm-dependency-invariant",
        task_kind="base_glue_invariant_task",
        detectors=(),
        dsl=("risc0",),
        keywords=("zkvm", "rv32", "instruction", "division", "multi-step", "execute"),
        base_anchors=(
            "external/contracts/src/multiproof/zk/ZKVerifier.sol",
            "external/contracts/src/multiproof/AggregateVerifier.sol",
        ),
        harness_task="Keep as dependency-semantics work only: prove a configured Base verifier can accept the zkVM-invalid trace before any finding language.",
        kill_criteria="Kill unless Base glue actually routes this proof system into an in-scope state proof acceptance path.",
    ),
)


def _norm(value: object) -> str:
    return str(value or "")


def _haystack(record: dict[str, Any]) -> str:
    fields = (
        "bug_id",
        "title",
        "dsl",
        "vulnerability",
        "root_cause",
        "impact",
        "short_vulnerability",
        "short_exploit",
        "proposed_mitigation",
        "location_path",
        "location_function",
    )
    return "\n".join(_norm(record.get(field)) for field in fields).lower()


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:96] or "zkbugs-row"


def _detectors_present(detectors: tuple[str, ...]) -> list[str]:
    return [path for path in detectors if (REPO_ROOT / path).is_file()]


def _matches(rule: MappingRule, record: dict[str, Any]) -> bool:
    dsl = _norm(record.get("dsl")).lower()
    if rule.dsl and dsl not in {item.lower() for item in rule.dsl}:
        return False
    hay = _haystack(record)
    if rule.rule_id == "circom-num2bits-state-alias":
        return (
            "num2bits" in hay
            or "blacklist states" in hay
            or "not representable" in hay
            or ("representable" in hay and "field" in hay)
        )
    if rule.rule_id == "circom-babyjubjub-suborder":
        return (
            "babyjub" in hay
            or ("suborder" in hay and ("constraint" in hay or "check" in hay))
            or ("point doubling" in hay and ("signature" in hay or "forgery" in hay))
        )
    if rule.rule_id == "circom-nullifier-disabled":
        return "nullifier" in hay or "zswap" in hay or "double spend" in hay
    if rule.rule_id == "circom-comparison-range":
        return (
            "comparison" in hay
            or "range check" in hay
            or "range checks" in hay
            or "lessthan" in hay
            or "greatereqthan" in hay
            or "less than" in hay
            or "greater" in hay
        )
    if rule.rule_id == "circom-blake3-nova-treepath":
        return "blake3" in hay or ("tree" in hay and "depth" in hay)
    if rule.rule_id == "rust-bellperson-zero-default":
        return (
            "zero" in hay
            or "default" in hay
            or "selector" in hay
            or "multicase" in hay
            or "padding" in hay
        )
    if rule.rule_id == "rust-fixed-point-field-arithmetic":
        return "fixed-point" in hay or "fixed point" in hay
    if rule.rule_id == "base-sp1-verifier-metadata-binding":
        return (
            "sp1" in hay
            or "vk_root" in hay
            or "chip_ordering" in hay
            or "stark verifier" in hay
            or "fri" in hay
            or "recursive verifier" in hay
            or "is_complete" in hay
            or ("babybear" in hay and "range" in hay)
        )
    if rule.rule_id == "base-zkvm-instruction-soundness":
        return "zkvm" in hay or "rv32" in hay or ("instruction" in hay and "risc0" in dsl)
    if rule.rule_id == "base-untrusted-length-allocation":
        return (
            "allocator overflow" in hay
            or "read_vec" in hay
            or ("allocation" in hay and ("overflow" in hay or "capacity" in hay or "length" in hay))
        )
    return any(keyword.lower() in hay for keyword in rule.keywords)


def _select_rule(record: dict[str, Any]) -> MappingRule | None:
    for rule in DETECTOR_RULES:
        if _matches(rule, record) and _detectors_present(rule.detectors):
            return rule
    for rule in BASE_GLUE_RULES:
        if _matches(rule, record):
            return rule
    return None


def _row_from_rule(record: dict[str, Any], rule: MappingRule) -> dict[str, Any]:
    source_id = _norm(record.get("bug_id") or record.get("title"))
    return {
        "row_id": f"{rule.rule_id}__{_slug(source_id)}",
        "corpus": "zkbugs",
        "source_id": source_id,
        "title": _norm(record.get("title")),
        "dsl": _norm(record.get("dsl")),
        "vulnerability": _norm(record.get("vulnerability")),
        "root_cause": _norm(record.get("root_cause")),
        "impact": _norm(record.get("impact")),
        "priority_score": int(record.get("priority_score") or 0),
        "location": {
            "path": _norm(record.get("location_path")),
            "function": _norm(record.get("location_function")),
            "line": _norm(record.get("location_line")),
        },
        "rule_id": rule.rule_id,
        "lane": rule.lane,
        "task_kind": rule.task_kind,
        "detector_paths": list(rule.detectors),
        "detector_paths_present": _detectors_present(rule.detectors),
        "base_anchors": list(rule.base_anchors),
        "candidate_kind": "detector_or_invariant_task_candidate",
        "submission_posture": "NOT_SUBMIT_READY",
        "severity": "none",
        "selected_impact": "",
        "impact_contract_required": True,
        "impact_contract_id": "",
        "harness_task": rule.harness_task,
        "kill_criteria": rule.kill_criteria,
        "source_links": record.get("source_links") or [],
        "report_files": record.get("report_files") or [],
        "commands": record.get("commands") or {},
    }


def _detector_hit_v2_row(record: dict[str, Any], rule: MappingRule) -> dict[str, Any]:
    """Build a sidecar detector_hits_v2 row merging v2 circuit metadata into a hit."""
    bug_id = _norm(record.get("bug_id") or record.get("title"))
    template_name = _norm(record.get("template_name") or record.get("location_function"))
    signal_names = record.get("signal_names") or []
    if not isinstance(signal_names, list):
        signal_names = []
    # Derive a short hit excerpt from short_vulnerability
    short_vuln = _norm(record.get("short_vulnerability"))
    hit_excerpt = short_vuln[:200] if short_vuln else ""
    # hit_line: use location_line when available
    hit_line_raw = _norm(record.get("location_line"))
    try:
        hit_line = int(hit_line_raw.split("-")[0]) if hit_line_raw else 0
    except ValueError:
        hit_line = 0
    detector_id = (
        rule.detectors[0].replace("/", ".").replace(".py", "")
        if rule.detectors
        else f"base_glue.{rule.rule_id}"
    )
    return {
        "bug_id": bug_id,
        "template_name": template_name,
        "signal_names": signal_names[:8],
        "detector_id": detector_id,
        "hit_line": hit_line,
        "hit_excerpt": hit_excerpt,
    }


def build_payload(workspace: Path, index_path: Path) -> dict[str, Any]:
    index = json.loads(index_path.read_text(encoding="utf-8"))
    records = index.get("records") or []
    if not isinstance(records, list):
        raise SystemExit(f"[zkbugs-detectorization-map] invalid records array in {index_path}")

    rows: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    detector_hits_v2: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        rule = _select_rule(record)
        if rule is None:
            excluded.append(
                {
                    "source_id": _norm(record.get("bug_id") or record.get("title")),
                    "title": _norm(record.get("title")),
                    "dsl": _norm(record.get("dsl")),
                    "reason": "no_existing_detector_or_base_glue_anchor",
                }
            )
            continue
        rows.append(_row_from_rule(record, rule))
        detector_hits_v2.append(_detector_hit_v2_row(record, rule))

    rows.sort(key=lambda row: (-int(row["priority_score"]), row["lane"], row["title"]))
    by_lane: dict[str, int] = {}
    by_task_kind: dict[str, int] = {}
    for row in rows:
        by_lane[row["lane"]] = by_lane.get(row["lane"], 0) + 1
        by_task_kind[row["task_kind"]] = by_task_kind.get(row["task_kind"], 0) + 1

    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "workspace": str(workspace),
        "source_index": str(index_path),
        "summary": {
            "index_records": len(records),
            "queued_rows": len(rows),
            "excluded_rows": len(excluded),
            "by_lane": by_lane,
            "by_task_kind": by_task_kind,
        },
        "rows": rows,
        "detector_hits_v2": detector_hits_v2,
        "excluded_sample": excluded[:40],
        "proof_boundary": (
            "Rows are detector/replay/invariant tasks only. They are not findings, "
            "do not select severity, and require an exact Base impact contract plus "
            "executed replay before promotion."
        ),
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# zkBugs Detectorization Map",
        "",
        f"- Source index: `{payload['source_index']}`",
        f"- Indexed records: `{summary['index_records']}`",
        f"- Queued detector/replay/invariant rows: `{summary['queued_rows']}`",
        f"- Excluded noise rows: `{summary['excluded_rows']}`",
        "",
        "## Queued Rows",
        "",
        "| Lane | Task | Priority | DSL | Source | Detector / Anchor |",
        "|---|---|---:|---|---|---|",
    ]
    for row in payload["rows"]:
        refs = row["detector_paths_present"] or row["detector_paths"] or row["base_anchors"]
        ref_text = "<br>".join(f"`{ref}`" for ref in refs[:3])
        if len(refs) > 3:
            ref_text += f"<br>`+{len(refs) - 3} more`"
        source = row["title"].replace("|", "\\|")
        lines.append(
            f"| `{row['lane']}` | `{row['task_kind']}` | {row['priority_score']} | "
            f"`{row['dsl']}` | {source} | {ref_text} |"
        )
    lines.extend(
        [
            "",
            "## Lane Counts",
            "",
        ]
    )
    for lane, count in sorted(summary["by_lane"].items()):
        lines.append(f"- `{lane}`: `{count}`")
    lines.extend(["", "## Excluded Sample", ""])
    for row in payload["excluded_sample"][:20]:
        lines.append(f"- `{row['dsl']}` `{row['source_id']}`: {row['reason']}")
    lines.extend(["", "## Boundary", "", payload["proof_boundary"]])
    return "\n".join(lines) + "\n"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--zkbugs-index", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    parser.add_argument("--strict-empty", action="store_true", help="Exit 2 if no rows are queued")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    workspace = args.workspace.expanduser().resolve()
    index_path = (
        args.zkbugs_index.expanduser().resolve()
        if args.zkbugs_index
        else workspace / ".audit_logs" / "zkbugs_farming" / "zkbugs_index.json"
    )
    if not workspace.is_dir():
        print(f"[zkbugs-detectorization-map] ERR workspace not found: {workspace}")
        return 2
    if not index_path.is_file():
        print(f"[zkbugs-detectorization-map] ERR zkBugs index not found: {index_path}")
        return 2

    payload = build_payload(workspace, index_path)
    out_json = args.out_json or workspace / ".auditooor" / "zkbugs_detectorization_map.json"
    out_md = args.out_md or workspace / ".auditooor" / "zkbugs_detectorization_map.md"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(payload), encoding="utf-8")

    # Write sidecar detector_hits_v2.jsonl
    hits_dir = workspace / "audit" / "zkbugs"
    hits_dir.mkdir(parents=True, exist_ok=True)
    hits_path = hits_dir / "detector_hits_v2.jsonl"
    with hits_path.open("w", encoding="utf-8") as fh:
        for hit in payload.get("detector_hits_v2") or []:
            fh.write(json.dumps(hit, sort_keys=True) + "\n")

    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"[zkbugs-detectorization-map] wrote {out_json}")
        print(f"[zkbugs-detectorization-map] wrote {out_md}")
        print(f"[zkbugs-detectorization-map] wrote {hits_path}")
        print(
            "[zkbugs-detectorization-map] "
            f"{payload['summary']['queued_rows']} queued, {payload['summary']['excluded_rows']} excluded"
        )
    if args.strict_empty and payload["summary"]["queued_rows"] == 0:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
