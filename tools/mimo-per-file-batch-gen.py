#!/usr/bin/env python3
# r36-rebuttal: lane MIMO-PERFILE-BATCH-GEN registered via agent-pathspec-register
"""mimo-per-file-batch-gen.py - proper per-file MIMO batch generator.

GENERAL fix for the function_anchor bug in per-fn-mimo-batch-gen.py:
- per-fn-mimo-batch-gen expects pre-ranked per-fn input that doesn't exist
  for most workspaces -> produces file:'?' fn:'?' empty anchors -> R76 hallucinations
- This tool instead enumerates ACTUAL workspace files, includes file contents
  in each prompt, and pairs (file, question) cartesianally with hacker-Q
  target_contract_patterns / target_function_patterns regex matching for
  relevance.

GENERAL fix also wires:
- Dead-end filter (skip already-killed file × attack_class pairs)
- Coverage-aware: ranks UNCOVERED files higher than already-mined files
- OOS filter (workspace BUG_BOUNTY.md / SCOPE.md exclusion catalog)
- Workspace-specific exclusion (test/, mock/, lib/, out/, cache/, node_modules/)
- File-size cap (skip > MAX_BYTES; MIMO context limit)

SPECIFIC behaviour per workspace:
- workspace passed as --workspace path; scope inferred from SCOPE.md if present
- BUG_BOUNTY.md OOS catalog auto-loaded if present
- known_dead_ends filter applied per workspace name

Output: JSONL ready for llm-fanout-dispatcher --task-batch
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

SCHEMA = "auditooor.mimo_per_file_batch.v2"

# General workspace exclusions (apply to all)
EXCLUDE_PATH_PARTS = {
    "/test/", "/tests/", "/mock/", "/mocks/", "/lib/",
    "/out/", "/cache/", "/node_modules/", "/.git/",
    "/dependencies/", "/forge-std/", "/_archive/",
    "/script/", "/scripts/",
    "/audit/", "/audits/",
    "/agent_outputs/", "/.auditooor/",
    "/external/",
}

GENERAL_OOS_HINTS = (
    "trusted/untrusted roles",
    "acknowledged by design",
    "centralization risks",
    "front-running",
    "rounding errors",
    "informational",
    "user errors",
    "gas optimization",
    "naming conventions",
    "magic numbers",
)

MAX_FILE_BYTES = 20_000
TRUNCATE_SUFFIX = "\n// ... [TRUNCATED] ...\n"
MCP_CONTEXT_ITEM_CAP = 1_200
AGI_CONTEXT_BLOCK_CAP = 6_000
SIGNATURE_BLOCK_LIMIT = 8
KNOWN_DEAD_END_BLOCK_LIMIT = 5

SUPPORTED_EXTS = {".sol", ".rs", ".go", ".vy", ".move", ".cairo"}
REPO_ROOT = Path(__file__).resolve().parent.parent
VAULT_MCP = Path(__file__).resolve().parent / "vault-mcp-server.py"


def load_dead_ends(path: Path, workspace_name: str) -> set:
    if not path.exists():
        return set()
    out = set()
    for ln in path.read_text().splitlines():
        try:
            d = json.loads(ln)
            if d.get("workspace") != workspace_name:
                continue
            file_field = (d.get("file") or "").lower()
            ac = (d.get("attack_class") or "").lower()
            if file_field and ac:
                for f in re.split(r"[,\s]+", file_field):
                    if f:
                        out.add((f.strip(), ac.strip()))
        except Exception:
            continue
    return out


def load_dead_end_records(path: Path, workspace_name: str) -> list[dict]:
    if not path.exists():
        return []
    out: list[dict] = []
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not ln.strip():
            continue
        try:
            row = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if row.get("workspace") != workspace_name:
            continue
        out.append(row)
    return out


def load_oos_catalog(workspace_path: Path) -> list:
    phrases = []
    for name in ("BUG_BOUNTY.md", "SCOPE.md", "SEVERITY.md"):
        for p in workspace_path.rglob(name):
            try:
                text = p.read_text(errors="ignore").lower()
                for ln in text.splitlines():
                    if any(k in ln for k in ("oos", "out of scope", "excluded", "out-of-scope", "not eligible", "won't fix", "wontfix", "acknowledged", "informational only")):
                        phrases.append(ln.strip()[:200])
            except Exception:
                continue
    return sorted(set(phrases))


def resolve_scan_root(workspace: Path, explicit_scan_root: str | None) -> tuple[Path, str]:
    if explicit_scan_root:
        scan_root = Path(explicit_scan_root).expanduser()
        if not scan_root.is_absolute():
            scan_root = workspace / scan_root
        return scan_root.resolve(), "cli"
    override_path = workspace / ".auditooor" / "scan_root.txt"
    if override_path.is_file():
        raw = override_path.read_text(encoding="utf-8", errors="replace").strip()
        if raw:
            scan_root = Path(raw).expanduser()
            if not scan_root.is_absolute():
                scan_root = workspace / scan_root
            return scan_root.resolve(), str(override_path)
    return workspace, "workspace"


def enumerate_workspace_files(scan_root: Path, workspace: Path) -> list:
    files = []
    for p in scan_root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix not in SUPPORTED_EXTS:
            continue
        try:
            rel = "/" + p.relative_to(scan_root).as_posix()
        except ValueError:
            rel = str(p).replace(str(workspace), "")
        if any(x in rel for x in EXCLUDE_PATH_PARTS):
            continue
        files.append(p)
    return sorted(files)


def load_coverage_uncovered(heatmap_path: Path) -> set:
    if not heatmap_path.exists():
        return set()
    text = heatmap_path.read_text()
    uncov = re.search(r"## UNCOVERED.*?(?=^## |\Z)", text, re.DOTALL | re.MULTILINE)
    if not uncov:
        return set()
    return set(re.findall(r"`([^`]+\.(?:sol|rs|go|vy|move|cairo))`", uncov.group()))


def latest_reweight_path(base_dir: Path) -> Path | None:
    paths = sorted(base_dir.glob("hacker_q_reweight_*.jsonl"))
    return paths[-1] if paths else None


def load_reweight_scores(path: Path | None) -> dict[str, dict]:
    if path is None or not path.exists():
        return {}
    out: dict[str, dict] = {}
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not ln.strip():
            continue
        try:
            row = json.loads(ln)
        except json.JSONDecodeError:
            continue
        qid = str(row.get("question_id") or "").strip()
        if not qid:
            continue
        out[qid] = row
    return out


def language_from_suffix(path: Path) -> str:
    return {
        ".sol": "solidity",
        ".rs": "rust",
        ".go": "go",
        ".vy": "vyper",
        ".move": "move",
        ".cairo": "cairo",
    }.get(path.suffix, path.suffix.lstrip(".") or "unknown")


def line_no_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, max(offset, 0)) + 1


def extract_function_signatures(text: str, suffix: str) -> list[dict]:
    patterns = {
        ".sol": r"\bfunction\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^;\n{]*\)[^;\n{]*",
        ".rs": r"(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^;\n{]*\)(?:\s*->\s*[^;\n{]+)?",
        ".go": r"func\s+(?:\([^)]*\)\s*)?[A-Za-z_][A-Za-z0-9_]*\s*\([^;\n{]*\)(?:\s*[^;\n{]+)?",
        ".move": r"(?:public\s+)?(?:entry\s+)?fun\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^;\n{]*\)(?:\s*:\s*[^;\n{]+)?",
        ".vy": r"def\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^;\n{]*\)(?:\s*->\s*[^:\n]+)?",
        ".cairo": r"(?:pub\s+)?fn\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^;\n{]*\)(?:\s*->\s*[^;\n{]+)?",
    }
    pat = patterns.get(suffix)
    if not pat:
        return []
    out: list[dict] = []
    for m in re.finditer(pat, text, re.MULTILINE):
        sig = " ".join(m.group(0).split())
        params_blob = ""
        if "(" in sig and ")" in sig:
            params_blob = sig[sig.find("(") + 1:sig.rfind(")")]
        params = [p.strip() for p in params_blob.split(",") if p.strip()]
        markers = []
        lower = sig.lower()
        for marker in ("view", "pure", "payable", "external", "public", "private", "internal", "entry", "async"):
            if re.search(rf"\b{re.escape(marker)}\b", lower):
                markers.append(marker)
        out.append({
            "line": line_no_for_offset(text, m.start()),
            "signature": sig[:240],
            "param_count": len(params),
            "markers": markers[:6],
        })
        if len(out) >= SIGNATURE_BLOCK_LIMIT:
            break
    return out


def state_write_fingerprint(text: str) -> dict:
    return {
        "assignment_like_lines": len(re.findall(r"(?m)^\s*(?:self\.|[A-Za-z_][A-Za-z0-9_]*\.)?[A-Za-z_][A-Za-z0-9_\[\].]*\s*(?:=|\+=|-=)", text)),
        "mapping_or_index_writes": len(re.findall(r"\[[^\]]+\]\s*(?:=|\+=|-=)", text)),
        "external_call_tokens": len(re.findall(r"\.(?:call|delegatecall|staticcall|transfer|send)\b|IERC20|safeTransfer|invoke_contract|call_contract", text)),
        "event_or_log_tokens": len(re.findall(r"\b(?:emit|Event|log::|println!)\b", text)),
    }


def compact_json(obj: object, cap: int = MCP_CONTEXT_ITEM_CAP) -> str:
    try:
        text = json.dumps(obj, sort_keys=True, ensure_ascii=True)
    except TypeError:
        text = str(obj)
    return text[:cap]


def fetch_mcp_context(workspace_path: Path, callable_name: str, extra_args: dict,
                      cap: int = MCP_CONTEXT_ITEM_CAP) -> dict:
    args = {"workspace_path": str(workspace_path)}
    args.update(extra_args)
    cmd = ["python3", str(VAULT_MCP), "--call", callable_name,
           "--args", json.dumps(args)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=25, check=False)
    except subprocess.TimeoutExpired:
        return {"callable": callable_name, "status": "soft-fail", "reason": "timeout", "text": ""}
    except Exception as exc:
        return {"callable": callable_name, "status": "soft-fail", "reason": type(exc).__name__, "text": ""}
    raw = (result.stdout or "").strip() or (result.stderr or "").strip()
    status = "ok" if result.returncode == 0 and raw else "soft-fail"
    reason = "" if status == "ok" else f"returncode={result.returncode}"
    try:
        parsed = json.loads(raw) if raw else {}
        text = compact_json(parsed, cap)
        pack_id = parsed.get("context_pack_id") if isinstance(parsed, dict) else ""
    except json.JSONDecodeError:
        text = raw[:cap]
        pack_id = ""
    return {
        "callable": callable_name,
        "status": status,
        "reason": reason,
        "context_pack_id": pack_id,
        "text": text,
    }


def relevant_dead_end_rows(rows: list[dict], rel_path: str, attack_class: str) -> list[dict]:
    rel_lower = rel_path.lower()
    file_name = Path(rel_path).name.lower()
    ac_lower = attack_class.lower()
    hits: list[dict] = []
    for row in rows:
        row_file = str(row.get("file") or row.get("file_path") or "").lower()
        row_ac = str(row.get("attack_class") or "").lower()
        row_text = json.dumps(row, ensure_ascii=True).lower()
        if (
            (row_file and (row_file in rel_lower or file_name in row_file))
            or (ac_lower and row_ac == ac_lower)
            or (ac_lower and ac_lower in row_text and file_name in row_text)
        ):
            hits.append(row)
        if len(hits) >= KNOWN_DEAD_END_BLOCK_LIMIT:
            break
    return hits


def build_attack_context_cache_entry(workspace_path: Path, attack_class: str,
                                     language: str) -> tuple[str, list[dict]]:
    if not attack_class or attack_class == "?":
        return "=== ATTACK-CLASS CONTEXT ===\n- unavailable: question has no attack_class_anchor\n", []
    snippets: list[dict] = [
        fetch_mcp_context(workspace_path, "vault_attack_class_evidence_v3", {
            "attack_class": attack_class,
            "target_language": language,
            "limit": 5,
            "min_verification_tier": 2,
            "exclude_quarantine": True,
            "with_fixtures": True,
            "cross_language_neighbors": True,
            "neighbor_limit": 3,
        }),
        fetch_mcp_context(workspace_path, "vault_anti_pattern_corpus", {
            "query": attack_class.replace("-", " "),
            "limit": 3,
            "body_chars": 450,
        }),
        fetch_mcp_context(workspace_path, "vault_exploit_narratives_synthesized", {
            "max_narratives": 3,
        }),
    ]
    lines = ["=== ATTACK-CLASS EVIDENCE AND GUARDRAILS ==="]
    for snip in snippets:
        header = f"### MCP {snip['callable']} [{snip['status']}]"
        if snip.get("reason"):
            header += f" {snip['reason']}"
        lines.append(header)
        lines.append(str(snip.get("text") or "<no context available>"))
    return "\n".join(lines)[:AGI_CONTEXT_BLOCK_CAP], snippets


def build_agi_context_block(workspace_path: Path, rel_path: str, file_path: Path,
                            file_contents: str, question: dict,
                            dead_end_rows: list[dict],
                            reweight_record: dict | None,
                            attack_context_cache: dict) -> tuple[str, dict]:
    attack_class = str(question.get("attack_class_anchor") or "?")
    language = language_from_suffix(file_path)
    sigs = extract_function_signatures(file_contents, file_path.suffix)
    fingerprint = state_write_fingerprint(file_contents)
    cache_key = (attack_class, language)
    if cache_key not in attack_context_cache:
        attack_context_cache[cache_key] = build_attack_context_cache_entry(
            workspace_path, attack_class, language
        )
    attack_block, mcp_meta = attack_context_cache[cache_key]
    dead_hits = relevant_dead_end_rows(dead_end_rows, rel_path, attack_class)
    dead_lines = ["=== KNOWN DEAD-ENDS - DO NOT RE-INVESTIGATE ==="]
    if dead_hits:
        for row in dead_hits:
            dead_lines.append("- " + compact_json(row, 800))
    else:
        dead_lines.append("- no scoped dead-end row matched this file and attack class")
    reweight_lines = ["=== HACKER-Q REWEIGHT SCORE ==="]
    if reweight_record:
        reweight_lines.append(compact_json({
            "signal_score": reweight_record.get("signal_score", 0),
            "signal_class": reweight_record.get("signal_class", "unknown"),
            "yes_count": reweight_record.get("yes_count", 0),
            "maybe_count": reweight_record.get("maybe_count", 0),
            "no_count": reweight_record.get("no_count", 0),
            "total_evals": reweight_record.get("total_evals", 0),
        }, 700))
    else:
        reweight_lines.append("- unavailable: no matching reweight ledger row")
    shape_lines = ["=== FUNCTION SIGNATURE SHAPE AND LOCAL FINGERPRINT ==="]
    shape_lines.append(compact_json({
        "language": language,
        "file": rel_path,
        "function_signatures": sigs,
        "state_write_fingerprint": fingerprint,
    }, 1_800))
    block = "\n".join([
        "\n".join(shape_lines),
        "\n".join(dead_lines),
        "\n".join(reweight_lines),
        attack_block,
    ])[:AGI_CONTEXT_BLOCK_CAP]
    metadata = {
        "schema": "auditooor.mimo_prompt_context_feed.v1",
        "attack_class": attack_class,
        "language": language,
        "context_sha256": hashlib.sha256(block.encode("utf-8")).hexdigest(),
        "context_fields": [
            "function_signature_shape",
            "state_write_fingerprint",
            "known_dead_ends_verbatim",
            "hacker_q_reweight_score",
            "attack_class_evidence",
            "anti_patterns",
            "exploit_narratives",
        ],
        "function_signature_count": len(sigs),
        "known_dead_end_matches": len(dead_hits),
        "has_reweight_record": bool(reweight_record),
        "mcp_calls": [
            {
                "callable": m.get("callable"),
                "status": m.get("status"),
                "context_pack_id": m.get("context_pack_id", ""),
                "reason": m.get("reason", ""),
            }
            for m in mcp_meta
        ],
        "context_chars": len(block),
    }
    return block, metadata


def question_signal_score(question: dict, reweights: dict[str, dict]) -> float:
    qid = str(question.get("question_id") or "").strip()
    row = reweights.get(qid) or {}
    try:
        return float(row.get("signal_score") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def match_question_to_file(q: dict, file_path: Path) -> bool:
    fname = file_path.name
    fpath_str = str(file_path).lower()
    contract_patterns = q.get("target_contract_patterns", []) or []
    if contract_patterns:
        for pat in contract_patterns:
            try:
                if re.search(pat, fname, re.IGNORECASE) or re.search(pat, fpath_str, re.IGNORECASE):
                    return True
            except Exception:
                continue
        return False
    return True


def build_task(
    idx,
    workspace_name,
    workspace_path,
    file_path,
    file_contents,
    question,
    oos_phrases,
    is_uncovered,
    reweight_record=None,
    agi_context_block="",
    agi_context_metadata=None,
):
    rel_path = str(file_path).replace(str(workspace_path) + "/", "")
    q_text = question.get("question_text", "?")
    q_id = question.get("question_id", "?")
    attack_class = question.get("attack_class_anchor", "?")

    oos_block = ""
    if oos_phrases:
        oos_sample = "\n".join(f"- {p}" for p in oos_phrases[:15])
        oos_block = f"\n=== WORKSPACE OOS CATALOG (auto-fail if your candidate matches) ===\n{oos_sample}\n"

    coverage_note = ""
    if is_uncovered:
        coverage_note = "\n[NOTE: This file is in the UNCOVERED set - higher priority signal]\n"

    reweight_note = ""
    if reweight_record:
        reweight_note = (
            "\n=== HACKER-Q REWEIGHT LEDGER ===\n"
            f"- signal_score: {reweight_record.get('signal_score', 0)}\n"
            f"- signal_class: {reweight_record.get('signal_class', 'unknown')}\n"
            f"- yes/maybe/no: {reweight_record.get('yes_count', 0)}/"
            f"{reweight_record.get('maybe_count', 0)}/{reweight_record.get('no_count', 0)}\n"
        )

    prompt_parts = [
        f"You are a security auditor for {workspace_name} (per-file hunt v2).",
        f"TASK: Apply the hypothesis to the SPECIFIC FILE below.",
        f"Output STRICT JSON only - no prose around it.",
        f"\nREQUIRED JSON KEYS:",
        f"  applies_to_target: yes | no | maybe",
        f"  confidence: low | medium | high",
        f"  candidate_finding: string (one-sentence, anchored to specific function in file)",
        f"  file_line: 'path/to/file.sol:42' (line in the file BELOW)",
        f"  code_excerpt: string (1-3 lines verbatim from BELOW)",
        f"  severity_estimate: LOW | MEDIUM | HIGH | CRITICAL",
        f"  rubric_row_cited: string (verbatim impact wording from program rubric)",
        f"  dupe_check: scan known_dead_ends for overlap",
        f"  falsification_attempt: what to check to disprove",
        f"  novel_angle_score: 0-5",
        f"\n=== HYPOTHESIS (question_id={q_id}, attack_class={attack_class}) ===",
        f"{q_text}",
        f"\n=== AGI-GRADE CONTEXT FEED (bounded, soft-fail safe) ===",
        f"{agi_context_block}",
        f"{reweight_note}",
        f"{oos_block}",
        f"{coverage_note}",
        f"=== FILE: {rel_path} ===",
        f"```{file_path.suffix.lstrip('.')}",
        f"{file_contents}",
        f"```",
        f"\n=== STOP CONDITIONS ===",
        f"- If file is interface-only (no logic): applies=no, severity=NA",
        f"- If candidate matches OOS catalog: applies=no, dupe_check cites OOS row",
        f"- If candidate requires admin/governance privilege: applies=no (trusted-infra OOS R46)",
        f"- If file_line cannot be verified in the file BELOW: do not invent; applies=no",
    ]

    return {
        "task_id": f"perfile_mimo_{workspace_name}_{idx:05d}",
        "task_type": "per_file_workspace_hunt_v2",
        "workspace": workspace_name,
        "workspace_path": str(workspace_path),
        "source_question_id": q_id,
        "attack_class": attack_class,
        "hacker_q_reweight": reweight_record or {},
        "mimo_context_feed": agi_context_metadata or {},
        "file_anchor": {
            "file_path": rel_path,
            "abs_path": str(file_path),
            "is_uncovered": is_uncovered,
            "file_size_bytes": len(file_contents),
        },
        "prompt": "\n".join(prompt_parts),
        "max_tokens": 1500,
    }


def main(argv):
    p = argparse.ArgumentParser()
    p.add_argument("--workspace", required=True)
    p.add_argument("--workspace-path", required=True)
    p.add_argument(
        "--scan-root",
        default="",
        help="Optional file-walk root. Relative paths resolve under --workspace-path. "
        "If omitted, .auditooor/scan_root.txt is honored before falling back to workspace root.",
    )
    p.add_argument("--hacker-q-corpus", default="audit/corpus_tags/derived/hacker_questions_library.jsonl")
    p.add_argument("--dead-ends", default="reports/known_dead_ends.jsonl")
    p.add_argument("--coverage-heatmap", default="")
    p.add_argument("--output", required=True)
    p.add_argument("--max-tasks", type=int, default=5000)
    p.add_argument("--max-questions-per-file", type=int, default=10)
    p.add_argument("--prioritize-uncovered", action="store_true", default=True)
    p.add_argument("--reweight", action="store_true",
                   help="Load latest hacker_q_reweight_*.jsonl and rank questions by signal_score.")
    p.add_argument("--no-reweight", action="store_true",
                   help="Disable automatic hacker-q reweight loading.")
    p.add_argument("--reweight-path", default="",
                   help="Explicit hacker-q reweight JSONL path. Implies --reweight.")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    ws_path = Path(args.workspace_path).resolve()
    if not ws_path.exists():
        print(f"ERR: workspace path missing: {ws_path}", file=sys.stderr)
        return 2
    scan_root, scan_root_source = resolve_scan_root(ws_path, args.scan_root or None)
    if not scan_root.exists() or not scan_root.is_dir():
        print(f"ERR: scan root missing or not a directory: {scan_root}", file=sys.stderr)
        return 2

    hq_path = Path(args.hacker_q_corpus)
    if not hq_path.is_absolute():
        hq_path = Path(__file__).resolve().parent.parent / hq_path
    if not hq_path.exists():
        print(f"ERR: hacker-q corpus missing: {hq_path}", file=sys.stderr)
        return 2
    questions = []
    for ln in hq_path.read_text().splitlines():
        if not ln.strip():
            continue
        try:
            questions.append(json.loads(ln))
        except Exception:
            continue
    print(f"[per-file-batch] loaded {len(questions)} hacker questions", file=sys.stderr)

    reweights: dict[str, dict] = {}
    reweight_path: Path | None = None
    if not args.no_reweight:
        if args.reweight_path:
            reweight_path = Path(args.reweight_path)
            if not reweight_path.is_absolute():
                reweight_path = Path(__file__).resolve().parent.parent / reweight_path
        else:
            reweight_path = latest_reweight_path(Path(__file__).resolve().parent.parent / "audit/corpus_tags/derived")
        reweights = load_reweight_scores(reweight_path)
        print(
            f"[per-file-batch] loaded {len(reweights)} reweight rows"
            f"{' from ' + str(reweight_path) if reweight_path else ''}",
            file=sys.stderr,
        )

    de_path = Path(args.dead_ends)
    if not de_path.is_absolute():
        de_path = Path(__file__).resolve().parent.parent / de_path
    dead_ends = load_dead_ends(de_path, args.workspace)
    dead_end_rows = load_dead_end_records(de_path, args.workspace)
    print(f"[per-file-batch] loaded {len(dead_ends)} dead-ends for {args.workspace}", file=sys.stderr)

    oos_phrases = load_oos_catalog(ws_path)
    print(f"[per-file-batch] loaded {len(oos_phrases)} OOS phrases", file=sys.stderr)

    uncovered = set()
    if args.coverage_heatmap:
        uncovered = load_coverage_uncovered(Path(args.coverage_heatmap))
        print(f"[per-file-batch] {len(uncovered)} uncovered files (prioritized)", file=sys.stderr)

    files = enumerate_workspace_files(scan_root, ws_path)
    print(
        f"[per-file-batch] scan_root={scan_root} source={scan_root_source} "
        f"files={len(files)} in-scope files (post-exclusion)",
        file=sys.stderr,
    )

    if args.prioritize_uncovered and uncovered:
        files.sort(key=lambda p: (0 if p.name in uncovered else 1, str(p)))

    tasks = []
    idx = 0
    attack_context_cache: dict = {}
    for fp in files:
        try:
            contents = fp.read_text(errors="ignore")
        except Exception:
            continue
        if len(contents) > MAX_FILE_BYTES:
            contents = contents[:MAX_FILE_BYTES] + TRUNCATE_SUFFIX
        matched = [q for q in questions if match_question_to_file(q, fp)]
        fname_lower = fp.name.lower()
        rel_str = str(fp).replace(str(ws_path), "").lower()
        filtered = []
        for q in matched:
            ac = (q.get("attack_class_anchor") or "").lower()
            killed = False
            for (de_file, de_ac) in dead_ends:
                if de_ac == ac and (de_file in fname_lower or de_file in rel_str):
                    killed = True
                    break
            if not killed:
                filtered.append(q)
        if reweights:
            filtered.sort(
                key=lambda q: (
                    -question_signal_score(q, reweights),
                    str(q.get("question_id") or ""),
                )
            )
        for q in filtered[: args.max_questions_per_file]:
            qid = str(q.get("question_id") or "").strip()
            rel_path = str(fp).replace(str(ws_path) + "/", "")
            agi_block, agi_meta = build_agi_context_block(
                ws_path,
                rel_path,
                fp,
                contents,
                q,
                dead_end_rows,
                reweights.get(qid),
                attack_context_cache,
            )
            tasks.append(
                build_task(
                    idx,
                    args.workspace,
                    ws_path,
                    fp,
                    contents,
                    q,
                    oos_phrases,
                    fp.name in uncovered,
                    reweights.get(qid),
                    agi_block,
                    agi_meta,
                )
            )
            idx += 1
            if idx >= args.max_tasks:
                break
        if idx >= args.max_tasks:
            break

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as fh:
        for t in tasks:
            fh.write(json.dumps(t) + "\n")

    summary = {
        "schema": SCHEMA,
        "tasks_built": len(tasks),
        "files_scanned": len(files),
        "files_uncovered_prioritized": len(uncovered),
        "dead_ends_loaded": len(dead_ends),
        "dead_end_records_loaded": len(dead_end_rows),
        "workspace_path": str(ws_path),
        "scan_root": str(scan_root),
        "scan_root_source": scan_root_source,
        "oos_phrases_loaded": len(oos_phrases),
        "reweight_rows_loaded": len(reweights),
        "reweight_path": str(reweight_path) if reweight_path else "",
        "attack_context_cache_entries": len(attack_context_cache),
        "output": str(out_path),
    }
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        for k, v in summary.items():
            print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
