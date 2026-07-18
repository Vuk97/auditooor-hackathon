#!/usr/bin/env bash
# graph-query.sh — query the cross-audit citation graph (R43 U6).
#
# The graph is built by tools/build-citation-graph.py and lives at
# reference/citation_graph.yaml. Every node represents one prior-audit finding.
#
# Usage:
#   ./tools/graph-query.sh --contract CTFExchange
#   ./tools/graph-query.sh --contract CTFExchange --function validateOrder
#   ./tools/graph-query.sh --mechanism "timestamp never validated"
#   ./tools/graph-query.sh --severity High --workspace morpho
#   ./tools/graph-query.sh --similar-to path/to/draft.md
#   ./tools/graph-query.sh --similar-to draft.md --json     # machine-readable
#
# Exit codes:
#   0  — query succeeded (may return zero matches)
#   2  — bad usage / missing graph
#
# Depends on: python3 + PyYAML + reference/citation_graph.yaml.

set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GRAPH="$HERE/reference/citation_graph.yaml"

if [ ! -f "$GRAPH" ]; then
  echo "[graph-query] graph not found: $GRAPH" >&2
  echo "[graph-query] run: ./tools/build-citation-graph.py" >&2
  exit 2
fi

CONTRACT=""
FUNCTION=""
MECHANISM=""
SEVERITY=""
WORKSPACE=""
PROTOCOL=""
SIMILAR_TO=""
LIMIT="10"
OUTPUT_JSON="0"

while [ $# -gt 0 ]; do
  case "$1" in
    --contract) CONTRACT="$2"; shift 2 ;;
    --function) FUNCTION="$2"; shift 2 ;;
    --mechanism) MECHANISM="$2"; shift 2 ;;
    --severity) SEVERITY="$2"; shift 2 ;;
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --protocol) PROTOCOL="$2"; shift 2 ;;
    --similar-to) SIMILAR_TO="$2"; shift 2 ;;
    --limit) LIMIT="$2"; shift 2 ;;
    --json) OUTPUT_JSON="1"; shift ;;
    -h|--help)
      sed -n '2,18p' "$0"
      exit 0 ;;
    *)
      echo "[graph-query] unknown arg: $1" >&2
      exit 2 ;;
  esac
done

export GRAPH CONTRACT FUNCTION MECHANISM SEVERITY WORKSPACE PROTOCOL SIMILAR_TO LIMIT OUTPUT_JSON

python3 - <<'PY'
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("[graph-query] PyYAML not installed")

graph_path = os.environ["GRAPH"]
contract_q = os.environ["CONTRACT"].lower()
function_q = os.environ["FUNCTION"].lower()
mechanism_q = os.environ["MECHANISM"].lower()
severity_q = os.environ["SEVERITY"].lower()
workspace_q = os.environ["WORKSPACE"].lower()
protocol_q = os.environ["PROTOCOL"].lower()
similar_to = os.environ["SIMILAR_TO"]
limit = int(os.environ["LIMIT"] or 10)
output_json = os.environ["OUTPUT_JSON"] == "1"

doc = yaml.safe_load(Path(graph_path).read_text())
nodes = doc["nodes"]

STOPWORDS = {
    "the","and","this","that","with","from","into","have","been","will",
    "they","when","then","each","your","most","more","only","such","some",
    "also","very","must","many","both","what","than","these","other","which",
    "make","like","time","even","still","same","just","over","here","kind",
    "being","above","below","after","before","where","about","under","while",
    "their","would","should","could","first","second","third","there","every",
    "order","event","state","value","check","order.","order`","order,","fixed",
    "severity","medium","high","critical","info","none","null","true","false",
    "function","contract","file","line","generated","source","see","code",
    "mechanism","target","recommendation","impact","vulnerable","vector",
    "trigger","path","severity:","target:","contract:","function:","file:line:",
}

def tokenize(s):
    toks = re.findall(r"[A-Za-z_][A-Za-z0-9_\.]{3,}", s.lower())
    return [t for t in toks if t not in STOPWORDS]


def fingerprint(text, cap=60):
    toks = tokenize(text)
    # unique, capped
    seen = []
    for t in toks:
        if t not in seen:
            seen.append(t)
        if len(seen) >= cap:
            break
    return seen


def score_similarity(draft_fp, node):
    """Weighted score:
       +3 per matching contract name token
       +2 per matching function token
       +1 per matching non-stopword fingerprint token
       +2 bonus if severity matches (when draft hints one)
    """
    node_text = " ".join([
        node.get("contract",""),
        node.get("function",""),
        node.get("mechanism",""),
        node.get("title",""),
        node.get("text_blob",""),
    ]).lower()
    node_tokens = set(tokenize(node_text))

    hits = 0
    for tok in draft_fp:
        if tok in node_tokens:
            hits += 1
    # Boost for contract match
    contract_boost = 0
    for tok in draft_fp:
        c = node.get("contract","").lower()
        if c and c in tok:
            contract_boost += 3
            break
    function_boost = 0
    f = node.get("function","").lower()
    if f and len(f) > 3 and any(f in tok or tok in f for tok in draft_fp):
        function_boost += 2

    return hits + contract_boost + function_boost


def match_filter(node):
    if contract_q and contract_q not in node.get("contract","").lower() \
            and contract_q not in node.get("text_blob","").lower():
        return False
    if function_q and function_q not in node.get("function","").lower() \
            and function_q not in node.get("text_blob","").lower():
        return False
    if mechanism_q:
        hay = (node.get("mechanism","") + " " + node.get("title","") + " " + node.get("text_blob","")).lower()
        if mechanism_q not in hay:
            # Fuzzy: all words of mechanism_q must appear
            words = [w for w in mechanism_q.split() if len(w) > 3]
            if not all(w in hay for w in words):
                return False
    if severity_q and severity_q != node.get("severity","").lower():
        return False
    if workspace_q and workspace_q != node.get("workspace","").lower():
        return False
    if protocol_q and protocol_q != node.get("protocol_type","").lower():
        return False
    return True


# ---------------- Similarity mode ----------------
results = []
mode = "filter"

if similar_to:
    mode = "similar"
    if not os.path.isfile(similar_to):
        sys.exit(f"[graph-query] draft not found: {similar_to}")
    draft = Path(similar_to).read_text()
    fp = fingerprint(draft)
    scored = []
    for n in nodes:
        s = score_similarity(fp, n)
        if s > 0:
            scored.append((s, n))
    scored.sort(key=lambda x: -x[0])
    results = [(s, n) for s, n in scored[:limit]]
else:
    for n in nodes:
        if match_filter(n):
            results.append((None, n))
            if len(results) >= limit:
                break


# ---------------- Output ----------------
if output_json:
    out = {
        "mode": mode,
        "query": {
            "contract": contract_q, "function": function_q, "mechanism": mechanism_q,
            "severity": severity_q, "workspace": workspace_q, "protocol": protocol_q,
            "similar_to": similar_to,
        },
        "count": len(results),
        "nodes": [
            {**n, "similarity_score": s} if s is not None else n
            for s, n in results
        ],
    }
    print(json.dumps(out, indent=2))
else:
    if mode == "similar":
        print(f"# citation_graph similarity query")
        print(f"# draft: {similar_to}")
        print(f"# top {len(results)} matches\n")
        for s, n in results:
            print(f"[score={s:>3}] {n['workspace']}/{n['source_audit']} {n['finding_id']} ({n['severity']})")
            print(f"           {n['title'][:100]}")
            if n.get("contract") or n.get("function"):
                print(f"           target: {n.get('contract','?')}::{n.get('function','?')}")
            print(f"           file: {n['source_path']}")
            print()
    else:
        print(f"# citation_graph filter query: contract={contract_q} function={function_q} mechanism='{mechanism_q}' severity={severity_q} workspace={workspace_q} protocol={protocol_q}")
        print(f"# {len(results)} matches\n")
        for _, n in results:
            print(f"- [{n['severity']}] {n['workspace']}/{n['source_audit']} {n['finding_id']} — {n['title'][:100]}")
            print(f"    {n.get('contract','?')}::{n.get('function','?')} (protocol={n.get('protocol_type','?')}, status={n.get('status','?')})")
PY

RC=$?
exit $RC
