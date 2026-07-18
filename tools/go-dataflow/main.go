// go-dataflow: native offline inter-procedural data-flow backend for Go.
//
// Pipeline:
//   go/packages.LoadAllSyntax (full type info + syntax)  ->
//   go/ssa (BuilderMode incl. InstantiateGenerics)        ->
//   callgraph/cha  (+ VTA refinement when feasible)       ->
//   backward + forward def-use slices across packages.
//
// It emits one JSON object per DefUsePath on stdout (a JSON array), matching the
// SHARED tools/dataflow_schema.py DefUsePath v1 record. The Python wrapper
// (tools/go-dataflow.py) converts/validates/merges these into
// <ws>/.auditooor/dataflow_paths.jsonl.
//
// SOURCES  = function parameters (tainted external input).
// SINKS    = value movers / state writes / authority:
//            bank.Send*/Transfer*/Mint*/Burn*, store.Set/Delete, KVStore.Set/Delete,
//            keeper Set*/Send*/Mint*/Burn*/Delegate*/Undelegate* mutations.
// GUARD    = an if-cond (or panic/require-like branch) that reads a value derived
//            from the sliced SSA value and dominates the sink's basic block.
//
// R80 honesty contract: confidence="semantic-ssa" for IR-backed paths. On any
// load/compile failure the program prints a single degrade record (degraded=true,
// engine="unsupported-or-compile-fail-degrade") and exits 0 (advisory, never silent).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/token"
	"go/types"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"golang.org/x/tools/go/types/typeutil"
)

const schemaVersion = "dataflow_path.v1"

// B-hops: depth is UNBOUNDED by design. The REAL terminator is the visited-SSA-value
// set in sliceArg (every value walked at most once - a structural cycle guard that
// mirrors slither_predicates.callee_closure's `seen`). The constants below are only
// HIGH runaway-safety ceilings (cosmos-sdk codec/context graphs can fan out into
// hundreds of thousands of SSA values). When a ceiling actually trips, the emitted
// record carries dataflow_truncated=true (honesty). All three are overridable via env:
//
//	AUDITOOOR_DATAFLOW_MAX_HOPS    - max recorded hops per slice  (default 256)
//	AUDITOOOR_DATAFLOW_MAX_WORK    - max SSA values popped/slice   (default 2000000)
//	AUDITOOOR_DATAFLOW_MAX_DEPTH   - max inter-proc boundary depth (default 24; the
//	                                 -max-depth flag still overrides when passed > 0)
//	AUDITOOOR_DATAFLOW_EMIT_HOPS   - max SERIALIZED hops/record    (default 96)
//	AUDITOOOR_DATAFLOW_EMIT_GUARDS - max SERIALIZED guards/record  (default 96)
//
// The MAX_* ceilings bound the TRAVERSAL; the EMIT_* caps bound what is WRITTEN so a
// single pathological slice cannot balloon one record to tens of MB (NUVA 2026-07-06:
// guard_nodes=163722 = 23.5MB/record, whole slice = 543MB, python json.loads OOM-hung
// -> step-1c produced ZERO records on cosmos-scale Go workspaces). Defaults were 4096;
// that runaway is the bug this fixes.
func envInt(name string, def int) int {
	if raw := os.Getenv(name); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			return v
		}
	}
	return def
}

// -------- output records (mirror dataflow_schema.py v1) --------

type srcRec struct {
	Kind string  `json:"kind"`
	Fn   *string `json:"fn"`
	Var  *string `json:"var"`
	File *string `json:"file"`
	Line *int    `json:"line"`
}

type sinkRec struct {
	Kind   string  `json:"kind"`
	Callee *string `json:"callee"`
	ArgPos *int    `json:"arg_pos"`
	Fn     *string `json:"fn"`
	File   *string `json:"file"`
	Line   *int    `json:"line"`
	// Cell is the PERSISTENT storage cell a state-write targets: the receiver FIELD
	// name of a `k.VaultAccounts.Set(...)` / collections write (`VaultAccounts`). The
	// `callee` for a cosmos-sdk collections write is the noisy generic TYPE signature
	// (`collections.Map[Triple[...], PendingSwapOut]`), which carries no clean cell
	// identity; Cell recovers the field name so the state-coupling resolver can map a
	// value-mover to the persistent cell it writes (the Aptos coupled-state join key).
	// Empty when the receiver is not a struct-field access.
	Cell *string `json:"cell,omitempty"`
	// PanicOp names the panic-CAPABLE SSA operation this sink is (set only for
	// kind=="panic" records emitted under -panic-sinks): "type-assert" (a
	// *ssa.TypeAssert with CommaOk==false), "index" (a *ssa.Index / *ssa.IndexAddr
	// out-of-range), or "nil-deref" (a pointer load *ssa.UnOp Op==MUL). The tainted
	// OPERAND that triggers the panic (the assertion subject / the index expression /
	// the dereferenced pointer) is the value the backward slicer traced to a param
	// source, so a kind=="panic" record with source.kind=="param" is an
	// attacker-reaches-panic-capable-node dataflow fact, not a text match.
	PanicOp *string `json:"panic_op,omitempty"`
}

type hopRec struct {
	FromVar *string `json:"from_var"`
	ToVar   *string `json:"to_var"`
	Fn      *string `json:"fn"`
	Via     string  `json:"via"`
	File    *string `json:"file"`
	Line    *int    `json:"line"`
	IR      *string `json:"ir"`
	Guarded bool    `json:"guarded"`
}

type guardRec struct {
	File *string `json:"file"`
	Line *int    `json:"line"`
	Expr string  `json:"expr"`
}

type pathRec struct {
	Schema        string     `json:"schema"`
	PathID        string     `json:"path_id"`
	Language      string     `json:"language"`
	Direction     string     `json:"direction"`
	Engine        string     `json:"engine"`
	Source        srcRec     `json:"source"`
	Sink          sinkRec    `json:"sink"`
	Hops          []hopRec   `json:"hops"`
	CallDepth     int        `json:"call_depth"`
	Unguarded     bool       `json:"unguarded"`
	GuardNodes    []guardRec `json:"guard_nodes"`
	SourceUnitIDs []string   `json:"source_unit_ids"`
	SinkUnitIDs   []string   `json:"sink_unit_ids"`
	Confidence    string     `json:"confidence"`
	Degraded      bool       `json:"degraded"`
	DegradeReason string     `json:"degrade_reason,omitempty"`
	// B-hops honesty: set when the backward slice was cut short by the HIGH safety
	// ceiling (depth / work / hop runaway guard) rather than reaching a real source.
	// A truncated chain must not be treated as a complete source->sink proof.
	DataflowTruncated bool `json:"dataflow_truncated,omitempty"`
}

func sp(s string) *string { return &s }
func ip(i int) *int       { return &i }

func emitDegrade(reason string) {
	rec := pathRec{
		Schema:        schemaVersion,
		PathID:        "degrade-0",
		Language:      "go",
		Direction:     "backward",
		Engine:        "unsupported-or-compile-fail-degrade",
		Source:        srcRec{Kind: "none"},
		Sink:          sinkRec{Kind: "none"},
		Hops:          []hopRec{},
		CallDepth:     0,
		Unguarded:     false,
		GuardNodes:    []guardRec{},
		SourceUnitIDs: []string{},
		SinkUnitIDs:   []string{},
		Confidence:    "heuristic",
		Degraded:      true,
		DegradeReason: reason,
	}
	out, _ := json.Marshal([]pathRec{rec})
	fmt.Println(string(out))
}

// -------- sink classification --------
//
// We classify a CallCommon as a sink by the callee's name. We keep this
// name-based at the *IR* level (it inspects the resolved SSA callee, not a
// text grep), so it is still semantic-ssa confidence.

var sinkPrefixes = []struct {
	sub  string
	kind string
}{
	{"SendCoins", "value-move"},
	{"SendCoinsFromModuleToAccount", "value-move"},
	{"SendCoinsFromAccountToModule", "value-move"},
	{"SendCoinsFromModuleToModule", "value-move"},
	{"Transfer", "value-move"},
	{"MintCoins", "mint"},
	{"BurnCoins", "burn"},
	{"Mint", "mint"},
	{"Burn", "burn"},
	{"Delegate", "authority"},
	{"Undelegate", "authority"},
	{"DelegateCoins", "value-move"},
	{"UndelegateCoins", "value-move"},
}

// store writes: receiver method .Set / .Delete on a KVStore-like, or keeper Set*.
var storeWriteMethods = []string{"Set", "Delete"}

// stdlibSink reports whether the callee is a Go stdlib symbol; stdlib symbols
// (net/http.readTransfer, bytes.Buffer, etc.) are never in-scope value-movers and
// would otherwise produce substring false-positives like "*Transfer*".
func stdlibSink(name string) bool {
	for _, p := range []string{"net/http.", "net/", "bytes.", "io.", "fmt.",
		"strings.", "runtime.", "reflect.", "encoding/", "crypto/", "sync.",
		"os.", "bufio.", "sort.", "time.", "context."} {
		if strings.HasPrefix(name, "(") {
			// receiver method form: "(*net/http.Transport).RoundTrip"
			if strings.Contains(name, p) {
				return true
			}
		} else if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// classifySink returns (kind, calleeName, true) if the call is a value-moving /
// state-write / authority sink. Matching is on the SSA-resolved callee SHORT name
// (word-boundary: the method name equals or starts with the verb), not an
// arbitrary substring, to avoid stdlib false-positives (readTransfer, etc.).
func classifySink(cc *ssa.CallCommon) (string, string, bool) {
	name := calleeName(cc)
	if name == "" || stdlibSink(name) {
		return "", "", false
	}
	short := name
	if i := strings.LastIndex(short, "."); i >= 0 {
		short = short[i+1:]
	}
	for _, sp := range sinkPrefixes {
		// the method's short name must EQUAL the verb or START with it
		// (SendCoins, MintCoins, Transfer, Mint, Burn, Delegate...). This is a
		// word-boundary match, not a `strings.Contains` over the full path, so
		// `readTransfer` / `noBurn` do not match.
		if short == sp.sub || strings.HasPrefix(short, sp.sub) {
			return sp.kind, name, true
		}
	}
	// store.Set / store.Delete (method on a *KVStore / CommitKVStore receiver) OR the
	// cosmos-sdk collections API (.Set on a collections.Map/Item/IndexedMap/KeySet/...).
	for _, m := range storeWriteMethods {
		if short == m && (looksLikeStore(cc) || looksLikeCollections(cc)) {
			return "state-write", name, true
		}
	}
	// cosmos-sdk collections use .Remove (not .Delete) to erase a key - a state write.
	// Gated on a collections receiver so a generic slice/set .Remove never false-hits.
	if short == "Remove" && looksLikeCollections(cc) {
		return "state-write", name, true
	}
	// keeper Set<X> mutations (Set followed by an exported word)
	if strings.HasPrefix(short, "Set") && len(short) > 3 && isUpper(short[3]) && isKeeperRecv(cc) {
		return "state-write", name, true
	}
	return "", "", false
}

func isUpper(b byte) bool { return b >= 'A' && b <= 'Z' }

// panicOperand classifies an SSA instruction as a PANIC-CAPABLE node and returns
// the operand whose value/type triggers the panic (the value to slice backward for
// param-taint), the op label, and true. This is an IR-level structural fact over the
// SSA (a *ssa.TypeAssert with CommaOk==false ALWAYS panics on a type mismatch; a
// *ssa.Index / *ssa.IndexAddr panics on an out-of-range index; a *ssa.UnOp with
// Op==MUL is a pointer load that panics on a nil pointer) - it is NOT a text match on
// "x.(T)". A comma-ok assert (`v, ok := x.(T)`) and a comma-ok map lookup do NOT panic
// and are excluded.
func panicOperand(instr ssa.Instruction) (ssa.Value, string, bool) {
	switch v := instr.(type) {
	case *ssa.TypeAssert:
		// single-result assert `x.(T)` panics on mismatch; `x, ok := x.(T)` does not.
		if !v.CommaOk {
			return v.X, "type-assert", true
		}
	case *ssa.IndexAddr:
		// &a[i] on a slice / *array: panics when i is out of range. The index is the
		// attacker-influenced trigger.
		return v.Index, "index", true
	case *ssa.Index:
		// a[i] on an array VALUE / string: out-of-range panic on the index.
		return v.Index, "index", true
	case *ssa.Slice:
		// a[lo:hi]: slice bounds out of range panic; the high bound is the usual
		// attacker trigger (fall back to the low bound when high is implicit).
		if v.High != nil {
			return v.High, "slice-bounds", true
		}
		if v.Low != nil {
			return v.Low, "slice-bounds", true
		}
	case *ssa.UnOp:
		// *p pointer load: nil-pointer dereference panic. Op MUL == the deref.
		if v.Op == token.MUL {
			return v.X, "nil-deref", true
		}
	}
	return nil, "", false
}

// collectionCellName recovers the PERSISTENT storage cell a state-write targets: the
// receiver FIELD name of `k.VaultAccounts.Set(...)` / `k.PausedBalance.Set(...)` etc.
// The method receiver (cc.Args[0] for a bound method call) is an SSA value produced by a
// field access on the keeper struct; unwrap loads/field-addresses to the *ssa.FieldAddr /
// *ssa.Field and return the struct field name. Empty when the receiver is not a plain
// struct-field access (a local collections value, a map literal, etc.) - never guess.
func collectionCellName(cc *ssa.CallCommon) string {
	// Only a genuine cosmos-sdk collections write (`k.Vaults.Set`) has a clean persistent
	// FIELD cell. The keeper-method Set<X> branch / store writes have a keeper/store
	// RECEIVER, whose field walk yields noise (`Keeper`, `Store`, `IndexedMap`) - gating on
	// looksLikeCollections drops that (NUVA: 287 spurious `Keeper` cells) so the resolver
	// never manufactures a coupling from a non-cell receiver name.
	if !looksLikeCollections(cc) {
		return ""
	}
	if len(cc.Args) == 0 {
		return ""
	}
	v := cc.Args[0]
	for i := 0; i < 8 && v != nil; i++ { // bounded unwrap; SSA def chains are short
		switch t := v.(type) {
		case *ssa.UnOp: // load: *p
			v = t.X
		case *ssa.MakeInterface:
			v = t.X
		case *ssa.ChangeType:
			v = t.X
		case *ssa.FieldAddr:
			return structFieldName(t.X.Type(), t.Field)
		case *ssa.Field:
			return structFieldName(t.X.Type(), t.Field)
		default:
			return ""
		}
	}
	return ""
}

// structFieldName returns the name of field #idx of a (possibly pointer-to) struct type.
func structFieldName(t types.Type, idx int) string {
	if p, ok := t.Underlying().(*types.Pointer); ok {
		t = p.Elem()
	}
	if st, ok := t.Underlying().(*types.Struct); ok && idx >= 0 && idx < st.NumFields() {
		return st.Field(idx).Name()
	}
	return ""
}

func calleeName(cc *ssa.CallCommon) string {
	if cc.IsInvoke() {
		// interface method call
		return cc.Method.FullName()
	}
	if cc.StaticCallee() != nil {
		return cc.StaticCallee().String()
	}
	// dynamic call through a value: try the signature's receiver/name via Value
	if cc.Value != nil {
		return cc.Value.Name()
	}
	return ""
}

func recvTypeString(cc *ssa.CallCommon) string {
	if cc.IsInvoke() && cc.Method != nil {
		if r := cc.Method.Type().(*types.Signature).Recv(); r != nil {
			return r.Type().String()
		}
		return cc.Method.Name()
	}
	callee := cc.StaticCallee()
	if callee == nil || callee.Signature == nil {
		return ""
	}
	if r := callee.Signature.Recv(); r != nil {
		return r.Type().String()
	}
	return ""
}

func looksLikeStore(cc *ssa.CallCommon) bool {
	rt := strings.ToLower(recvTypeString(cc))
	return strings.Contains(rt, "kvstore") || strings.Contains(rt, "store") || strings.Contains(rt, "prefix")
}

// looksLikeCollections reports whether the call receiver is a cosmos-sdk `collections`
// type (Map / Item / IndexedMap / KeySet / Sequence / Pair...). The Provenance vault (and
// most modern cosmos-sdk modules) persist coupled state via `k.Field.Set(ctx, key, val)`
// on a collections.Map, whose receiver type string is `cosmossdk.io/collections.Map[...]`.
// Without this, the vault's PRIMARY state-write mechanism is invisible to the slice, so
// the state-coupling conserved-with lane can never ground its cells (measured on NUVA:
// the src/vault module produced ~0 state-write hops, 0 touching VaultAccount).
func looksLikeCollections(cc *ssa.CallCommon) bool {
	rt := strings.ToLower(recvTypeString(cc))
	return strings.Contains(rt, "collections.")
}

func isKeeperRecv(cc *ssa.CallCommon) bool {
	rt := strings.ToLower(recvTypeString(cc))
	return strings.Contains(rt, "keeper")
}

// -------- position helpers --------

func pos(prog *ssa.Program, p token.Pos) (string, int) {
	if !p.IsValid() {
		return "", 0
	}
	pp := prog.Fset.Position(p)
	return pp.Filename, pp.Line
}

func fnName(f *ssa.Function) string {
	if f == nil {
		return ""
	}
	return f.String()
}

// -------- backward def-use slice --------
//
// Given a sink CallCommon argument SSA value, walk backward over the SSA
// def-chain. When we cross a function boundary (the value is a *ssa.Parameter or
// flows from a call's return), we record a hop and continue in the caller (using
// the callgraph to find callers). We collect dominating guards along the way.

type slicer struct {
	prog     *ssa.Program
	cg       *callgraph.Graph
	maxDepth int
	engine   string
}

// guardsDominating returns if-condition guards whose block dominates `target`'s
// block within fn, and whose condition transitively reads `v` (best-effort:
// any guard in a dominating block that references a value in the slice set).
func (s *slicer) guardsDominating(fn *ssa.Function, target ssa.Instruction, sliceSet map[ssa.Value]bool) []guardRec {
	var out []guardRec
	if fn == nil || fn.Blocks == nil {
		return out
	}
	var targetBlock *ssa.BasicBlock
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			if instr == target {
				targetBlock = b
			}
		}
	}
	if targetBlock == nil {
		return out
	}
	seen := map[*ssa.BasicBlock]bool{}
	for _, b := range fn.Blocks {
		if !blockDominates(b, targetBlock) || seen[b] {
			continue
		}
		seen[b] = true
		if len(b.Instrs) == 0 {
			continue
		}
		last := b.Instrs[len(b.Instrs)-1]
		ifi, ok := last.(*ssa.If)
		if !ok {
			continue
		}
		// the If condition; check it references a sliced value (or a derived bool)
		if condTouchesSlice(ifi.Cond, sliceSet, map[ssa.Value]bool{}) {
			file, line := pos(s.prog, ifi.Cond.Pos())
			out = append(out, guardRec{
				File: nilIfEmpty(file),
				Line: nilIfZero(line),
				Expr: condExpr(ifi.Cond),
			})
		}
	}
	return out
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
func nilIfZero(i int) *int {
	if i == 0 {
		return nil
	}
	return &i
}

func condExpr(v ssa.Value) string {
	switch t := v.(type) {
	case *ssa.BinOp:
		return fmt.Sprintf("%s %s %s", valDesc(t.X), t.Op, valDesc(t.Y))
	case *ssa.UnOp:
		return fmt.Sprintf("%s%s", t.Op, valDesc(t.X))
	case *ssa.Call:
		return "call(" + valDesc(t) + ")"
	default:
		return valDesc(v)
	}
}

func valDesc(v ssa.Value) string {
	if v == nil {
		return "<nil>"
	}
	if n := v.Name(); n != "" {
		return n
	}
	return v.String()
}

// condTouchesSlice: does the if-condition transitively read any value in sliceSet?
func condTouchesSlice(v ssa.Value, sliceSet map[ssa.Value]bool, visited map[ssa.Value]bool) bool {
	if v == nil || visited[v] {
		return false
	}
	visited[v] = true
	if sliceSet[v] {
		return true
	}
	if rv, ok := v.(interface{ Operands([]*ssa.Value) []*ssa.Value }); ok {
		for _, op := range rv.Operands(nil) {
			if op != nil && condTouchesSlice(*op, sliceSet, visited) {
				return true
			}
		}
	}
	return false
}

// blockDominates: does a dominate b? Uses SSA's dominator tree.
func blockDominates(a, b *ssa.BasicBlock) bool {
	for x := b; x != nil; x = x.Idom() {
		if x == a {
			return true
		}
	}
	return false
}

// backwardOperands returns the SSA values that define `v` (one step back).
func backwardOperands(v ssa.Value) []ssa.Value {
	var out []ssa.Value
	if instr, ok := v.(ssa.Instruction); ok {
		var ops []*ssa.Value
		ops = instr.Operands(ops)
		for _, op := range ops {
			if op != nil && *op != nil {
				out = append(out, *op)
			}
		}
	}
	return out
}

// sliceArg walks backward from a sink arg value, building hops + a slice set,
// crossing function boundaries via parameters and the callgraph. Returns the
// origin source (a Parameter if reached), the hops, the dominating guards, a
// truncation flag, and structuredInput (see below).
//
// structuredInput: true when the backward slice touched a STRUCTURED-INPUT node -
// a struct field read (*ssa.FieldAddr/*ssa.Field), a map read (*ssa.Lookup), or
// the return of an EXTERNAL/opaque call (a *ssa.Call whose static callee has no
// body, or an interface/dynamic dispatch). This is the cosmos decode substrate:
// state and message data are populated through codec Unmarshal (a pointer-OUTPUT
// argument) and read back via keeper getters / iterators / Any.GetCachedValue,
// so a value derived from decoded state has NO SSA def-use edge back to a
// *ssa.Parameter - it dead-ends at a local *ssa.Alloc. The plain `originParam !=
// nil` gate therefore drops 100% of cosmos panic-capable asserts (which operate
// on exactly such decoded values). structuredInput lets the panic arm accept
// "value provably came from structured state/message input" as a taint origin
// for EXPORTED entrypoints, WITHOUT degrading to a text match: a pure-constant /
// pure-local assert never sets it.
func (s *slicer) sliceArg(start ssa.Value, sinkFn *ssa.Function, sinkInstr ssa.Instruction) (*ssa.Parameter, *ssa.Function, []hopRec, []guardRec, bool, bool) {
	sliceSet := map[ssa.Value]bool{}
	visited := map[ssa.Value]bool{}
	var hops []hopRec
	var guards []guardRec
	structuredInput := false

	type frame struct {
		v     ssa.Value
		fn    *ssa.Function
		depth int // inter-procedural boundary-crossing depth so far
	}
	stack := []frame{{start, sinkFn, 0}}
	var originParam *ssa.Parameter
	var originFn *ssa.Function
	maxObservedDepth := 0

	// B-hops: depth is UNBOUNDED; the visited[] set below is the real terminator.
	// maxHops/maxWork are HIGH runaway-safety ceilings (env-overridable) for the
	// pathological transitive closures cosmos-sdk codec/context graphs produce - NOT
	// small semantic caps. truncated records when a ceiling actually trips (honesty).
	maxHops := envInt("AUDITOOOR_DATAFLOW_MAX_HOPS", 256)
	maxWork := envInt("AUDITOOOR_DATAFLOW_MAX_WORK", 2000000)
	work := 0
	hopSeen := map[string]bool{}
	truncated := false

	addHop := func(h hopRec) {
		if len(hops) >= maxHops {
			truncated = true
			return
		}
		k := fmt.Sprintf("%s|%v|%v|%v|%v", h.Via, h.FromVar, h.ToVar, h.Fn, h.Line)
		if hopSeen[k] {
			return
		}
		hopSeen[k] = true
		hops = append(hops, h)
	}

	// collect guards in the sink's own function first
	guards = append(guards, s.guardsDominating(sinkFn, sinkInstr, sliceSet)...)

	for len(stack) > 0 {
		work++
		if work > maxWork {
			truncated = true
			break
		}
		fr := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if fr.depth > s.maxDepth {
			truncated = true
			continue
		}
		if fr.v == nil || visited[fr.v] {
			continue
		}
		visited[fr.v] = true
		sliceSet[fr.v] = true
		if fr.depth > maxObservedDepth {
			maxObservedDepth = fr.depth
		}

		// STRUCTURED-INPUT witness: the value derives from a struct field, a map
		// entry, or an opaque/external call return (codec decode / store read /
		// iterator value). Marks that the sliced value is NOT a pure local/const,
		// even when the def-use chain never lands on a *ssa.Parameter.
		switch iv := fr.v.(type) {
		case *ssa.FieldAddr, *ssa.Field, *ssa.Lookup:
			structuredInput = true
		case *ssa.UnOp:
			// *p load of a field/global (nil-deref-capable) is a structured read;
			// a load of a plain local Alloc is not.
			if iv.Op == token.MUL {
				switch iv.X.(type) {
				case *ssa.FieldAddr, *ssa.Global, *ssa.Lookup:
					structuredInput = true
				}
			}
		case *ssa.Call:
			// external/opaque callee (no body) or dynamic dispatch => the returned
			// value is decoded state/message data the slicer cannot see through.
			callee := iv.Call.StaticCallee()
			if callee == nil || callee.Blocks == nil {
				structuredInput = true
			}
		}

		switch def := fr.v.(type) {
		case *ssa.Parameter:
			// boundary: this value is a parameter of fr.fn -> walk into callers
			if originParam == nil { // keep the FIRST (closest-to-sink) source as canonical origin
				originParam = def
				originFn = fr.fn
			}
			idx := paramIndex(fr.fn, def)
			callers := s.callersOf(fr.fn)
			for _, cs := range callers {
				cc := cs.common()
				if cc == nil || idx < 0 || idx >= len(cc.Args) {
					continue
				}
				argV := cc.Args[idx]
				file, line := pos(s.prog, cs.Pos())
				addHop(hopRec{
					FromVar: sp(valDesc(argV)),
					ToVar:   sp(def.Name()),
					Fn:      sp(fnName(cs.callerFn())),
					Via:     "internal_call",
					File:    nilIfEmpty(file),
					Line:    nilIfZero(line),
					IR:      sp(trim(cs.String())),
					Guarded: false,
				})
				// guards in the caller dominating the call site. Seed the slice
				// set with the caller's argument value FIRST so a guard whose
				// condition reads that arg (e.g. `if amount <= 0`) is recognized.
				if cf := cs.callerFn(); cf != nil {
					if ci := cs.instr(); ci != nil {
						sliceSet[argV] = true
						guards = append(guards, s.guardsDominating(cf, ci, sliceSet)...)
					}
				}
				stack = append(stack, frame{argV, cs.callerFn(), fr.depth + 1})
			}
		case *ssa.Call:
			// value flows from a call's return -> dive into callee return operands
			callee := def.Call.StaticCallee()
			if callee != nil && callee.Blocks != nil {
				rets := returnValues(callee)
				file, line := pos(s.prog, def.Pos())
				for _, rv := range rets {
					addHop(hopRec{
						FromVar: sp(valDesc(rv)),
						ToVar:   sp(def.Name()),
						Fn:      sp(fnName(callee)),
						Via:     "return",
						File:    nilIfEmpty(file),
						Line:    nilIfZero(line),
						IR:      sp(trim(def.String())),
						Guarded: false,
					})
					stack = append(stack, frame{rv, callee, fr.depth + 1})
				}
			}
			// also walk the call's arguments (data passed in may define the result)
			for _, op := range backwardOperands(def) {
				stack = append(stack, frame{op, fr.fn, fr.depth})
			}
		default:
			for _, op := range backwardOperands(fr.v) {
				stack = append(stack, frame{op, fr.fn, fr.depth})
			}
		}
	}
	// dedup guards
	guards = dedupGuards(guards)
	_ = originFn
	_ = maxObservedDepth
	return originParam, originFn, hops, guards, truncated, structuredInput
}

// fnExported reports whether fn is an exported entrypoint (its own name, or - for
// a method - the method name, begins with an upper-case letter). Cosmos consensus
// surfaces (EndBlocker/BeginBlocker/handlers/msg-servers) are exported; a private
// pure-helper assert on a local is not, which keeps the widened panic predicate
// from firing on non-entrypoint internal noise.
func fnExported(fn *ssa.Function) bool {
	if fn == nil {
		return false
	}
	n := fn.Name()
	if n == "" {
		return false
	}
	return token.IsExported(n)
}

func dedupGuards(gs []guardRec) []guardRec {
	seen := map[string]bool{}
	var out []guardRec
	for _, g := range gs {
		k := fmt.Sprintf("%v:%v:%s", g.File, g.Line, g.Expr)
		if !seen[k] {
			seen[k] = true
			out = append(out, g)
		}
	}
	return out
}

func paramIndex(fn *ssa.Function, p *ssa.Parameter) int {
	for i, q := range fn.Params {
		if q == p {
			return i
		}
	}
	return -1
}

func returnValues(fn *ssa.Function) []ssa.Value {
	var out []ssa.Value
	for _, b := range fn.Blocks {
		if len(b.Instrs) == 0 {
			continue
		}
		if ret, ok := b.Instrs[len(b.Instrs)-1].(*ssa.Return); ok {
			out = append(out, ret.Results...)
		}
	}
	return out
}

func trim(s string) string {
	if len(s) > 160 {
		return s[:160]
	}
	return s
}

// -------- callgraph caller adapter --------

type callSite struct {
	edge *callgraph.Edge
}

func (cs callSite) common() *ssa.CallCommon {
	if cs.edge == nil || cs.edge.Site == nil {
		return nil
	}
	cc := cs.edge.Site.Common()
	return cc
}
func (cs callSite) callerFn() *ssa.Function {
	if cs.edge == nil || cs.edge.Caller == nil {
		return nil
	}
	return cs.edge.Caller.Func
}
func (cs callSite) instr() ssa.Instruction {
	if cs.edge == nil || cs.edge.Site == nil {
		return nil
	}
	return cs.edge.Site.(ssa.Instruction)
}
func (cs callSite) Pos() token.Pos {
	if cs.edge == nil || cs.edge.Site == nil {
		return token.NoPos
	}
	return cs.edge.Site.Pos()
}
func (cs callSite) String() string {
	if cc := cs.common(); cc != nil {
		return cc.String()
	}
	return ""
}

func (s *slicer) callersOf(fn *ssa.Function) []callSite {
	var out []callSite
	if s.cg == nil {
		return out
	}
	node := s.cg.Nodes[fn]
	if node == nil {
		return out
	}
	for _, e := range node.In {
		out = append(out, callSite{e})
	}
	return out
}

// -------- forward slice (lightweight, for completeness) --------
//
// For each source parameter that reaches a sink, the backward slice already
// captures the full path. We additionally emit forward direction records by
// reversing the backward record so consumers asking direction="forward" get hits.

// -------- go1.25 TypeParam-safe callgraph substrate --------
//
// runtimeTypesSafe wraps prog.RuntimeTypes() in a recover. On go1.25.0 sources
// this reflection-reachability computation can PANIC inside x/tools
// (typesinternal.ForEachElement) when prog.makeInterfaceTypes contains a type
// still parameterized by a *types.TypeParam. When that happens we lose only the
// set of reflection-reachable runtime types (a best-effort CHA over-approximation
// extra), NOT the IR-backed call/def-use structure. We surface the degrade LOUDLY
// on stderr (never a silent starve) and return an empty slice so the caller keeps
// going with the syntactic function set.
func runtimeTypesSafe(prog *ssa.Program) (rts []types.Type, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
			rts = nil
			fmt.Fprintf(os.Stderr,
				"go-dataflow: WARN RuntimeTypes() panicked (%v); "+
					"proceeding with syntactic function set only "+
					"(reflection-reachable methods omitted, partial callgraph)\n", r)
		}
	}()
	return prog.RuntimeTypes(), false
}

// allFunctionsSafe mirrors ssautil.AllFunctions but recover-guards the
// prog.RuntimeTypes() step that panics on go1.25 parameterized MakeInterface
// operands. Everything else (the operand-closure over declared/anonymous funcs,
// the exported-named-type method hack, and methodsOf over runtime types) is a
// faithful reimplementation using only the PUBLIC ssa/types/typeutil API.
func allFunctionsSafe(prog *ssa.Program) map[*ssa.Function]bool {
	seen := make(map[*ssa.Function]bool)

	var function func(fn *ssa.Function)
	function = func(fn *ssa.Function) {
		if fn == nil || seen[fn] {
			return
		}
		seen[fn] = true
		var buf [10]*ssa.Value
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				for _, op := range instr.Operands(buf[:0]) {
					if g, ok := (*op).(*ssa.Function); ok {
						function(g)
					}
				}
			}
		}
	}

	methodsOf := func(T types.Type) {
		if types.IsInterface(T) {
			return
		}
		mset := prog.MethodSets.MethodSet(T)
		for i := 0; i < mset.Len(); i++ {
			sel := mset.At(i)
			// Skip generic methods (cannot be materialized as a concrete fn).
			if sel.Obj().(*types.Func).Type().(*types.Signature).TypeParams() == nil {
				function(prog.MethodValue(sel))
			}
		}
	}

	// Exported named concrete types: include T and *T method sets, as x/tools
	// does for backward compatibility with reflection-reachable methods.
	exportedTypeHack := func(t *ssa.Type) {
		if !isExportedName(t.Name()) || types.IsInterface(t.Type()) {
			return
		}
		if named, ok := t.Type().(*types.Named); ok {
			if named.TypeParams() == nil { // skip generic types
				methodsOf(named)
				methodsOf(types.NewPointer(named))
			}
		}
	}

	for _, pkg := range prog.AllPackages() {
		for _, mem := range pkg.Members {
			switch mem := mem.(type) {
			case *ssa.Function:
				function(mem)
			case *ssa.Type:
				exportedTypeHack(mem)
			}
		}
	}

	// Reflection-reachable runtime types. THIS is the step that panics on
	// go1.25 sources; runtimeTypesSafe converts the panic into a reported
	// partial (empty slice) instead of unwinding the whole analysis.
	for _, T := range func() []types.Type { rts, _ := runtimeTypesSafe(prog); return rts }() {
		methodsOf(T)
	}

	return seen
}

func isExportedName(name string) bool {
	if name == "" {
		return false
	}
	c := name[0]
	return c >= 'A' && c <= 'Z'
}

// chaCallGraphSafe is a faithful, self-contained reimplementation of
// cha.CallGraph that takes a precomputed function set (so it never re-invokes the
// panicking ssautil.AllFunctions). The dynamic-dispatch resolution mirrors
// x/tools' internal chautil.LazyCallees exactly (CHA over the whole implements
// relation), using only the public ssa/types/typeutil API.
func chaCallGraphSafe(prog *ssa.Program, allFuncs map[*ssa.Function]bool) *callgraph.Graph {
	cg := callgraph.New(nil)
	calleesOf := lazyCalleesSafe(allFuncs)

	addEdge := func(fnode *callgraph.Node, site ssa.CallInstruction, g *ssa.Function) {
		gnode := cg.CreateNode(g)
		callgraph.AddEdge(fnode, site, gnode)
	}

	for f := range allFuncs {
		fnode := cg.CreateNode(f)
		for _, b := range f.Blocks {
			for _, instr := range b.Instrs {
				if site, ok := instr.(ssa.CallInstruction); ok {
					if g := site.Common().StaticCallee(); g != nil {
						addEdge(fnode, site, g)
					} else {
						for _, g := range calleesOf(site) {
							addEdge(fnode, site, g)
						}
					}
				}
			}
		}
	}
	return cg
}

// lazyCalleesSafe is a verbatim port of x/tools go/callgraph/internal/chautil
// LazyCallees (which is an internal package we cannot import). It resolves each
// dynamic call site to its CHA callee set over allFuncs.
func lazyCalleesSafe(fns map[*ssa.Function]bool) func(site ssa.CallInstruction) []*ssa.Function {
	var funcsBySig typeutil.Map // value is []*ssa.Function
	methodsByID := make(map[string][]*ssa.Function)

	type imethod struct {
		I  *types.Interface
		id string
	}
	methodsMemo := make(map[imethod][]*ssa.Function)
	lookupMethods := func(I *types.Interface, m *types.Func) []*ssa.Function {
		id := m.Id()
		methods, ok := methodsMemo[imethod{I, id}]
		if !ok {
			for _, f := range methodsByID[id] {
				C := f.Signature.Recv().Type() // named or *named
				if types.Implements(C, I) {
					methods = append(methods, f)
				}
			}
			methodsMemo[imethod{I, id}] = methods
		}
		return methods
	}

	for f := range fns {
		if f.Signature.Recv() == nil {
			if f.Name() == "init" && f.Synthetic == "package initializer" {
				continue
			}
			funcs, _ := funcsBySig.At(f.Signature).([]*ssa.Function)
			funcs = append(funcs, f)
			funcsBySig.Set(f.Signature, funcs)
		} else if obj := f.Object(); obj != nil {
			id := obj.(*types.Func).Id()
			methodsByID[id] = append(methodsByID[id], f)
		}
	}

	return func(site ssa.CallInstruction) []*ssa.Function {
		call := site.Common()
		if call.IsInvoke() {
			tiface := call.Value.Type().Underlying().(*types.Interface)
			return lookupMethods(tiface, call.Method)
		} else if g := call.StaticCallee(); g != nil {
			return []*ssa.Function{g}
		} else if _, ok := call.Value.(*ssa.Builtin); !ok {
			fns, _ := funcsBySig.At(call.Signature()).([]*ssa.Function)
			return fns
		}
		return nil
	}
}

// -------- main analysis --------

func analyze(patterns []string, maxDepth int, forward bool, panicSinks bool) ([]pathRec, error) {
	cfg := &packages.Config{
		Mode: packages.LoadAllSyntax,
		Dir:  "",
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, fmt.Errorf("packages.Load: %w", err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		// type/parse errors -> SSA may be incomplete. Treat as degrade unless we
		// still managed to build some functions.
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("no packages loaded for %v", patterns)
	}

	prog, _ := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics|ssa.SanityCheckFunctions)
	// prog.Build() is best-effort: on go1.25 generics-heavy sources a sanity-check or
	// generic-instantiation edge can panic mid-build. Recover-guard it so the arm
	// proceeds over whatever functions WERE built (already-built function bodies are
	// still sliceable) instead of unwinding the whole analysis into a degrade-0
	// sentinel. Reported LOUDLY (R80), never silent.
	//
	// SCOPED-BUILD (root-caused axelar-dlt 2026-07-14): on a heavy cosmos-sdk
	// closure (axelar-core: a single in-scope keeper pulls in ~265 dependency
	// packages of generics-heavy cosmos-sdk/ibc/tendermint) the cost is NOT the
	// type-check - packages.Load(LoadAllSyntax) for the smallest in-scope package
	// (`./config`) finishes in 0.5s. It is prog.Build() eagerly building SSA
	// function BODIES for ALL 265 closure packages, which exceeds 240s/package and
	// makes even the batched per-package runner time out (RC=124, 0 records ->
	// fail-dataflow-substrate-starved). When AUDITOOOR_GO_DATAFLOW_SCOPED_BUILD is
	// truthy we build SSA bodies ONLY for the INITIAL (pattern-matched, in-scope)
	// packages - `pkgs` are exactly the target packages, their .Imports are the
	// out-of-scope closure. Every in-scope function body is still built (so
	// intra-package param-tainted panic sinks + in-package inter-proc hops are
	// fully sliced); hops that leave the target package into an UNBUILT cosmos-sdk
	// dependency simply terminate (callee.Blocks == nil) - which is the desired
	// in-scope boundary for the batched per-package runner (each in-scope package
	// is a separate target, so the union still covers every in-scope body). Gated
	// OFF by default so the whole-program inter-proc slice is byte-identical for
	// existing consumers; the python batched runner turns it on per-package.
	scopedBuild := func() bool {
		v := strings.TrimSpace(strings.ToLower(os.Getenv("AUDITOOOR_GO_DATAFLOW_SCOPED_BUILD")))
		return !(v == "" || v == "0" || v == "false" || v == "no")
	}()
	func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr,
					"go-dataflow: WARN SSA build panicked (%v); proceeding with the "+
						"partially-built SSA (some function bodies may be absent)\n", r)
			}
		}()
		if scopedBuild {
			built := 0
			for _, p := range pkgs {
				if p == nil || p.Types == nil {
					continue
				}
				if sp := prog.Package(p.Types); sp != nil {
					sp.Build()
					built++
				}
			}
			fmt.Fprintf(os.Stderr,
				"go-dataflow: scoped-build ON - built SSA for %d in-scope package(s) "+
					"only (closure deps left unbuilt; hops exiting in-scope terminate)\n",
				built)
		} else {
			prog.Build()
		}
	}()

	// callgraph: CHA, refined by VTA when the program is non-trivial.
	//
	// NOTE (go1.25 TypeParam panic fix): we deliberately do NOT call
	// ssautil.AllFunctions / cha.CallGraph from x/tools directly. Both route
	// through Program.RuntimeTypes(), which iterates prog.makeInterfaceTypes and
	// calls the internal typesinternal.ForEachElement. On go1.25.0 sources
	// (generics-heavy cosmos-sdk / axelar-core), a MakeInterface operand whose
	// type still contains a *types.TypeParam gets registered, and ForEachElement
	// PANICS ("ForEachElement called on type containing *types.TypeParam").
	// That panic previously unwound the whole analysis into a single degrade
	// record - starving every dataflow-dependent lens. allFunctionsSafe /
	// chaCallGraphSafe below reimplement the same logic but recover-guard the
	// RuntimeTypes reflection-reachability step, degrading it to a REPORTED
	// partial (a stderr note) instead of a silent starve.
	allFns := allFunctionsSafe(prog)
	var cg *callgraph.Graph
	chaG := chaCallGraphSafe(prog, allFns)
	cg = chaG
	// VTA refinement (best effort; falls back to CHA on panic)
	func() {
		defer func() { _ = recover() }()
		vtaG := vta.CallGraph(allFns, chaG)
		if vtaG != nil {
			cg = vtaG
		}
	}()

	s := &slicer{prog: prog, cg: cg, maxDepth: maxDepth, engine: "go-ssa-cha-vta"}

	var records []pathRec
	pathID := 0

	// iterate all functions; find sink call instructions
	fns := make([]*ssa.Function, 0, len(allFns))
	for f := range allFns {
		fns = append(fns, f)
	}
	sort.Slice(fns, func(i, j int) bool { return fns[i].String() < fns[j].String() })

	// sliceOneFunc scans ONE function for sink calls and appends the def-use path
	// records it finds. Extracted so the caller can wrap it in a PER-FUNCTION recover:
	// if slicing a single (typically generics-heavy) function panics deep in x/tools
	// (e.g. a go1.25 *types.TypeParam edge that slips past the RuntimeTypes guard, or a
	// VTA-refined callee whose instantiated body trips an internal invariant), that ONE
	// function degrades to SKIPPED - it never unwinds the whole arm into a single
	// degrade-0 sentinel. This is the slicing-loop analogue of runtimeTypesSafe: a
	// reported partial, never a silent (or total) starve.
	sliceOneFunc := func(fn *ssa.Function) {
		if fn.Blocks == nil {
			return
		}
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				// PANIC-CAPABLE NODE arm (only under -panic-sinks): a type-assert
				// without comma-ok / an index-or-slice (OOB) / a pointer nil-deref
				// whose triggering OPERAND the backward slicer traces to a param source
				// is an attacker-reaches-panic-capable-node fact. Emitted as a
				// kind=="panic" record so the must-succeed-panic reasoner can JOIN it
				// with the ABCI/lifecycle entrypoint family (consensus-halt class).
				if panicSinks {
					if operand, op, isPanic := panicOperand(instr); isPanic {
						originParam, originFn, hops, guards, truncated, structuredInput := s.sliceArg(operand, fn, instr)
						// A panic-capable node counts when its triggering operand is
						// externally influenced. TWO accepted taint origins:
						//  (1) originParam != nil  - the operand traces to a function
						//      Parameter (the strong, cross-language default).
						//  (2) structuredInput && fnExported(fn) - the operand traces
						//      to STRUCTURED state/message input (a struct field, a map
						//      entry, or an opaque/external call return) inside an
						//      exported entrypoint. This is the cosmos decode idiom:
						//      codec Unmarshal populates via a pointer-OUTPUT arg, so a
						//      decoded value has NO def-use edge to a *ssa.Parameter and
						//      (1) alone drops every cosmos EndBlocker/handler assert.
						//      Gating on fnExported + structuredInput keeps this a
						//      dataflow fact (a pure-local/const assert sets neither),
						//      not a `.(`-token grep.
						paramTainted := originParam != nil
						stateTainted := structuredInput && fnExported(fn)
						if paramTainted || stateTainted {
							pFile, pLine := pos(prog, instr.Pos())
							rec := pathRec{
								Schema:    schemaVersion,
								PathID:    fmt.Sprintf("go-%d-panic", pathID),
								Language:  "go",
								Direction: "backward",
								Engine:    s.engine,
								Sink: sinkRec{
									Kind:    "panic",
									Fn:      sp(fnName(fn)),
									File:    nilIfEmpty(pFile),
									Line:    nilIfZero(pLine),
									PanicOp: sp(op),
								},
								Hops:          normHops(hops),
								GuardNodes:    normGuards(guards),
								SourceUnitIDs: []string{},
								SinkUnitIDs:   []string{},
								Confidence:    "semantic-ssa",
								Degraded:      false,
							}
							of := originFn
							if of == nil {
								of = fn
							}
							if originParam != nil {
								spFile, spLine := pos(prog, originParam.Pos())
								rec.Source = srcRec{
									Kind: "param",
									Fn:   sp(fnName(of)),
									Var:  sp(originParam.Name()),
									File: nilIfEmpty(spFile),
									Line: nilIfZero(spLine),
								}
							} else {
								// state-tainted: the operand came from structured
								// state/message input inside this exported entrypoint,
								// with no def-use edge to a Parameter (cosmos decode).
								sFile, sLine := pos(prog, instr.Pos())
								rec.Source = srcRec{
									Kind: "state",
									Fn:   sp(fnName(fn)),
									File: nilIfEmpty(sFile),
									Line: nilIfZero(sLine),
								}
							}
							rec.CallDepth = countInterproc(rec.Hops)
							rec.Unguarded = !(len(rec.GuardNodes) > 0 || anyHopGuarded(rec.Hops))
							rec.DataflowTruncated = truncated
							records = append(records, rec)
							pathID++
						}
					}
				}
				call, ok := instr.(*ssa.Call)
				if !ok {
					continue
				}
				cc := call.Common()
				kind, callee, isSink := classifySink(cc)
				if !isSink {
					continue
				}
				// slice each argument backward toward a source parameter
				for argPos, arg := range cc.Args {
					originParam, originFn, hops, guards, truncated, _ := s.sliceArg(arg, fn, instr)
					if originParam == nil && len(hops) == 0 {
						continue // pure constant / no taint origin -> skip
					}
					sinkFile, sinkLine := pos(prog, call.Pos())
					rec := pathRec{
						Schema:    schemaVersion,
						PathID:    fmt.Sprintf("go-%d", pathID),
						Language:  "go",
						Direction: "backward",
						Engine:    s.engine,
						Sink: sinkRec{
							Kind:   kind,
							Callee: sp(callee),
							ArgPos: ip(argPos),
							Fn:     sp(fnName(fn)),
							File:   nilIfEmpty(sinkFile),
							Line:   nilIfZero(sinkLine),
							Cell:   nilIfEmpty(collectionCellName(cc)),
						},
						Hops:          normHops(hops),
						GuardNodes:    normGuards(guards),
						SourceUnitIDs: []string{},
						SinkUnitIDs:   []string{},
						Confidence:    "semantic-ssa",
						Degraded:      false,
					}
					if originParam != nil {
						of := originFn
						if of == nil {
							of = fn
						}
						pFile, pLine := pos(prog, originParam.Pos())
						rec.Source = srcRec{
							Kind: "param",
							Fn:   sp(fnName(of)),
							Var:  sp(originParam.Name()),
							File: nilIfEmpty(pFile),
							Line: nilIfZero(pLine),
						}
					} else {
						rec.Source = srcRec{Kind: "local", Fn: sp(fnName(fn))}
					}
					// derive call_depth + unguarded (mirror python new_path semantics)
					rec.CallDepth = countInterproc(rec.Hops)
					rec.Unguarded = !(len(rec.GuardNodes) > 0 || anyHopGuarded(rec.Hops))
					rec.DataflowTruncated = truncated
					records = append(records, rec)
					pathID++

					if forward {
						fwd := rec
						fwd.PathID = fmt.Sprintf("go-%d-fwd", pathID)
						fwd.Direction = "forward"
						records = append(records, fwd)
						pathID++
					}
				}
			}
		}
	}

	// safeSliceOneFunc runs sliceOneFunc under a recover so ONE pathological function
	// is skipped-and-counted, never fatal to the arm. Returns true when the function
	// panicked (so the caller can tally + report it).
	safeSliceOneFunc := func(fn *ssa.Function) (panicked bool) {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		sliceOneFunc(fn)
		return false
	}

	var skippedFns int
	var skippedSample []string
	for _, fn := range fns {
		if safeSliceOneFunc(fn) {
			skippedFns++
			if len(skippedSample) < 10 {
				skippedSample = append(skippedSample, fnName(fn))
			}
		}
	}
	if skippedFns > 0 {
		// LOUD, never silent (R80): report exactly how many functions were skipped
		// and a bounded sample, so a partial slice is auditable - not mistaken for a
		// clean complete run.
		fmt.Fprintf(os.Stderr,
			"go-dataflow: WARN skipped %d function(s) whose slicing panicked "+
				"(per-function degrade; real paths from all other functions retained); "+
				"sample=%v\n", skippedFns, skippedSample)
	}
	return records, nil
}

func countInterproc(hops []hopRec) int {
	n := 0
	for _, h := range hops {
		switch h.Via {
		case "internal_call", "high_level", "return", "storage":
			n++
		}
	}
	return n
}

func anyHopGuarded(hops []hopRec) bool {
	for _, h := range hops {
		if h.Guarded {
			return true
		}
	}
	return false
}

// emitCap bounds the SERIALIZED length of the per-record hops / guard_nodes
// arrays. This is independent of the traversal ceilings (maxHops/maxDepth/maxWork,
// which govern how deep the analysis EXPLORES) - it bounds only what is WRITTEN.
// Without it a single pathological slice through the cosmos-sdk codec/amino/context
// graph balloons one record to tens of MB (observed NUVA 2026-07-06: one record
// carried guard_nodes len=163722 = 23.5MB + hops len=4096 = 1.1MB; the whole slice
// serialized to 543MB, and the python arm's json.loads OOM-hung on it, so step-1c
// dataflow-slice produced ZERO records on every cosmos-scale Go workspace).
// 96 is far above any downstream consumer's need: the Unguarded flag only checks
// len(guard_nodes)>0, and path-mode hunt ranking never reads beyond the first few
// dozen hops - so this loses no signal, it only stops the serialization runaway.
func emitCap(name string, def int) int {
	n := envInt(name, def)
	if n <= 0 {
		return def
	}
	return n
}

func normHops(h []hopRec) []hopRec {
	if h == nil {
		return []hopRec{}
	}
	if lim := emitCap("AUDITOOOR_DATAFLOW_EMIT_HOPS", 96); len(h) > lim {
		return h[:lim]
	}
	return h
}
func normGuards(g []guardRec) []guardRec {
	if g == nil {
		return []guardRec{}
	}
	if lim := emitCap("AUDITOOOR_DATAFLOW_EMIT_GUARDS", 96); len(g) > lim {
		return g[:lim]
	}
	return g
}

func main() {
	var (
		// B-hops: default is now the HIGH safety ceiling (effectively unbounded), not 8.
		// Pass -max-depth N (>0) to pin a cap, or set AUDITOOOR_DATAFLOW_MAX_DEPTH.
		maxDepth = flag.Int("max-depth", envInt("AUDITOOOR_DATAFLOW_MAX_DEPTH", 24),
			"max inter-procedural boundary depth (HIGH safety ceiling; visited-set is the real terminator)")
		forward = flag.Bool("forward", false, "also emit forward-direction records")
		// -panic-sinks: ADDITIONALLY emit kind=="panic" records for panic-CAPABLE
		// SSA nodes (type-assert w/o comma-ok, index/slice OOB, pointer nil-deref)
		// whose triggering operand the backward slicer traces to a param source. This
		// is the substrate the Go must-succeed-panic-reachability reasoner consumes:
		// attacker-param -> panic-capable node, joined downstream with the ABCI /
		// module-lifecycle (must-succeed) entrypoint family for the consensus-halt class.
		panicSinks = flag.Bool("panic-sinks", false,
			"also emit kind=panic records for param-tainted panic-capable SSA nodes")
		// A-P3 derivation-parity probe: read a hops JSON array on stdin and emit the
		// derived {call_depth, unguarded} so a cross-language test can assert this Go
		// formula matches dataflow_schema.new_path's (no SSA build needed).
		deriveCheck = flag.Bool("derive-check", false,
			"read {\"hops\":[...],\"guard_nodes\":[...]} on stdin; emit derived call_depth+unguarded")
	)
	flag.Parse()

	if *deriveCheck {
		runDeriveCheck()
		return
	}

	patterns := flag.Args()
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}

	defer func() {
		if r := recover(); r != nil {
			emitDegrade(fmt.Sprintf("panic during analysis: %v", r))
			os.Exit(0)
		}
	}()

	recs, err := analyze(patterns, *maxDepth, *forward, *panicSinks)
	if err != nil {
		emitDegrade(fmt.Sprintf("load/build failure: %v", err))
		os.Exit(0) // R80: advisory, never silent, never non-zero on degrade
	}
	if recs == nil {
		recs = []pathRec{}
	}
	out, e := json.Marshal(recs)
	if e != nil {
		emitDegrade(fmt.Sprintf("json marshal: %v", e))
		os.Exit(0)
	}
	fmt.Println(string(out))
}

// runDeriveCheck reads a {"hops":[...],"guard_nodes":[...]} object on stdin and prints
// {"call_depth":N,"unguarded":bool} using the SAME countInterproc / anyHopGuarded
// formula the producer uses. The Python parity test (tools/tests/
// test_go_python_derivation_parity.py) feeds identical inputs to dataflow_schema.new_path
// and asserts the two derivations agree (A-P3 Go/Python drift guard).
func runDeriveCheck() {
	var in struct {
		Hops       []hopRec   `json:"hops"`
		GuardNodes []guardRec `json:"guard_nodes"`
	}
	dec := json.NewDecoder(os.Stdin)
	if err := dec.Decode(&in); err != nil {
		fmt.Printf("{\"error\":%q}\n", err.Error())
		os.Exit(2)
	}
	callDepth := countInterproc(in.Hops)
	unguarded := !(len(in.GuardNodes) > 0 || anyHopGuarded(in.Hops))
	res := map[string]interface{}{"call_depth": callDepth, "unguarded": unguarded}
	b, _ := json.Marshal(res)
	fmt.Println(string(b))
}
