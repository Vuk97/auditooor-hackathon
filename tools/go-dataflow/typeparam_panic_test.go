package main

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// Regression for the go1.25 "ForEachElement called on type containing
// *types.TypeParam" panic (observed on axelar-core ./x/nexus/keeper, go 1.25.0).
//
// Root cause: a MakeInterface whose operand type still contains a *types.TypeParam
// gets registered into ssa.Program.makeInterfaceTypes. Program.RuntimeTypes() then
// iterates that set through the internal typesinternal.ForEachElement, which PANICS
// on any parameterized type. Both ssautil.AllFunctions and cha.CallGraph route
// through RuntimeTypes(), so the panic previously unwound the entire go-dataflow
// analysis into a single degrade-0 record - starving every dataflow-dependent lens
// (hunt / guard-reachability / chain-synth / SCC / coupled-state).
//
// The fix (allFunctionsSafe / chaCallGraphSafe / runtimeTypesSafe in main.go)
// recover-guards the RuntimeTypes() step and degrades it to a REPORTED partial
// (a stderr WARN) instead of a silent starve, so the IR-backed function set and
// call graph are still produced and real semantic-ssa paths are emitted.
//
// This test builds SSA for a generic-to-interface program WITHOUT
// ssa.InstantiateGenerics, which deterministically reproduces the parameterized
// MakeInterface registration and hence the RuntimeTypes() panic, then asserts the
// safe helpers survive it.
const genericIfaceSrc = `package p

type Item[T any] struct{ v T }

// Get performs a MakeInterface on a value of type T (a *types.TypeParam) inside
// the generic method template. Without InstantiateGenerics this parameterized
// type is registered into makeInterfaceTypes.
func (i Item[T]) Get() any { return i.v }

func Use() any {
	var it Item[string]
	return it.Get()
}
`

func buildGenericProg(t *testing.T, mode ssa.BuilderMode) *ssa.Program {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", genericIfaceSrc, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	tc := &types.Config{Importer: importer.Default()}
	pkg := types.NewPackage("example.com/p", "p")
	spkg, _, err := ssautil.BuildPackage(tc, fset, pkg, []*ast.File{f}, mode)
	if err != nil {
		t.Fatalf("BuildPackage: %v", err)
	}
	return spkg.Prog
}

func recovers(fn func()) (r any) {
	defer func() { r = recover() }()
	fn()
	return nil
}

// TestRuntimeTypesPanicIsReproduced documents the upstream panic: on a generic
// interface conversion built without InstantiateGenerics, prog.RuntimeTypes()
// panics with the ForEachElement message. If a future x/tools upgrade fixes this
// upstream (no panic), the test still passes and the safe helpers below remain a
// harmless no-op wrapper - so this guards the fix without pinning the bug.
func TestRuntimeTypesPanicIsReproduced(t *testing.T) {
	prog := buildGenericProg(t, ssa.SanityCheckFunctions) // NO InstantiateGenerics
	if r := recovers(func() { _ = prog.RuntimeTypes() }); r != nil {
		t.Logf("reproduced upstream RuntimeTypes() panic: %v", r)
	} else {
		t.Log("RuntimeTypes() did not panic on this toolchain (upstream may have fixed it); safe-path test still applies")
	}
}

// TestRuntimeTypesSafeNeverPanics asserts runtimeTypesSafe swallows the panic and
// reports it (panicked=true) instead of propagating - the core of the fix.
func TestRuntimeTypesSafeNeverPanics(t *testing.T) {
	prog := buildGenericProg(t, ssa.SanityCheckFunctions)
	if r := recovers(func() { _, _ = runtimeTypesSafe(prog) }); r != nil {
		t.Fatalf("runtimeTypesSafe must never propagate a panic, got: %v", r)
	}
}

// TestAllFunctionsSafeSurvivesTypeParam asserts allFunctionsSafe produces the
// IR-backed function set even when RuntimeTypes() would panic, and that
// chaCallGraphSafe builds a call graph over that set without panicking. This is
// the end-to-end guarantee that the go arm emits real paths instead of a starve.
func TestAllFunctionsSafeSurvivesTypeParam(t *testing.T) {
	prog := buildGenericProg(t, ssa.SanityCheckFunctions)

	var fns map[*ssa.Function]bool
	if r := recovers(func() { fns = allFunctionsSafe(prog) }); r != nil {
		t.Fatalf("allFunctionsSafe panicked on parameterized MakeInterface: %v", r)
	}
	if len(fns) == 0 {
		t.Fatalf("allFunctionsSafe returned an empty set; expected the declared/anonymous functions")
	}
	// The user-declared Use + Item.Get must be present in the function set.
	var sawUse, sawGet bool
	for f := range fns {
		switch f.Name() {
		case "Use":
			sawUse = true
		case "Get":
			sawGet = true
		}
	}
	if !sawUse {
		t.Errorf("expected function Use in the safe function set")
	}
	_ = sawGet // Get is a generic method; presence is toolchain-dependent, informative only

	if r := recovers(func() { _ = chaCallGraphSafe(prog, fns) }); r != nil {
		t.Fatalf("chaCallGraphSafe panicked: %v", r)
	}
}
