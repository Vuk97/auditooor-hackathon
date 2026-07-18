package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Regression for the go1.25 "*types.TypeParam" family of panics (axelar-core):
// a workspace containing a GENERIC function must NOT degrade the whole go-dataflow
// arm into a single degrade-0 sentinel. analyze() runs the full pipeline (packages.Load
// -> SSA build [guarded] -> callgraph [CHA + guarded VTA] -> per-function slicing
// [guarded]) end-to-end over a tiny on-disk module whose only non-trivial function is
// generic and whose type parameter flows into a recognized sink (Transfer). We assert:
//   - analyze returns WITHOUT error and WITHOUT panicking (no whole-arm unwind), and
//   - it emits >=1 REAL (non-degrade) semantic-ssa path from the generic function.
//
// This is the end-to-end complement to the unit-level safe-helper tests in
// typeparam_panic_test.go: those prove runtimeTypesSafe/allFunctionsSafe/chaCallGraphSafe
// survive the RuntimeTypes panic; this proves the arm as a whole still PRODUCES real
// def-use paths on generic code instead of a single degrade sentinel.
func TestAnalyzeGenericFixtureEmitsRealPathsNotGlobalDegrade(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module genfix\n\ngo 1.21\n")
	// Process is generic; its type parameter v flows into Transfer (a sink verb), so
	// the backward slice yields a real param->sink path. Run calls it so the generic
	// body is reachable/instantiated.
	writeFile(t, filepath.Join(dir, "f.go"), `package genfix

func Transfer(amount string) {}

func Process[T ~string](v T) {
	Transfer(string(v))
}

func Run(x string) {
	Process(x)
}
`)

	// analyze() loads from the current working directory; chdir into the fixture module.
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(prev) }()

	var recs []pathRec
	panicked := recovers(func() {
		recs, err = analyze([]string{"./..."}, 24, false, false)
	})
	if panicked != nil {
		t.Fatalf("analyze panicked on a generic fixture (whole-arm unwind): %v", panicked)
	}
	if err != nil {
		t.Fatalf("analyze returned error on a generic fixture: %v", err)
	}

	// Must NOT be a single global degrade sentinel, and must contain >=1 real path.
	real := 0
	for _, r := range recs {
		if !r.Degraded {
			real++
		}
	}
	if real == 0 {
		t.Fatalf("expected >=1 real (non-degrade) path from the generic fixture, got %d records: %+v", len(recs), recs)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
