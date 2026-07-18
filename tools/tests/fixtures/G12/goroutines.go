package async

import "context"

// spawnBare: a bare goroutine with NO recover -> a panicking callee crashes
// the whole process. This is the FIRE case (M14-trap reachable-panic axis).
func spawnBare(work func()) {
	go func() {
		for {
			work() // work() may panic; nothing recovers here
		}
	}()
}

// spawnGuarded: benign sibling - the goroutine body DOES contain recover(),
// so a panicking callee is contained. This must NOT fire.
func spawnGuarded(work func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				_ = r
			}
		}()
		for {
			work()
		}
	}()
}

// callerRecoverUseless: the recover lives in the CALLER scope, not inside the
// goroutine. Per the FP-guard note, caller-scope recover is useless, so the
// bare goroutine here must still FIRE.
func callerRecoverUseless(ctx context.Context, work func()) {
	defer func() {
		_ = recover()
	}()
	go func() {
		work()
	}()
}

// commentRecoverStillFires: a `// recover()` comment must NOT count as a guard;
// this bare goroutine must FIRE.
func commentRecoverStillFires(work func()) {
	go func() {
		// recover() would go here but does not
		work()
	}()
}
