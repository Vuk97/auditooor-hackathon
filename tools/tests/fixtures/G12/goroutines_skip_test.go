package async

// A bare goroutine in a *_test.go file must be skipped by G12.
func spawnBareInTest(work func()) {
	go func() {
		work()
	}()
}
