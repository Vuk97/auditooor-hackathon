package consume

// A *_test.go file - even a lax decode-then-consume here must be SKIPPED.
func testLaxCachedAssert(any *codectypes.Any) error {
	acc := any.GetCachedValue().(AccountI)
	return acc.Validate()
}
