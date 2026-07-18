package trie

// LOCAL-VAR: the goroutine writes a slice DECLARED inside the closure
// (buf), so nothing shared is mutated -> G6 must NOT fire.
func process(items []int) {
	for i := 0; i < len(items); i++ {
		go func(index int) {
			buf := make([]int, 4)
			buf[index%4] = items[index]
			_ = buf
		}(i)
	}
}
