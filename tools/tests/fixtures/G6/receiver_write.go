package trie

import "sync"

// RECEIVER-WRITE: the goroutine writes the RECEIVER's own field index
// (c.cache[index]), not a captured non-receiver. That shape is Pattern 39
// territory, not G6 -> G6 must NOT fire (keeps the two lanes distinct).
func (c *committer) fillCache(n *fullNode) {
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(index int) {
			c.cache[index] = n.Children[index]
			wg.Done()
		}(i)
	}
	wg.Wait()
}
