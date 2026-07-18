package trie

import "sync"

// UNGUARDED: goroutine fan-out writes a captured non-receiver cell
// (n.Children[index]) with NO mutex/channel/atomic guard. A bare
// WaitGroup does NOT serialize the concurrent writes -> G6 must FIRE.
func (c *committer) commitChildrenUnsync(path []byte, n *fullNode) {
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		child := n.Children[i]
		if child == nil {
			continue
		}
		wg.Add(1)
		go func(index int) {
			p := append(path, byte(index))
			n.Children[index] = c.commit(p, child)
			wg.Done()
		}(i)
	}
	wg.Wait()
}
