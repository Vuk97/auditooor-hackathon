package trie

import "sync"

// GUARDED: same fan-out but a mutex Lock/Unlock CALL is present in the
// closure scope -> FP-guard suppresses (defended). G6 must NOT fire.
func (c *committer) commitChildrenLocked(path []byte, n *fullNode) {
	var (
		wg      sync.WaitGroup
		nodesMu sync.Mutex
	)
	for i := 0; i < 16; i++ {
		child := n.Children[i]
		if child == nil {
			continue
		}
		wg.Add(1)
		go func(index int) {
			p := append(path, byte(index))
			nodesMu.Lock()
			n.Children[index] = c.commit(p, child)
			nodesMu.Unlock()
			wg.Done()
		}(i)
	}
	wg.Wait()
}
