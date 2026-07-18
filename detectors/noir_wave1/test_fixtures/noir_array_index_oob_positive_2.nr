// Positive fixture: dynamic index `pos` computed from arithmetic,
// used to index array without bounds assertion.
use dep::std;

struct MerkleTree {
    nodes: [Field; 32],
}

impl MerkleTree {
    fn get_sibling(self, pos: u32) -> Field {
        let sibling_pos = pos ^ 1; // flip LSB to get sibling
        // BUG: sibling_pos could be >= 32 if pos is large enough
        // No assert(sibling_pos < 32) before indexing
        self.nodes[sibling_pos]
    }
}

fn main(tree: MerkleTree, pos: pub u32) -> pub Field {
    tree.get_sibling(pos)
}
