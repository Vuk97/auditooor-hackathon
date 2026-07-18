use std::collections::{HashMap, HashSet};
use std::sync::Arc;

mod sprout {
    pub mod tree {
        pub type Root = [u8; 32];

        #[derive(Clone)]
        pub struct NoteCommitmentTree {
            pub root_value: Root,
        }

        impl NoteCommitmentTree {
            pub fn root(&self) -> Root {
                self.root_value
            }
        }
    }
}

mod sapling {
    pub mod tree {
        pub type Root = [u8; 32];
    }
}

struct ZebraDb;
struct Chain {
    sapling_anchors: HashSet<sapling::tree::Root>,
    sprout_trees_by_anchor: HashMap<sprout::tree::Root, Arc<sprout::tree::NoteCommitmentTree>>,
}
struct JoinSplit {
    anchor: sprout::tree::Root,
}
struct Transaction {
    joinsplits: Vec<JoinSplit>,
    sapling: Vec<sapling::tree::Root>,
}
enum ValidateContextError {
    UnknownSaplingAnchor,
}

impl Transaction {
    fn sapling_anchors(&self) -> impl Iterator<Item = sapling::tree::Root> + '_ {
        self.sapling.iter().copied()
    }

    fn sprout_groth16_joinsplits(&self) -> impl Iterator<Item = &JoinSplit> {
        self.joinsplits.iter()
    }
}

impl ZebraDb {
    fn contains_sapling_anchor(&self, _anchor: &sapling::tree::Root) -> bool {
        false
    }

    fn sprout_tree_by_anchor(
        &self,
        _anchor: &sprout::tree::Root,
    ) -> Option<Arc<sprout::tree::NoteCommitmentTree>> {
        None
    }
}

fn sapling_anchor_finalized_only(
    finalized_state: &ZebraDb,
    transaction: &Transaction,
) -> Result<(), ValidateContextError> {
    for anchor in transaction.sapling_anchors() {
        if !finalized_state.contains_sapling_anchor(&anchor) {
            return Err(ValidateContextError::UnknownSaplingAnchor);
        }
    }

    Ok(())
}

fn fetch_sprout_final_treestates_without_root_binding(
    sprout_final_treestates: &mut HashMap<
        sprout::tree::Root,
        Arc<sprout::tree::NoteCommitmentTree>,
    >,
    finalized_state: &ZebraDb,
    parent_chain: Option<&Arc<Chain>>,
    transaction: &Transaction,
) {
    for joinsplit in transaction.sprout_groth16_joinsplits() {
        let input_tree = parent_chain
            .and_then(|chain| chain.sprout_trees_by_anchor.get(&joinsplit.anchor).cloned())
            .or_else(|| finalized_state.sprout_tree_by_anchor(&joinsplit.anchor));

        if let Some(input_tree) = input_tree {
            sprout_final_treestates.insert(joinsplit.anchor, input_tree);
        }
    }
}
