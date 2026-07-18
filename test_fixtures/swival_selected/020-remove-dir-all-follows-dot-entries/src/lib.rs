//! Hermetic Swival fixture skeleton.
//! Boundary: models traversal decisions only; it never deletes files.

#[derive(Clone)]
pub struct DirEntry {
    name: &'static str,
    is_dir: bool,
}

fn mock_readdir() -> Vec<DirEntry> {
    vec![
        DirEntry { name: ".", is_dir: true },
        DirEntry { name: "..", is_dir: true },
        DirEntry { name: "child", is_dir: true },
    ]
}

pub mod vulnerable {
    use super::*;

    pub fn traversal_targets() -> Vec<&'static str> {
        mock_readdir().into_iter().filter(|entry| entry.is_dir).map(|entry| entry.name).collect()
    }
}

pub mod clean {
    use super::*;

    pub fn traversal_targets() -> Vec<&'static str> {
        mock_readdir()
            .into_iter()
            .filter(|entry| entry.is_dir)
            .filter(|entry| entry.name != "." && entry.name != "..")
            .map(|entry| entry.name)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vulnerable_model_reaches_dot_entries() {
        assert_eq!(vulnerable::traversal_targets(), vec![".", "..", "child"]);
    }

    #[test]
    fn clean_model_filters_dot_entries_before_recursion() {
        assert_eq!(clean::traversal_targets(), vec!["child"]);
    }
}
