use std::{
    ffi::OsString,
    path::{Component, Path, PathBuf},
};

use crate::{
    backend::node::{Metadata, Node, NodeType},
    blob::tree::comp_to_osstr,
};

/// `TreeIterator` turns an Iterator yielding items with paths and Nodes into an
/// Iterator which ensures that all subdirectories are visited and closed.
/// The resulting Iterator yields a `TreeType` which either contains the original
/// item, a new tree to be inserted or a pseudo item which indicates that a tree is finished.
///
/// # Type Parameters
///
/// * `T` - The type of the current item.
/// * `I` - The type of the original Iterator.
/// * `F` - The type of the function giving the nodes of missing directories.
pub(crate) struct TreeIterator<T, I, F = fn(&Path) -> Option<Node>> {
    /// The original Iterator.
    iter: I,
    /// The current path.
    path: PathBuf,
    /// The current item.
    item: Option<T>,
    /// BackOtter: the node of a directory the original Iterator doesn't
    /// give (one above the backed-up paths), by its path, if it has one.
    dir_node: F,
}

impl<T, I> TreeIterator<T, I>
where
    I: Iterator<Item = T>,
{
    #[cfg(test)]
    pub(crate) fn new(iter: I) -> Self {
        Self::with_dir_nodes(iter, |_| None)
    }
}

impl<T, I, F> TreeIterator<T, I, F>
where
    I: Iterator<Item = T>,
{
    /// BackOtter: as [`TreeIterator::new`], with `dir_node` giving the
    /// nodes of missing directories (those above the backed-up paths) with
    /// their own metadata, as restic stores them. Where it gives none, the
    /// directory gets a node of rustic's own making.
    pub(crate) fn with_dir_nodes(mut iter: I, dir_node: F) -> Self {
        let item = iter.next();
        Self {
            iter,
            path: PathBuf::new(),
            item,
            dir_node,
        }
    }

    // like self.path.pop(), but does also pop path prefixes (on windows; like "C:\")
    fn pop(&mut self) -> bool {
        let mut comps = self.path.components();
        loop {
            let comp = comps.next_back();
            match comp {
                Some(Component::Prefix(_) | Component::Normal(_)) => {
                    self.path = comps.collect();
                    return true;
                }
                Some(Component::RootDir | Component::ParentDir | Component::CurDir) => {}
                None => return false,
            }
        }
    }
}

/// `TreeType` is the type returned by the `TreeIterator`.
///
/// It either contains the original item, a new tree to be inserted
/// or a pseudo item which indicates that a tree is finished.
///
/// # Type Parameters
///
/// * `T` - The type of the original item.
/// * `U` - The type of the new tree.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TreeType<T, U> {
    /// New tree to be inserted.
    NewTree((PathBuf, Node, U)),
    /// A pseudo item which indicates that a tree is finished.
    EndTree,
    /// Original item.
    Other((PathBuf, Node, T)),
}

impl<I, O, F> Iterator for TreeIterator<(PathBuf, Node, O), I, F>
where
    I: Iterator<Item = (PathBuf, Node, O)>,
    F: FnMut(&Path) -> Option<Node>,
{
    type Item = TreeType<O, OsString>;
    fn next(&mut self) -> Option<Self::Item> {
        match &self.item {
            None => self.pop().then_some(TreeType::EndTree),
            Some((path, node, _)) => {
                match path.strip_prefix(&self.path) {
                    Err(_) => {
                        _ = self.pop();
                        Some(TreeType::EndTree)
                    }
                    Ok(missing_dirs) => {
                        for comp in missing_dirs.components() {
                            self.path.push(comp);
                            // process next normal path component - other components are simply ignored
                            if let Some(p) = comp_to_osstr(comp).ok().flatten() {
                                if node.is_dir() && path == &self.path {
                                    let (path, node, _) = self.item.take().unwrap();
                                    self.item = self.iter.next();
                                    let name = node.name().into_owned();
                                    return Some(TreeType::NewTree((path, node, name)));
                                }
                                // BackOtter: a missing dir's own metadata,
                                // as restic stores it, where it has some
                                let node = (self.dir_node)(&self.path)
                                    .filter(|node| node.is_dir() && node.name() == p)
                                    .unwrap_or_else(|| {
                                        // Use mode 755 for missing dirs, so they can be accessed
                                        let meta = Metadata {
                                            mode: Some(0o755),
                                            ..Default::default()
                                        };
                                        Node::new_node(&p, NodeType::Dir, meta)
                                    });
                                return Some(TreeType::NewTree((
                                    self.path.clone(),
                                    node,
                                    p.into_owned(),
                                )));
                            }
                        }
                        // there wasn't any normal path component to process - return current item
                        let item = self.item.take().unwrap();
                        self.item = self.iter.next();
                        Some(TreeType::Other(item))
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use insta::assert_debug_snapshot;
    use rstest::rstest;

    use super::*;
    use std::path::Path;

    fn test_tree_iter(case: &str, paths: Vec<&str>) {
        let paths = paths.into_iter().map(|p| {
            (
                Path::new(&p).to_path_buf(),
                Node::new_node(
                    Path::new(&p).file_name().unwrap(),
                    NodeType::Dir,
                    Metadata::default(),
                ),
                (),
            )
        });

        let result: Vec<_> = TreeIterator::new(paths).collect();
        assert_debug_snapshot!(format!("tree_iter#{case}"), result);
    }

    #[cfg(not(windows))]
    #[rstest]
    #[case("simple", ["a", "a/b", "a/b/c"].to_vec())]
    #[case("simple_root", ["/a", "/a/b", "/a/b/c"].to_vec())]
    #[case("simple_relative", ["./a", "./a/b", "./a/b/c"].to_vec())]
    #[case("complex", ["a/b", "a/b/c", "a/b/d", "f"].to_vec())]
    #[case("complex_root", ["/a/b", "/a/b/c", "/a/b/d", "/f"].to_vec())]
    #[case("complex_relative", ["./a/b", "./a/b/c", "./a/b/d", "./f"].to_vec())]
    fn test_tree_iter_nix(#[case] case: &str, #[case] paths: Vec<&str>) {
        test_tree_iter(case, paths);
    }

    #[cfg(not(windows))]
    #[test]
    fn missing_dirs_get_their_own_nodes() {
        // BackOtter: the directories above a backed-up path get the nodes
        // `dir_node` gives, the others a node of rustic's own making.
        let item = |p: &str| {
            (
                Path::new(p).to_path_buf(),
                Node::new_node(
                    Path::new(p).file_name().unwrap(),
                    NodeType::Dir,
                    Metadata::default(),
                ),
                (),
            )
        };
        let own = |path: &Path| {
            (path == Path::new("/a")).then(|| {
                let meta = Metadata {
                    mode: Some(0o20_000_000_751),
                    uid: Some(1234),
                    ..Default::default()
                };
                Node::new_node(path.file_name().unwrap(), NodeType::Dir, meta)
            })
        };
        let new_trees: Vec<_> = TreeIterator::with_dir_nodes([item("/a/b/c")].into_iter(), own)
            .filter_map(|t| match t {
                TreeType::NewTree((path, node, _)) => Some((path, node)),
                _ => None,
            })
            .collect();
        assert_eq!(new_trees.len(), 3);
        assert_eq!(new_trees[0].0, Path::new("/a"));
        assert_eq!(new_trees[0].1.meta.mode, Some(0o20_000_000_751));
        assert_eq!(new_trees[0].1.meta.uid, Some(1234));
        assert_eq!(new_trees[1].0, Path::new("/a/b"));
        assert_eq!(new_trees[1].1.meta.mode, Some(0o755));
        assert_eq!(new_trees[1].1.meta.uid, None);
        assert_eq!(new_trees[2].0, Path::new("/a/b/c"));
    }

    #[cfg(windows)]
    #[rstest]
    #[case("windows", [r"C:\a", r"C:\a\b", r"D:\a"].to_vec())]
    fn test_tree_iter_windows(#[case] case: &str, #[case] paths: Vec<&str>) {
        test_tree_iter(case, paths);
    }
}
