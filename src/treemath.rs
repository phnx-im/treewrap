// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::cmp::Ordering;

/// LeafNodeIndex references a leaf node in a tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LeafNodeIndex(u32);

impl std::fmt::Display for LeafNodeIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self.0))
    }
}

impl LeafNodeIndex {
    /// Create a new `LeafNodeIndex` from a `u32`.
    pub fn new(index: u32) -> Self {
        LeafNodeIndex(index)
    }

    /// Return the inner value as `u32`.
    pub fn u32(&self) -> u32 {
        self.0
    }

    /// Return the inner value as `usize`.
    pub fn usize(&self) -> usize {
        self.u32() as usize
    }

    /// Return the index as a TreeNodeIndex value.
    fn to_tree_index(self) -> u32 {
        self.0 * 2
    }

    /// Warning: Only use when the node index represents a leaf node
    fn from_tree_index(node_index: u32) -> Self {
        debug_assert!(node_index % 2 == 0);
        LeafNodeIndex(node_index / 2)
    }
}

/// ParentNodeIndex references a parent node in a tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ParentNodeIndex(u32);

impl ParentNodeIndex {
    pub(crate) fn usize(&self) -> usize {
        self.0 as usize
    }

    /// Return the index as a TreeNodeIndex value.
    fn to_tree_index(self) -> u32 {
        self.0 * 2 + 1
    }

    /// Warning: Only use when the node index represents a parent node
    fn from_tree_index(node_index: u32) -> Self {
        debug_assert!(node_index > 0);
        debug_assert!(node_index % 2 == 1);
        ParentNodeIndex((node_index - 1) / 2)
    }
}

impl From<LeafNodeIndex> for TreeNodeIndex {
    fn from(leaf_index: LeafNodeIndex) -> Self {
        TreeNodeIndex::Leaf(leaf_index)
    }
}

impl From<ParentNodeIndex> for TreeNodeIndex {
    fn from(parent_index: ParentNodeIndex) -> Self {
        TreeNodeIndex::Parent(parent_index)
    }
}

/// TreeNodeIndex references a node in a tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeNodeIndex {
    Leaf(LeafNodeIndex),
    Parent(ParentNodeIndex),
}

impl TreeNodeIndex {
    /// Create a new `TreeNodeIndex` from a `u32`.
    fn new(index: u32) -> Self {
        if index % 2 == 0 {
            TreeNodeIndex::Leaf(LeafNodeIndex::from_tree_index(index))
        } else {
            TreeNodeIndex::Parent(ParentNodeIndex::from_tree_index(index))
        }
    }

    /// Return the inner value as `u32`.
    pub(crate) fn u32(&self) -> u32 {
        match self {
            TreeNodeIndex::Leaf(index) => index.to_tree_index(),
            TreeNodeIndex::Parent(index) => index.to_tree_index(),
        }
    }
}

impl Ord for TreeNodeIndex {
    fn cmp(&self, other: &TreeNodeIndex) -> Ordering {
        self.u32().cmp(&other.u32())
    }
}

impl PartialOrd for TreeNodeIndex {
    fn partial_cmp(&self, other: &TreeNodeIndex) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct TreeSize(u32);

impl TreeSize {
    /// Create a new `TreeSize` from `nodes`, which will be rounded up to the
    /// next power of 2. The tree size then reflects the smallest tree that can
    /// contain the number of nodes.
    pub(crate) fn new(nodes: u32) -> Self {
        let k = log2(nodes);
        TreeSize((1 << (k + 1)) - 1)
    }

    /// Create a new `TreeSize` from a specific index. This is the smallest tree
    /// that can contain the index.
    pub(crate) fn new_with_index(index: LeafNodeIndex) -> Self {
        TreeSize::new(index.u32() * 2 + 1)
    }

    /// Creates a new `TreeSize` from a specific leaf count
    pub(crate) fn from_leaf_count(leaf_count: usize) -> Self {
        TreeSize::new((leaf_count * 2 - 1) as u32)
    }

    /// Return the number of leaf nodes in the tree.
    pub(crate) fn leaf_count(&self) -> u32 {
        (self.0 / 2) + 1
    }

    /// Return the number of parent nodes in the tree.
    pub(crate) fn parent_count(&self) -> u32 {
        self.0 / 2
    }

    /// Return the inner value as `u32`.
    pub(crate) fn u32(&self) -> u32 {
        self.0
    }
}

fn log2(x: u32) -> usize {
    if x == 0 {
        return 0;
    }
    let mut k = 0;
    while (x >> k) > 0 {
        k += 1
    }
    k - 1
}

pub fn level(index: u32) -> usize {
    let x = index;
    if (x & 0x01) == 0 {
        return 0;
    }
    let mut k = 0;
    while ((x >> k) & 0x01) == 1 {
        k += 1;
    }
    k
}

pub(crate) fn root(size: TreeSize) -> TreeNodeIndex {
    let size = size.u32();
    debug_assert!(size > 0);
    TreeNodeIndex::new((1 << log2(size)) - 1)
}

pub(crate) fn left(index: ParentNodeIndex) -> TreeNodeIndex {
    let x = index.to_tree_index();
    let k = level(x);
    debug_assert!(k > 0);
    let index = x ^ (0x01 << (k - 1));
    TreeNodeIndex::new(index)
}

pub(crate) fn right(index: ParentNodeIndex) -> TreeNodeIndex {
    let x = index.to_tree_index();
    let k = level(x);
    debug_assert!(k > 0);
    let index = x ^ (0x03 << (k - 1));
    TreeNodeIndex::new(index)
}

pub(crate) fn parent(x: TreeNodeIndex) -> ParentNodeIndex {
    let x = x.u32();
    let k = level(x);
    let b = (x >> (k + 1)) & 0x01;
    let index = (x | (1 << k)) ^ (b << (k + 1));
    ParentNodeIndex::from_tree_index(index)
}

/// Direct path from a node to the root.
/// Does not include the node itself.
pub(crate) fn direct_path(node_index: LeafNodeIndex, size: TreeSize) -> Vec<ParentNodeIndex> {
    let r = root(size).u32();

    let mut d = vec![];
    let mut x = node_index.to_tree_index();
    while x != r {
        let parent = parent(TreeNodeIndex::new(x));
        d.push(parent);
        x = parent.to_tree_index();
    }
    d
}

#[test]
fn tree_size() {
    assert_eq!(TreeSize::new(1).u32(), 1);
    assert_eq!(TreeSize::new(3).u32(), 3);
    assert_eq!(TreeSize::new(5).u32(), 7);
    assert_eq!(TreeSize::new(7).u32(), 7);
    assert_eq!(TreeSize::new(9).u32(), 15);
    assert_eq!(TreeSize::new(11).u32(), 15);
    assert_eq!(TreeSize::new(13).u32(), 15);
    assert_eq!(TreeSize::new(15).u32(), 15);
    assert_eq!(TreeSize::new(17).u32(), 31);

    assert_eq!(TreeSize::new(1).leaf_count(), 1);
    assert_eq!(TreeSize::new(3).leaf_count(), 2);
    assert_eq!(TreeSize::new(5).leaf_count(), 4);
    assert_eq!(TreeSize::new(7).leaf_count(), 4);
    assert_eq!(TreeSize::new(9).leaf_count(), 8);
    assert_eq!(TreeSize::new(11).leaf_count(), 8);
    assert_eq!(TreeSize::new(13).leaf_count(), 8);
    assert_eq!(TreeSize::new(15).leaf_count(), 8);
    assert_eq!(TreeSize::new(17).leaf_count(), 16);

    assert_eq!(TreeSize::new(1).parent_count(), 0);
    assert_eq!(TreeSize::new(3).parent_count(), 1);
    assert_eq!(TreeSize::new(5).parent_count(), 3);
    assert_eq!(TreeSize::new(7).parent_count(), 3);
    assert_eq!(TreeSize::new(9).parent_count(), 7);
    assert_eq!(TreeSize::new(11).parent_count(), 7);
    assert_eq!(TreeSize::new(13).parent_count(), 7);
    assert_eq!(TreeSize::new(15).parent_count(), 7);
    assert_eq!(TreeSize::new(17).parent_count(), 15);

    assert_eq!(TreeSize::from_leaf_count(1).u32(), 1);
    assert_eq!(TreeSize::from_leaf_count(2).u32(), 3);
    assert_eq!(TreeSize::from_leaf_count(4).u32(), 7);
    assert_eq!(TreeSize::from_leaf_count(8).u32(), 15);
}
