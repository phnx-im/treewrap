// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;
use treemath::{
    direct_path, left, right, root, LeafNodeIndex, ParentNodeIndex, TreeNodeIndex, TreeSize,
};

use crate::treemath::parent;

mod treemath;

pub type AesKey = [u8; 32];
pub type ParentCiphertext = [u8; 64];
pub type LeafCiphertext = [u8; 64];
pub type Mac = [u8; 32];
pub type InitSecret = [u8; 32];

#[derive(Debug, PartialEq, Clone, Default)]
pub struct LeafNode {
    content: Option<LeafNodeContent>,
}

#[derive(Debug, PartialEq, Clone, Default)]
pub struct ParentNode {
    content: Option<ParentNodeContent>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct LeafNodeContent {
    plaintext: LeafNodePlaintext,
    ciphertext: LeafCiphertext,
}

#[derive(Debug, PartialEq, Clone)]
pub struct ParentNodeContent {
    plaintext: ParentNodePlaintext,
    ciphertext: ParentCiphertext,
}

#[derive(Debug, PartialEq, Clone)]
pub struct LeafNodePlaintext {
    key: AesKey,
    mac: Mac,
}

impl LeafNodePlaintext {
    fn serialize(&self) -> [u8; 64] {
        let mut buffer = [0u8; 64];
        buffer[..32].copy_from_slice(&self.key);
        buffer[32..].copy_from_slice(&self.mac);
        buffer
    }

    fn deserialize(buffer: &[u8; 64]) -> Self {
        Self {
            key: buffer[..32].try_into().unwrap(),
            mac: buffer[32..].try_into().unwrap(),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct ParentNodePlaintext {
    left_key: AesKey,
    right_key: AesKey,
}

impl ParentNodePlaintext {
    fn serialize(&self) -> [u8; 64] {
        let mut buffer = [0u8; 64];
        buffer[..32].copy_from_slice(&self.left_key);
        buffer[32..].copy_from_slice(&self.right_key);
        buffer
    }

    fn deserialize(buffer: &[u8; 64]) -> Self {
        Self {
            left_key: buffer[..32].try_into().unwrap(),
            right_key: buffer[32..].try_into().unwrap(),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
enum Resolution {
    Empty,
    One(TreeNodeIndex),
    Both(TreeNodeIndex, TreeNodeIndex),
}

trait Resolver {
    fn has_node(&self, index: usize) -> bool;

    /// Calculates the resolution of a node
    fn resolution(&self, index: TreeNodeIndex) -> Resolution {
        return match index {
            TreeNodeIndex::Leaf(l) => {
                if self.has_node(l.usize()) {
                    return Resolution::One(TreeNodeIndex::from(l));
                } else {
                    return Resolution::Empty;
                }
            }
            TreeNodeIndex::Parent(p) => {
                let left = TreeNodeIndex::from(left(p));
                let right = TreeNodeIndex::from(right(p));
                match (self.resolution(left), self.resolution(right)) {
                    (Resolution::One(l), Resolution::One(r)) => Resolution::Both(l, r),
                    (Resolution::One(l), Resolution::Empty) => Resolution::One(l),
                    (Resolution::Empty, Resolution::One(r)) => Resolution::One(r),
                    (Resolution::Empty, Resolution::Empty) => Resolution::Empty,
                    (Resolution::Both(_, _), Resolution::Empty) => Resolution::One(left),
                    (Resolution::Empty, Resolution::Both(_, _)) => Resolution::One(right),
                    (Resolution::Both(_, _), Resolution::Both(_, _)) => {
                        Resolution::Both(left, right)
                    }
                    (Resolution::One(x), Resolution::Both(_, _)) => Resolution::Both(x, right),
                    (Resolution::Both(_, _), Resolution::One(x)) => Resolution::Both(left, x),
                }
            }
        };
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PublicTree {
    leaf_nodes: Vec<Option<LeafCiphertext>>,
    parent_nodes: Vec<Option<ParentCiphertext>>,
}

impl Resolver for PublicTree {
    fn has_node(&self, index: usize) -> bool {
        self.leaf_nodes[index].is_some()
    }
}

pub struct WrappingTree {
    init_secret: InitSecret,
    leaf_nodes: Vec<LeafNode>,
    parent_nodes: Vec<ParentNode>,
}

impl Resolver for WrappingTree {
    fn has_node(&self, index: usize) -> bool {
        self.leaf_nodes[index].content.is_some()
    }
}

impl WrappingTree {
    /// Create a new empty tree
    pub fn new(init_secret: InitSecret) -> WrappingTree {
        WrappingTree {
            init_secret,
            leaf_nodes: Vec::new(),
            parent_nodes: Vec::new(),
        }
    }

    /// Create a new tree from a public tree and a root secret
    pub fn from_public_tree(public_tree: PublicTree, init_secret: InitSecret) -> WrappingTree {
        // If the public tree is empty, we return a new empty tree
        if public_tree.leaf_nodes.is_empty() {
            return WrappingTree::new(init_secret);
        }

        // Prepare the new tree with the correct size and blank nodes
        let tree_size = TreeSize::from_leaf_count(public_tree.leaf_nodes.len());
        let mut tree = WrappingTree {
            init_secret,
            leaf_nodes: vec![LeafNode { content: None }; tree_size.leaf_count() as usize],
            parent_nodes: vec![ParentNode { content: None }; tree_size.parent_count() as usize],
        };
        let root = root(tree_size);

        // We populate the tree with the public nodes and decrypt them
        // starting from the root
        println!(
            "Expanding nodes with root key {:?}",
            derive_node_key(&init_secret, root)
        );
        match public_tree.resolution(root) {
            Resolution::Empty => {
                // The root node is blank, nothing to do
                println!("Root node's resolution is empty");
            }
            Resolution::One(child) => {
                // The root node has only one child, we start from there
                println!("Root node has only one child: {:?}", child);
                tree.expand_nodes(child, derive_node_key(&init_secret, child), &public_tree);
            }
            Resolution::Both(_, _) => {
                // The root node has two children, we stay at the root
                println!("Root node has two children");
                tree.expand_nodes(root, derive_node_key(&init_secret, root), &public_tree);
            }
        }

        tree
    }

    /// Expand a node and its children by decrypting the nodes from the public
    /// tree and storing them in the tree
    fn expand_nodes(&mut self, index: TreeNodeIndex, key: AesKey, public_tree: &PublicTree) {
        match index {
            TreeNodeIndex::Leaf(l) => {
                // If the leaf node is present in the public tree, we decrypt it
                // and store it in the tree
                if let Some(ciphertext) = public_tree.leaf_nodes[l.usize()] {
                    println!("Decrypting leaf node {} with key {:?}", l.usize(), key);
                    self.leaf_nodes[l.usize()] = self.decrypt_leaf_node(ciphertext, &key);
                    debug_assert_eq!(
                        self.leaf_nodes[l.usize()]
                            .clone()
                            .content
                            .unwrap()
                            .plaintext
                            .key[..32],
                        [1u8; 32]
                    );
                }
            }
            TreeNodeIndex::Parent(p) => {
                // If the parent node is present in the public tree, we decrypt it
                // and store it in the tree. We also extract the keys for the children.
                let (left_key, right_key) =
                    if let Some(ciphertext) = public_tree.parent_nodes[p.usize()] {
                        println!("Decrypting parent node {} with key {:?}", p.usize(), key);
                        let node = self.decrypt_parent_node(ciphertext, &key);
                        let left_key = node.content.as_ref().map(|c| c.plaintext.left_key).unwrap();
                        let right_key = node
                            .content
                            .as_ref()
                            .map(|c| c.plaintext.right_key)
                            .unwrap();
                        self.parent_nodes[p.usize()] = node;
                        (left_key, right_key)
                    } else {
                        // If it is blank, we just return the current key
                        (key, key)
                    };
                // We continue to navigate down the tree until we reach the
                // leaves
                let left_child = left(p);
                let right_child = right(p);
                self.expand_nodes(left_child, left_key, public_tree);
                self.expand_nodes(right_child, right_key, public_tree);
            }
        }
    }

    /// Decrypt a parent node from the public tree
    fn decrypt_parent_node(&self, ciphertext: ParentCiphertext, key: &AesKey) -> ParentNode {
        let plaintext = decrypt(key, &ciphertext);
        ParentNode {
            content: Some(ParentNodeContent {
                ciphertext,
                plaintext: ParentNodePlaintext::deserialize(&plaintext),
            }),
        }
    }

    /// Decrypt a leaf node from the public tree
    fn decrypt_leaf_node(&self, ciphertext: LeafCiphertext, key: &AesKey) -> LeafNode {
        let plaintext = decrypt(key, &ciphertext);
        LeafNode {
            content: Some(LeafNodeContent {
                ciphertext,
                plaintext: LeafNodePlaintext::deserialize(&plaintext),
            }),
        }
    }

    #[inline(always)]
    fn size(&self) -> TreeSize {
        TreeSize::from_leaf_count(self.leaf_nodes.len())
    }

    /// Create a new epoch
    pub fn new_epoch(&mut self, init_secret: InitSecret) {
        self.init_secret = init_secret;

        // Re-encrypt the root node
        match root(self.size()) {
            TreeNodeIndex::Leaf(l) => self.rewrap_leaf(l),
            TreeNodeIndex::Parent(p) => self.rewrap_parent(p),
        }
    }

    /// Add a new node to the tree
    pub fn add(&mut self, index: LeafNodeIndex, leaf_node_plaintext: LeafNodePlaintext) {
        // Extend the nodes vector if necessary
        if index.usize() >= self.leaf_nodes.len() {
            let desired_tree_size = TreeSize::new_with_index(index);
            self.leaf_nodes.resize(
                desired_tree_size.leaf_count() as usize,
                LeafNode { content: None },
            );
            self.parent_nodes.resize(
                desired_tree_size.parent_count() as usize,
                ParentNode { content: None },
            );
        }

        // Wrap the leaf node
        let leaf_key = derive_node_key(&self.init_secret, TreeNodeIndex::Leaf(index));
        println!(
            "Encrypting leaf node {} with key {:?}",
            index.usize(),
            leaf_key
        );
        self.leaf_nodes[index.usize()] = encrypt_leaf_node(&leaf_key, leaf_node_plaintext);

        // Wrap the parent nodes up to the root
        if self.leaf_nodes.len() > 1 {
            self.wrap_up(index)
        };
    }

    /// Remove a node from the tree
    pub fn remove(&mut self, index: LeafNodeIndex) {
        println!(
            "Removing node {:?}, leaf node length: {}",
            index,
            self.leaf_nodes.len()
        );
        if self.leaf_nodes.len() == 0 {
            println!("Tree is empty, nothing to remove");
            // The tree is empty, nothing to do
            return;
        }

        if index.usize() >= self.leaf_nodes.len() {
            // The node is outside the current tree, nothing to do
            return;
        }

        if self.leaf_nodes[index.usize()].content.is_none() {
            // The node is already blank, nothing to do
            return;
        }

        // We first blank the leaf node
        self.leaf_nodes[index.usize()] = LeafNode { content: None };

        // We shrink the tree if necessary
        let mut right_most_leaf_index = None;
        for i in (0..self.leaf_nodes.len()).rev() {
            if self.leaf_nodes[i].content.is_some() {
                right_most_leaf_index = Some(LeafNodeIndex::new(i as u32));
                break;
            }
        }

        let right_most_leaf_index = if let Some(right_most_leaf_index) = right_most_leaf_index {
            println!("Right most leaf index: {:?}", right_most_leaf_index);
            right_most_leaf_index
        } else {
            println!("Tree is empty, clearing it");
            // The tree is empty, we can clear it
            self.leaf_nodes.clear();
            self.parent_nodes.clear();
            return;
        };

        // Wrap the parent nodes up to the root
        if self.leaf_nodes.len() > 1 {
            println!("Wrapping up from node {:?}", index);
            self.wrap_up(index)
        } else {
            // If the tree only has one node, we rewrap it since it's the root
            println!("Rewrapping root/leaf node after removal");
            self.rewrap_leaf(LeafNodeIndex::new(0));
        }

        let tree_size = TreeSize::from_leaf_count(self.leaf_nodes.len());
        let desired_tree_size = TreeSize::new_with_index(right_most_leaf_index);

        if desired_tree_size.leaf_count() < tree_size.leaf_count() {
            self.leaf_nodes.resize(
                desired_tree_size.leaf_count() as usize,
                LeafNode { content: None },
            );
            self.parent_nodes.resize(
                desired_tree_size.parent_count() as usize,
                ParentNode { content: None },
            );
        }
    }

    fn rewrap_leaf(&mut self, index: LeafNodeIndex) {
        if index.usize() >= self.leaf_nodes.len() {
            println!("Rewrap leaf: Index is outside the tree, nothing to do");
            // The index is outside the tree, nothing to do
            return;
        }

        let key = derive_node_key(&self.init_secret, TreeNodeIndex::Leaf(index));

        println!("Rewrapping leaf node {:?}", index);

        if let Some(ref leaf_node) = self.leaf_nodes[index.usize()].content {
            self.leaf_nodes[index.usize()] = encrypt_leaf_node(&key, leaf_node.plaintext.clone());
        }
    }

    fn rewrap_parent(&mut self, index: ParentNodeIndex) {
        println!("Rewrapping parent node {:?}", index);
        if index.usize() >= self.parent_nodes.len() {
            println!("Rewrap parent: Index is outside the tree, nothing to do");
            // The index is outside the tree, nothing to do
            return;
        }

        let res = self.resolution(TreeNodeIndex::Parent(index));

        match res {
            Resolution::Empty => {
                panic!("rewrap_parent: Resolution is empty");
            }
            Resolution::One(child) => {
                println!("Rewrapping partial parent node {:?}", child);

                match child {
                    TreeNodeIndex::Leaf(leaf_node_index) => {
                        self.rewrap_leaf(leaf_node_index);
                    }
                    TreeNodeIndex::Parent(parent_node_index) => {
                        self.rewrap_parent(parent_node_index);
                    }
                }
            }
            Resolution::Both(_, _) => {
                let key = derive_node_key(&self.init_secret, TreeNodeIndex::Parent(index));

                println!("Rewrapping full parent node {:?}", index);

                if let Some(ref parent_node) = self.parent_nodes[index.usize()].content {
                    self.parent_nodes[index.usize()] =
                        encrypt_parent_node(&key, parent_node.plaintext.clone());
                }
            }
        }
    }

    /// Wrap up from a given index, which has either been set or blanked.
    /// This function will rewrap the parent nodes up to the root and skip
    /// the nodes that only have one child.
    fn wrap_up(&mut self, index: LeafNodeIndex) {
        let root = root(self.size());

        if index.usize() >= self.leaf_nodes.len() {
            println!("Wrap up: Index is outside the tree, nothing to do");
            // The index is outside the tree, nothing to do
            return;
        }

        let mut last_index = TreeNodeIndex::Leaf(index);
        let mut last_key = derive_node_key(&self.init_secret, last_index);

        // We check the resolution of the nodes in the direct path and either
        // skip or rewrap them
        for node_index in direct_path(index, self.size()) {
            match self.resolution(node_index.into()) {
                Resolution::Empty => {
                    // The node is blank, nothing to do
                    continue;
                }
                Resolution::One(child) => {
                    println!("Wrap up: one with node {:?}", node_index);
                    // The node has only one child, we need to skip it
                    // and we blank it, unless it is the root node.
                    if TreeNodeIndex::from(node_index) != root {
                        // Extract the keys from the parent node
                        if let Some(node_content) =
                            self.parent_nodes[node_index.usize()].content.as_ref()
                        {
                            last_key = if child.u32() < TreeNodeIndex::from(node_index).u32() {
                                // The child was on the left, hence we keep the left key
                                println!("\tThe child was on the left");
                                node_content.plaintext.left_key
                            } else {
                                // The child was on the right, hence we keep the right key
                                println!("\tThe child was on the right");
                                node_content.plaintext.right_key
                            };
                            println!("\tExtracting key from parent node {:?}", last_key);
                        }

                        println!("\tBlanking node {:?}", node_index);
                        self.parent_nodes[node_index.usize()] = ParentNode { content: None };

                        continue;
                    } else {
                        println!("Wrapped up to root node, but there is only one child");
                        // Blank the root node
                        self.parent_nodes[node_index.usize()] = ParentNode { content: None };
                        // Rewrap child
                        println!("\tRewrapping child node {:?}", child);
                        match child {
                            TreeNodeIndex::Leaf(leaf_node_index) => {
                                self.rewrap_leaf(leaf_node_index);
                            }
                            TreeNodeIndex::Parent(parent_node_index) => {
                                self.rewrap_parent(parent_node_index);
                            }
                        }

                        break;
                    }
                }
                Resolution::Both(left_index, right_index) => {
                    // The node has two children, we need to rewrap it. We only
                    // want to derive a key for the node in the direct path and
                    // keep the key for the other one.

                    println!(
                        "Wrap up: both with node {:?}\n\tLeft: {:?}\n\tRight: {:?}",
                        node_index, left_index, right_index
                    );

                    let left_key;
                    let right_key;

                    if last_index.u32() < TreeNodeIndex::from(node_index).u32() {
                        // We came from the left, hence we keep the right key
                        println!("We came from the left");
                        left_key = last_key;
                        right_key = self
                            .parent_nodes
                            .get(node_index.usize())
                            .and_then(|n| n.content.as_ref())
                            .map(|c| c.plaintext.right_key)
                            .unwrap_or_else(|| self.next_or_derive(right_index));
                    // find next key instead
                    } else {
                        // We came from the right, hence we keep the left key
                        println!("We came from the right");
                        left_key = self
                            .parent_nodes
                            .get(node_index.usize())
                            .and_then(|n| n.content.as_ref())
                            .map(|c| c.plaintext.left_key)
                            .unwrap_or_else(|| self.next_or_derive(left_index));
                        right_key = last_key;
                    }

                    println!(
                        "Parent node {:?}: \n\tLeft key: {:?}, \n\tRight key: {:?}",
                        node_index, left_key, right_key
                    );

                    let parent_node_plaintext = ParentNodePlaintext {
                        left_key,
                        right_key,
                    };

                    // Encrypt the two keys and store the new parent node
                    last_key = derive_node_key(&self.init_secret, node_index.into());
                    println!(
                        "Encrypting parent node {} with key {:?}",
                        node_index.usize(),
                        last_key
                    );
                    let new_node = encrypt_parent_node(&last_key, parent_node_plaintext);
                    self.parent_nodes[node_index.usize()] = new_node;
                }
            }
            last_index = node_index.into();
        }
    }

    /// Export the public tree, i.e. the tree without the plaintexts
    pub fn export_public_tree(&self) -> PublicTree {
        PublicTree {
            leaf_nodes: self
                .leaf_nodes
                .iter()
                .map(|n| n.content.as_ref().map(|c| c.ciphertext.clone()))
                .collect(),
            parent_nodes: self
                .parent_nodes
                .iter()
                .map(|n| n.content.as_ref().map(|c| c.ciphertext.clone()))
                .collect(),
        }
    }

    /// Looks for the key in the next non-blank node in the direct path, if it
    /// is not found we assume it must be the root node and we derive the key
    fn next_or_derive(&self, index: TreeNodeIndex) -> AesKey {
        let root = root(TreeSize::from_leaf_count(self.leaf_nodes.len()));
        let mut path_index = index;

        println!("next_or_derive: {:?}", index);

        while path_index != root {
            let parent = parent(path_index);
            println!("Looking for key in node {:?}", parent);
            if let Some(content) = &self.parent_nodes[parent.usize()].content {
                if path_index > TreeNodeIndex::Parent(parent) {
                    println!("Found right key");
                    return content.plaintext.right_key;
                } else {
                    println!("Found left key");
                    return content.plaintext.left_key;
                }
            }
            path_index = TreeNodeIndex::Parent(parent);
        }
        println!(
            "Deriving key for index {:?}: {:?}",
            index,
            derive_node_key(&self.init_secret, index)
        );
        derive_node_key(&self.init_secret, index)
    }

    /// Export the init secret
    pub fn export_root_secret(&self) -> &InitSecret {
        &self.init_secret
    }

    /// Export the leaf node plaintexts along their index
    pub fn export_leaf_node_plaintexts(&self) -> Vec<(usize, LeafNodePlaintext)> {
        self.leaf_nodes
            .iter()
            .enumerate()
            .filter_map(|(i, n)| n.content.as_ref().map(|c| (i, c.plaintext.clone())))
            .collect()
    }
}

fn derive_node_key(init_secret: &InitSecret, index: TreeNodeIndex) -> AesKey {
    let mut key = [0u8; 32];
    let hk = Hkdf::<Sha256>::from_prk(init_secret).unwrap();
    hk.expand(&index.u32().to_be_bytes(), &mut key).unwrap();
    key
}

fn encrypt(key: &AesKey, plaintext: &[u8; 64]) -> [u8; 64] {
    let mut buffer = [0u8; 64];
    buffer.copy_from_slice(plaintext);

    let mut b1 = GenericArray::from_slice(buffer[..16].as_ref()).to_owned();
    let mut b2 = GenericArray::from_slice(buffer[16..32].as_ref()).to_owned();
    let mut b3 = GenericArray::from_slice(buffer[32..48].as_ref()).to_owned();
    let mut b4 = GenericArray::from_slice(buffer[48..64].as_ref()).to_owned();

    let cipher = aes::Aes256::new(&GenericArray::from(*key));

    cipher.encrypt_block(&mut b1);
    cipher.encrypt_block(&mut b2);
    cipher.encrypt_block(&mut b3);
    cipher.encrypt_block(&mut b4);

    // Copy blocks into buffer
    let mut buffer = [0u8; 64];
    buffer[..16].copy_from_slice(b1.as_slice());
    buffer[16..32].copy_from_slice(b2.as_slice());
    buffer[32..48].copy_from_slice(b3.as_slice());
    buffer[48..64].copy_from_slice(b4.as_slice());

    buffer
}

fn decrypt(key: &AesKey, ciphertext: &[u8; 64]) -> [u8; 64] {
    let mut buffer = [0u8; 64];
    buffer.copy_from_slice(ciphertext);

    let mut b1 = GenericArray::from_slice(buffer[..16].as_ref()).to_owned();
    let mut b2 = GenericArray::from_slice(buffer[16..32].as_ref()).to_owned();
    let mut b3 = GenericArray::from_slice(buffer[32..48].as_ref()).to_owned();
    let mut b4 = GenericArray::from_slice(buffer[48..64].as_ref()).to_owned();

    let cipher = aes::Aes256::new(&GenericArray::from(*key));

    cipher.decrypt_block(&mut b1);
    cipher.decrypt_block(&mut b2);
    cipher.decrypt_block(&mut b3);
    cipher.decrypt_block(&mut b4);

    // Copy blocks into buffer
    let mut buffer = [0u8; 64];
    buffer[..16].copy_from_slice(b1.as_slice());
    buffer[16..32].copy_from_slice(b2.as_slice());
    buffer[32..48].copy_from_slice(b3.as_slice());
    buffer[48..64].copy_from_slice(b4.as_slice());

    buffer
}

fn encrypt_leaf_node(key: &[u8; 32], plaintext: LeafNodePlaintext) -> LeafNode {
    LeafNode {
        content: Some(LeafNodeContent {
            ciphertext: encrypt(key, &plaintext.serialize()),
            plaintext: plaintext,
        }),
    }
}

fn encrypt_parent_node(key: &[u8; 32], plaintext: ParentNodePlaintext) -> ParentNode {
    ParentNode {
        content: Some(ParentNodeContent {
            ciphertext: encrypt(key, &plaintext.serialize()),
            plaintext: plaintext,
        }),
    }
}

#[test]
fn encrypt_decrypt() {
    let key = [1u8; 32];
    let plaintext = [2u8; 64];
    let ciphertext = encrypt(&key, &plaintext);
    let decrypted = decrypt(&key, &ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn add_leaf() {
    let init_secret = [0u8; 32];
    let mut tree = WrappingTree::new(init_secret);
    let leaf_node_plaintext = LeafNodePlaintext {
        key: [0u8; 32],
        mac: [0u8; 32],
    };
    // Add 1st leaf
    tree.add(LeafNodeIndex::new(0), leaf_node_plaintext.clone());
    assert_eq!(tree.leaf_nodes.len(), 1);
    assert_eq!(tree.parent_nodes.len(), 0);
    assert_eq!(
        tree.leaf_nodes[0].content.as_ref().unwrap().plaintext,
        leaf_node_plaintext
    );
    // Add 2nd leaf
    tree.add(LeafNodeIndex::new(1), leaf_node_plaintext.clone());
    assert_eq!(tree.leaf_nodes.len(), 2);
    assert_eq!(tree.parent_nodes.len(), 1);
    assert_eq!(
        tree.leaf_nodes[1].content.as_ref().unwrap().plaintext,
        leaf_node_plaintext
    );
    // Add another 10 nodes
    for i in 2..12 {
        tree.add(LeafNodeIndex::new(i), leaf_node_plaintext.clone());
    }
    assert_eq!(tree.leaf_nodes.len(), 16);
    assert_eq!(tree.parent_nodes.len(), 15);
}

#[test]
fn remove_leaf() {
    let init_secret = [0u8; 32];
    let mut tree = WrappingTree::new(init_secret);
    let leaf_node_plaintext = LeafNodePlaintext {
        key: [0u8; 32],
        mac: [0u8; 32],
    };
    // Add 100 leaves
    for i in 0..100 {
        tree.add(LeafNodeIndex::new(i), leaf_node_plaintext.clone());
    }
    assert_eq!(tree.leaf_nodes.len(), 128);
    assert_eq!(tree.parent_nodes.len(), 127);
    // Remove 1st leaf
    tree.remove(LeafNodeIndex::new(0));
    // Remove 2nd leaf
    tree.remove(LeafNodeIndex::new(1));
    // Remove another 10 nodes
    for i in 2..100 {
        tree.remove(LeafNodeIndex::new(i));
    }
    assert_eq!(tree.leaf_nodes.len(), 0);
    assert_eq!(tree.parent_nodes.len(), 0);
}

#[test]
fn fuzz() {
    fn eval_tree(tree: &WrappingTree) {
        let public_tree = tree.export_public_tree();
        let root_secret = tree.export_root_secret();
        let new_tree = WrappingTree::from_public_tree(public_tree.clone(), *root_secret);
        let leaf_node_plaintexts = tree.export_leaf_node_plaintexts();
        let new_leaf_node_plaintexts = new_tree.export_leaf_node_plaintexts();
        assert_eq!(leaf_node_plaintexts, new_leaf_node_plaintexts);
    }

    const LEAF_COUNT: u32 = 32;
    const OPERATION_COUNT: usize = 100;
    const EPOCH_COUNT: usize = 10;

    let init_secret = [0u8; 32];
    let mut tree = WrappingTree::new(init_secret);
    let leaf_node_plaintext = LeafNodePlaintext {
        key: [1u8; 32],
        mac: [2u8; 32],
    };

    for epoch in 0..EPOCH_COUNT {
        println!("--- Epoch: {}", epoch);

        for operation in 0..OPERATION_COUNT {
            println!("-- Operation: {}", operation);
            let index = LeafNodeIndex::new(rand::random::<u32>() % LEAF_COUNT);
            let add = rand::random::<bool>();

            if add {
                println!("+ {:?}", index);
                tree.add(index, leaf_node_plaintext.clone());
            } else {
                println!("- {:?}", index);
                tree.remove(index);
            }

            eval_tree(&tree);
        }

        let new_init_secret = [rand::random::<u8>(); 32];
        tree.new_epoch(new_init_secret);

        eval_tree(&tree);
    }
}

#[test]
fn pathological_case2() {
    let init_secret = [3u8; 32];
    let mut tree = WrappingTree::new(init_secret);
    let leaf_node_plaintext = LeafNodePlaintext {
        key: [1u8; 32],
        mac: [2u8; 32],
    };

    tree.add(LeafNodeIndex::new(3), leaf_node_plaintext.clone());
    tree.add(LeafNodeIndex::new(1), leaf_node_plaintext.clone());
    tree.add(LeafNodeIndex::new(0), leaf_node_plaintext.clone());

    println!("First tree: {:?}", tree.export_public_tree().leaf_nodes);

    let public_tree = tree.export_public_tree();
    let root_secret = tree.export_root_secret();
    let new_tree = WrappingTree::from_public_tree(public_tree, *root_secret);
    let leaf_node_plaintexts = tree.export_leaf_node_plaintexts();
    let new_leaf_node_plaintexts = new_tree.export_leaf_node_plaintexts();
    assert_eq!(leaf_node_plaintexts, new_leaf_node_plaintexts);

    println!("Second epoch");
    let new_init_secret = [5u8; 32];
    tree.new_epoch(new_init_secret);

    println!("Exporting tree");

    let public_tree = tree.export_public_tree();
    let root_secret = tree.export_root_secret();
    let new_tree = WrappingTree::from_public_tree(public_tree, *root_secret);
    let leaf_node_plaintexts = tree.export_leaf_node_plaintexts();
    let new_leaf_node_plaintexts = new_tree.export_leaf_node_plaintexts();
    assert_eq!(leaf_node_plaintexts, new_leaf_node_plaintexts);

    println!("Second tree: {:?}", tree.export_public_tree().leaf_nodes);

    let remove_node = 0;

    println!("Removing node {}", remove_node);

    tree.remove(LeafNodeIndex::new(remove_node));

    println!("Node {} removed", remove_node);

    println!("Third tree: {:?}", tree.export_public_tree().leaf_nodes);

    let public_tree = tree.export_public_tree();
    let root_secret = tree.export_root_secret();
    let new_tree = WrappingTree::from_public_tree(public_tree, *root_secret);
    let leaf_node_plaintexts = tree.export_leaf_node_plaintexts();
    let new_leaf_node_plaintexts = new_tree.export_leaf_node_plaintexts();
    assert_eq!(leaf_node_plaintexts, new_leaf_node_plaintexts);

    let new_init_secret = [7u8; 32];
    tree.new_epoch(new_init_secret);

    let public_tree = tree.export_public_tree();
    let root_secret = tree.export_root_secret();
    let new_tree = WrappingTree::from_public_tree(public_tree, *root_secret);
    let leaf_node_plaintexts = tree.export_leaf_node_plaintexts();
    let new_leaf_node_plaintexts = new_tree.export_leaf_node_plaintexts();
    assert_eq!(leaf_node_plaintexts, new_leaf_node_plaintexts);
}

#[test]
fn root_test() {
    assert_eq!(root(TreeSize::new(1)).u32(), 0);
    assert_eq!(TreeSize::new(1).parent_count(), 0);
    assert_eq!(TreeSize::new(1).leaf_count(), 1);
    assert_eq!(TreeSize::new(0).parent_count(), 0);
    assert_eq!(TreeSize::new(0).leaf_count(), 0);
}
