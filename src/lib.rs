use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Block,
};
use hkdf::Hkdf;
use sha2::Sha256;
use treemath::{direct_path, left, right, root, LeafNodeIndex, TreeNodeIndex, TreeSize};

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

pub struct PublicTree {
    leaf_nodes: Vec<Option<LeafCiphertext>>,
    parent_nodes: Vec<Option<ParentCiphertext>>,
}

#[derive(Debug, PartialEq, Clone)]
enum Resolution {
    Empty,
    One(TreeNodeIndex),
    Both(TreeNodeIndex, TreeNodeIndex),
}

pub struct WrappingTree {
    init_secret: InitSecret,
    leaf_nodes: Vec<LeafNode>,
    parent_nodes: Vec<ParentNode>,
}

impl WrappingTree {
    // Create a new empty tree
    pub fn new(init_secret: InitSecret) -> WrappingTree {
        WrappingTree {
            init_secret,
            leaf_nodes: Vec::new(),
            parent_nodes: Vec::new(),
        }
    }

    // Create a new tree from a public tree and a root secret
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
        tree.expand_nodes(root, derive_node_key(&init_secret, root), &public_tree);

        tree
    }

    // Expand a node and its children by decrypting the nodes from the public
    // tree and storing them in the tree
    fn expand_nodes(&mut self, index: TreeNodeIndex, key: AesKey, public_tree: &PublicTree) {
        match index {
            TreeNodeIndex::Leaf(l) => {
                // If the leaf node is present in the public tree, we decrypt it
                // and store it in the tree
                if let Some(ciphertext) = public_tree.leaf_nodes[l.usize()] {
                    self.leaf_nodes[l.usize()] = self.decrypt_leaf_node(ciphertext, &key);
                }
            }
            TreeNodeIndex::Parent(p) => {
                // If the parent node is present in the public tree, we decrypt it
                // and store it in the tree. We also extract the keys for the children.
                let (left_key, right_key) =
                    if let Some(ciphertext) = public_tree.parent_nodes[p.usize()] {
                        let node = self.expand_parent_node(ciphertext, &key);
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
    fn expand_parent_node(&self, ciphertext: ParentCiphertext, key: &AesKey) -> ParentNode {
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

    // Create a new epoch
    pub fn new_epoch(&mut self, init_secret: InitSecret) {
        self.init_secret = init_secret;
    }

    // Add a new node to the tree
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
        self.leaf_nodes[index.usize()] = wrap_leaf(&leaf_key, leaf_node_plaintext);

        // Wrap the parent nodes up to the root
        if self.leaf_nodes.len() > 1 {
            self.wrap_up(index)
        };
    }

    // Remove a node from the tree
    pub fn remove(&mut self, index: LeafNodeIndex) {
        if index.usize() >= self.leaf_nodes.len() {
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
            right_most_leaf_index
        } else {
            self.leaf_nodes.clear();
            self.parent_nodes.clear();
            return;
        };

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

        // Wrap the parent nodes up to the root
        if self.leaf_nodes.len() > 1 {
            self.wrap_up(index)
        };
    }

    /// Wrap up from a given index, which has either been set or blanked.
    /// This function will rewrap the parent nodes up to the root and skip
    /// the nodes that only have one child.
    fn wrap_up(&mut self, index: LeafNodeIndex) {
        let tree_size = TreeSize::from_leaf_count(self.leaf_nodes.len());

        let mut last_index = TreeNodeIndex::Leaf(LeafNodeIndex::new(0));

        // We check the resolution of the nodes in the direct path and either
        // skip or rewrap them
        for node_index in direct_path(index, tree_size) {
            match self.resolution(node_index.into()) {
                Resolution::Empty => {
                    // The node is blank, nothing to do
                    continue;
                }
                Resolution::One(_) => {
                    // The node has only one child, we need to skip it
                    // and we blank it
                    self.parent_nodes[node_index.usize()] = ParentNode { content: None };
                    continue;
                }
                Resolution::Both(left, right) => {
                    // The node has two children, we need to rewrap it. We only
                    // want to derive a key for the node in the direct path and
                    // keep the key for the other one.

                    let left_key;
                    let right_key;

                    if last_index.u32() < TreeNodeIndex::from(node_index).u32() {
                        // We came from the left, hence we keep the right key
                        left_key = derive_node_key(&self.init_secret, left);
                        right_key = self
                            .parent_nodes
                            .get(node_index.usize())
                            .and_then(|n| n.content.as_ref())
                            .map(|c| c.plaintext.right_key)
                            .unwrap_or_else(|| derive_node_key(&self.init_secret, right));
                    } else {
                        // We came from the right, hence we keep the left key
                        left_key = self
                            .parent_nodes
                            .get(node_index.usize())
                            .and_then(|n| n.content.as_ref())
                            .map(|c| c.plaintext.left_key)
                            .unwrap_or_else(|| derive_node_key(&self.init_secret, left));
                        right_key = derive_node_key(&self.init_secret, right);
                    }

                    let parent_node_plaintext = ParentNodePlaintext {
                        left_key,
                        right_key,
                    };
                    let key = derive_node_key(&self.init_secret, node_index.into());
                    let new_node = wrap_parent(&key, parent_node_plaintext);
                    self.parent_nodes[node_index.usize()] = new_node;
                }
            }
            last_index = node_index.into();
        }
    }

    // Calculates the resolution of a node
    fn resolution(&self, index: TreeNodeIndex) -> Resolution {
        return match index {
            TreeNodeIndex::Leaf(l) => {
                if self.leaf_nodes[l.usize()].content.is_some() {
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

    // Export the public tree, i.e. the tree without the plaintexts
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

    // Export the init secret
    pub fn export_root_secret(&self) -> &InitSecret {
        &self.init_secret
    }

    // Export the leaf node plaintexts along their index
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
    let b1 = Block::from_slice(&buffer[..16]).to_owned();
    let b2 = Block::from_slice(&buffer[16..32]).to_owned();
    let b3 = Block::from_slice(&buffer[32..48]).to_owned();
    let b4 = Block::from_slice(&buffer[48..64]).to_owned();

    let cipher = aes::Aes256::new(&GenericArray::from_slice(key));
    cipher.encrypt_blocks(&mut [b1, b2, b3, b4]);

    buffer
}

fn decrypt(key: &[u8], ciphertext: &[u8; 64]) -> [u8; 64] {
    let mut buffer = [0u8; 64];
    buffer.copy_from_slice(ciphertext);
    let b1 = Block::from_slice(&buffer[..16]).to_owned();
    let b2 = Block::from_slice(&buffer[16..32]).to_owned();
    let b3 = Block::from_slice(&buffer[32..48]).to_owned();
    let b4 = Block::from_slice(&buffer[48..64]).to_owned();

    let cipher = aes::Aes256::new(&GenericArray::from_slice(key));
    cipher.decrypt_blocks(&mut [b1, b2, b3, b4]);

    buffer
}

fn wrap_leaf(key: &[u8; 32], plaintext: LeafNodePlaintext) -> LeafNode {
    LeafNode {
        content: Some(LeafNodeContent {
            ciphertext: encrypt(key, &plaintext.serialize()),
            plaintext: plaintext,
        }),
    }
}

fn wrap_parent(key: &[u8; 32], plaintext: ParentNodePlaintext) -> ParentNode {
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
    const LEAF_COUNT: u32 = 100;
    const OPERATION_COUNT: usize = 1_000;

    let init_secret = [0u8; 32];
    let mut tree = WrappingTree::new(init_secret);
    let leaf_node_plaintext = LeafNodePlaintext {
        key: [0u8; 32],
        mac: [0u8; 32],
    };

    for _ in 0..OPERATION_COUNT {
        let index = LeafNodeIndex::new(rand::random::<u32>() % LEAF_COUNT);
        let add = rand::random::<bool>();

        if add {
            tree.add(index, leaf_node_plaintext.clone());
        } else {
            tree.remove(index);
        }

        let public_tree = tree.export_public_tree();
        let root_secret = tree.export_root_secret();

        let new_tree = WrappingTree::from_public_tree(public_tree, *root_secret);

        let leaf_node_plaintexts = tree.export_leaf_node_plaintexts();
        let new_leaf_node_plaintexts = new_tree.export_leaf_node_plaintexts();

        assert_eq!(leaf_node_plaintexts.len(), new_leaf_node_plaintexts.len());
        assert_eq!(leaf_node_plaintexts, new_leaf_node_plaintexts);
    }
}
