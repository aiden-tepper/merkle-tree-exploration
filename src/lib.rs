pub mod merkle_tree {

    use crypto::digest::Digest;
    use crypto::sha2::Sha256;
    use rand::Rng;
    use std::result::Result;
    use std::vec::Vec;

    // hash function to be used for the construction of the merkle tree
    pub fn hash_leaf(leaf: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.input_str(leaf);
        hasher.result_str()
    }

    // hash function to be used for the construction of the merkle tree
    pub fn hash_node(left: &str, right: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.input_str(left);
        hasher.input_str(right);
        hasher.result_str()
    }

    pub enum Node {
        Empty,
        Leaf {
            hash: String,
            data: String,
        },
        Branch {
            hash: String,
            left: Box<Node>,
            right: Box<Node>,
        },
    }

    pub struct MerkleTree {
        root: Node,
    }

    pub struct MerkleProof {
        pub element: String,       // element for which we want to prove inclusion
        pub siblings: Vec<String>, // path of siblings from the element up to the root
        pub directions: Vec<bool>, // signal if the sibling at the same index is on the left or right
    }

    pub fn get_root(mt: &MerkleTree) -> String {
        match &mt.root {
            Node::Empty => String::new(),
            Node::Leaf { hash, .. } => hash.to_string(),
            Node::Branch { hash, .. } => hash.to_string(),
        }
    }

    // create a merkle tree from a list of elements
    // the tree should have the minimum height needed to contain all elements
    // empty slots should be filled with an empty string
    pub fn create_merkle_tree(elements: &Vec<String>) -> Result<MerkleTree, String> {
        if elements.is_empty() {
            return Ok(MerkleTree { root: Node::Empty });
        }

        let padded_elements = pad_elements(elements);

        let root = create_node(&padded_elements);
        Ok(MerkleTree { root })
    }

    // helper function to fill empty slots with empty strings
    fn pad_elements(elements: &Vec<String>) -> Vec<String> {
        let num_elements: u32 = elements.len().try_into().unwrap();
        let target_size = 1 << (32 - num_elements.leading_zeros());

        let diff = if num_elements > target_size {
            num_elements - target_size
        } else {
            target_size - num_elements
        };

        let mut padded_elements = elements.clone();

        for _ in 0..diff {
            padded_elements.push(String::new());
        }

        padded_elements
    }

    fn create_node(elements: &[String]) -> Node {
        if elements.len() == 1 {
            println!(
                "creating node \"{}\" with hash: {}",
                elements[0].clone(),
                hash_leaf(&elements[0])
            );
            return Node::Leaf {
                hash: hash_leaf(&elements[0]),
                data: elements[0].clone(),
            };
        }

        let mid = elements.len() / 2;
        let left = create_node(&elements[0..mid]);
        let right = create_node(&elements[mid..]);

        let hash = hash_node(
            match &left {
                Node::Leaf { hash, .. } | Node::Branch { hash, .. } => hash,
                Node::Empty => "",
            },
            match &right {
                Node::Leaf { hash, .. } | Node::Branch { hash, .. } => hash,
                Node::Empty => "",
            },
        );
        println!("creating branch with hash: {}\n", hash);

        Node::Branch {
            hash: hash_node(
                match &left {
                    Node::Leaf { hash, .. } | Node::Branch { hash, .. } => hash,
                    Node::Empty => "",
                },
                match &right {
                    Node::Leaf { hash, .. } | Node::Branch { hash, .. } => hash,
                    Node::Empty => "",
                },
            ),
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    // return a merkle proof of the inclusion of element at the given index
    //
    // example:
    // proof for index 2 (marked with E), return the nodes marked `*` at each layer.
    //
    // tree:
    // d0:                                   [ R ]
    // d1:                [*]                                     [*]
    // d2:      [*]                 [*]                 [ ]                 [ ]
    // d3: [ ]       [ ]       [E]       [*]       [ ]       [ ]       [ ]       [ ]
    //
    // proof:
    // element    = E
    // siblings   = [d3-3, d2-0, d1-1]
    // directions = [false, true, false]
    pub fn get_proof(t: &MerkleTree, index: usize) -> Result<MerkleProof, String> {
        let root = &t.root;
        let elements = collect_elements(root);
        let num_elements = elements.len();

        if index >= num_elements {
            return Err(String::from("Index out of bounds"));
        }

        let element = elements[index].clone();
        let mut siblings = Vec::new();
        let mut directions = Vec::new();

        let mut current_node = root;
        let h = (num_elements as f32).log2() as usize;

        let b_str = format!("{:0h$b}", index, h = h);
        let b_vec: Vec<_> = b_str.chars().map(|c| c.to_digit(2).unwrap()).collect();

        for b in &b_vec {
            if let Node::Branch { left, right, .. } = current_node {
                let (sibling_node, next_node, direction) = if *b == 0 {
                    (right, left, true)
                } else {
                    (left, right, false)
                };

                match &**sibling_node {
                    Node::Branch { hash, .. } => {
                        siblings.push(hash.clone());
                        directions.push(direction);
                    }
                    Node::Leaf { hash, .. } => {
                        siblings.push(hash.clone());
                        directions.push(direction);
                    }
                    Node::Empty => return Err(String::from("Invalid sibling node type")),
                }

                current_node = next_node;
            }
        }

        siblings.reverse();
        directions.reverse();

        Ok(MerkleProof {
            element,
            siblings,
            directions,
        })
    }

    // Helper function to collect leaf nodes' elements in-order
    fn collect_elements(node: &Node) -> Vec<String> {
        match node {
            Node::Leaf { data, .. } => vec![data.clone()],
            Node::Branch { left, right, .. } => {
                let mut elements = collect_elements(left);
                elements.extend(collect_elements(right));
                elements
            }
            Node::Empty => Vec::new(),
        }
    }

    // verify a merkle tree against a known root
    pub fn verify_proof(root: String, proof: &MerkleProof) -> bool {
        let mut current_hash = hash_leaf(&proof.element);

        for (sibling_hash, direction) in proof.siblings.iter().zip(proof.directions.iter()) {
            if *direction {
                current_hash = hash_node(&current_hash, sibling_hash);
            } else {
                current_hash = hash_node(sibling_hash, &current_hash);
            }
            // println!("current_hash: {}", current_hash);
        }

        current_hash == root
    }

    pub fn generate_random_string(length: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut rng = rand::thread_rng();
        (0..length)
            .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
            .collect()
    }

    // ** BONUS (optional - easy) **
    // Updates the Merkle tree (from leaf to root) to include the new element at index.
    // For simplicity, the index must be within the bounds of the original vector size.
    // If it is not, return an error.
    pub fn update_element(
        t: &MerkleTree,
        index: usize,
        element: &str,
    ) -> Result<MerkleTree, String> {
        // let mut path = Vec::new();
        // let height = (collect_elements(&t.root).len() as f32).log2() as usize;

        let mut current_node = &t.root;
        let mut updated_node_list = Vec::new();

        let proof = get_proof(t, index);
        match proof {
            Ok(p, ..) => {
                for direction in &p.directions {
                    if let Node::Branch { left, right, .. } = current_node {
                        current_node = if *direction { right } else { left };
                        updated_node_list.push(current_node);
                    }
                }
                updated_node_list.reverse();

                // Update the leaf node and recompute the hashes along the path
                let mut new_hash = hash_leaf(element).clone();
                let mut new_node = Node::Leaf {
                    hash: new_hash.clone(),
                    data: element.to_string().clone(),
                };

                for i in 0..updated_node_list.len() {
                    if p.directions[i] {
                        *updated_node_list[i + 1] = Node::Branch {
                            hash: hash_node(&new_hash.clone(), &p.siblings[i]),
                            left: Box::new(new_node),
                            right: Box::new(*updated_node_list[i]),
                        };
                    } else {
                        new_hash = hash_node(&p.siblings[i], &new_hash);
                    }
                    // println!("current_hash: {}", current_hash);
                }

                Ok(MerkleTree { root: new_node })
            }
            Err(e) => Err(e),
        }
    }

    // ** BONUS (optional - hard) **
    // Generates a Merkle proof of the inclusion of contiguous elements,
    // starting at startIndex (inclusive) and ending at endIndex (exclusive).
    // If the indexes are out of bounds or startIndex >= endIndex, an error is returned.
    //
    // Note: modify the method signature to return your proof type.
    // Implement a separate verify_aggregate_proof for this type.
    //
    // The aggregated proof size should generally be smaller than
    // that of the naive approach (calling GetProof for every index).
    // pub fn get_aggregate_proof(t: &MerkleTree, start_index: usize, end_index: usize) -> () {
    //     // TODO
    // }
}

#[cfg(test)]
mod tests {
    use crate::merkle_tree::*;

    #[test]
    fn test_root() {
        let elements = vec![
            "some".to_string(),
            "test".to_string(),
            "elements".to_string(),
        ];

        let expected_root = hash_node(
            &hash_node(&hash_leaf("some"), &hash_leaf("test")),
            &hash_node(&hash_leaf("elements"), &hash_leaf("")),
        );

        let mt = create_merkle_tree(&elements);

        match mt {
            Ok(mt) => assert_eq!(get_root(&mt), expected_root),
            Err(e) => println!("{}", e),
        }
    }

    #[test]
    fn test_proof() {
        let elements = vec![
            "some".to_string(),
            "test".to_string(),
            "elements".to_string(),
        ];
        let mt = create_merkle_tree(&elements);

        match mt {
            Ok(mt) => {
                for i in 0..elements.len() {
                    let proof = get_proof(&mt, i);

                    match proof {
                        Ok(p) => {
                            // println!("\n-------- {}", p.element);
                            // println!("-------- {:?}", p.siblings);
                            // println!("-------- {:?}\n", p.directions);
                            assert!(verify_proof(get_root(&mt), &p))
                        }
                        Err(e) => println!("{}", e),
                    }
                }
            }
            Err(e) => println!("{}", e),
        }
    }

    #[test]
    fn test_empty() {
        let mut elements = Vec::new();
        let mt = create_merkle_tree(&elements);

        let expected_root = String::new();

        match mt {
            Ok(mt) => assert_eq!(get_root(&mt), expected_root),
            Err(e) => println!("{}", e),
        }
    }

    #[test]
    fn test_big_tree() {
        let elements: Vec<String> = (0..1000).map(|_| generate_random_string(10)).collect();
        let mt = create_merkle_tree(&elements);

        match mt {
            Ok(mt) => {
                for i in 0..elements.len() {
                    let proof = get_proof(&mt, i);

                    match proof {
                        Ok(p) => {
                            // println!("\n-------- {}", p.element);
                            // println!("-------- {:?}", p.siblings);
                            // println!("-------- {:?}\n", p.directions);
                            assert!(verify_proof(get_root(&mt), &p))
                        }
                        Err(e) => println!("{}", e),
                    }
                }
            }
            Err(e) => println!("{}", e),
        }
    }

    #[test]
    fn test_update_element() {
        let elements = vec![
            "some".to_string(),
            "test".to_string(),
            "elements".to_string(),
        ];

        let mt = create_merkle_tree(&elements);

        match mt {
            Ok(mt) => {
                update_element(&mt, 0, "updated");
            }
            Err(e) => println!("{}", e),
        }
    }
}
