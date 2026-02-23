import { CryptoUtils } from '../security/CryptoUtils';

/**
 * Sparse Merkle Tree for efficient revocation registry
 * Enables non-revocation proofs with O(log n) witness size
 */
export class SparseMerkleTree {
  private readonly TREE_DEPTH = 20; // Supports 2^20 = ~1M credentials
  private readonly EMPTY_LEAF = '0'.repeat(64);

  private nodes: Map<string, string> = new Map();
  private leaves: Map<string, string> = new Map();
  private root: string;

  constructor() {
    this.root = this.computeEmptyRoot();
  }

  /**
   * Insert or update a leaf in the tree
   */
  insert(index: bigint, value: string): void {
    if (index < 0n || index >= 2n ** BigInt(this.TREE_DEPTH)) {
      throw new Error('Index out of range');
    }

    // Store leaf
    this.leaves.set(index.toString(), value);

    // Update tree from leaf to root
    this.updatePath(index, value);
  }

  /**
   * Get value at index
   */
  get(index: bigint): string {
    return this.leaves.get(index.toString()) || this.EMPTY_LEAF;
  }

  /**
   * Generate Merkle proof for a leaf
   */
  generateProof(index: bigint): MerkleProof {
    const siblings: string[] = [];
    let currentIndex = index;

    for (let level = 0; level < this.TREE_DEPTH; level++) {
      const isRightNode = currentIndex % 2n === 1n;
      const siblingIndex = isRightNode ? currentIndex - 1n : currentIndex + 1n;

      const siblingHash = this.getNode(level, siblingIndex);
      siblings.push(siblingHash);

      currentIndex = currentIndex / 2n;
    }

    return {
      leaf: this.get(index),
      index: index.toString(),
      siblings,
      root: this.root
    };
  }

  /**
   * Verify a Merkle proof
   */
  verifyProof(proof: MerkleProof): boolean {
    let currentHash = proof.leaf;
    let index = BigInt(proof.index);

    for (let level = 0; level < this.TREE_DEPTH; level++) {
      const sibling = proof.siblings[level];
      const isRightNode = index % 2n === 1n;

      if (isRightNode) {
        currentHash = this.hashPair(sibling, currentHash);
      } else {
        currentHash = this.hashPair(currentHash, sibling);
      }

      index = index / 2n;
    }

    return CryptoUtils.constantTimeEqual(currentHash, proof.root);
  }

  /**
   * Get current root hash
   */
  getRoot(): string {
    return this.root;
  }

  /**
   * Get tree size
   */
  getSize(): number {
    return this.leaves.size;
  }

  /**
   * Update path from leaf to root
   */
  private updatePath(index: bigint, value: string): void {
    let currentHash = value;
    let currentIndex = index;

    // Store leaf node
    this.setNode(0, currentIndex, currentHash);

    // Update internal nodes
    for (let level = 0; level < this.TREE_DEPTH; level++) {
      const isRightNode = currentIndex % 2n === 1n;
      const siblingIndex = isRightNode ? currentIndex - 1n : currentIndex + 1n;
      const siblingHash = this.getNode(level, siblingIndex);

      if (isRightNode) {
        currentHash = this.hashPair(siblingHash, currentHash);
      } else {
        currentHash = this.hashPair(currentHash, siblingHash);
      }

      currentIndex = currentIndex / 2n;
      this.setNode(level + 1, currentIndex, currentHash);
    }

    // Update root
    this.root = currentHash;
  }

  /**
   * Get node at level and index
   */
  private getNode(level: number, index: bigint): string {
    const key = `${level}:${index}`;
    return this.nodes.get(key) || this.getEmptyNode(level);
  }

  /**
   * Set node at level and index
   */
  private setNode(level: number, index: bigint, hash: string): void {
    const key = `${level}:${index}`;
    this.nodes.set(key, hash);
  }

  /**
   * Get empty node hash for a level
   */
  private getEmptyNode(level: number): string {
    // Cache empty node hashes for each level
    const key = `empty:${level}`;
    let hash = this.nodes.get(key);

    if (!hash) {
      hash = this.EMPTY_LEAF;
      for (let i = 0; i < level; i++) {
        hash = this.hashPair(hash, hash);
      }
      this.nodes.set(key, hash);
    }

    return hash;
  }

  /**
   * Compute empty root hash
   */
  private computeEmptyRoot(): string {
    return this.getEmptyNode(this.TREE_DEPTH);
  }

  /**
   * Hash a pair of nodes
   */
  private hashPair(left: string, right: string): string {
    return CryptoUtils.deterministicHash(left, right);
  }

  /**
   * Export tree state
   */
  export(): SparseMerkleTreeState {
    return {
      root: this.root,
      depth: this.TREE_DEPTH,
      leaves: Array.from(this.leaves.entries()).map(([index, value]) => ({
        index,
        value
      }))
    };
  }

  /**
   * Import tree state
   */
  import(state: SparseMerkleTreeState): void {
    if (state.depth !== this.TREE_DEPTH) {
      throw new Error('Tree depth mismatch');
    }

    this.nodes.clear();
    this.leaves.clear();

    // Rebuild tree from leaves
    for (const leaf of state.leaves) {
      this.insert(BigInt(leaf.index), leaf.value);
    }

    // Verify root matches
    if (!CryptoUtils.constantTimeEqual(this.root, state.root)) {
      throw new Error('Root hash mismatch after import');
    }
  }
}

/**
 * Merkle proof structure
 */
export interface MerkleProof {
  leaf: string;
  index: string;
  siblings: string[];
  root: string;
}

/**
 * Sparse Merkle Tree state for export/import
 */
export interface SparseMerkleTreeState {
  root: string;
  depth: number;
  leaves: Array<{ index: string; value: string }>;
}
