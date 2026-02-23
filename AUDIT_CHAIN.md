# DICPS Deterministic Audit Chain Specification
**Tamper-Evident State Transition Tracking**
**Version:** 1.0
**Status:** Draft
**Last Updated:** 2026-02-23

---

## Table of Contents

1. [Audit Chain Architecture](#1-audit-chain-architecture)
2. [State Transition Hashing](#2-state-transition-hashing)
3. [Tamper Evidence](#3-tamper-evidence)
4. [Event Ordering](#4-event-ordering)
5. [Fork Resolution](#5-fork-resolution)

---

## 1. Audit Chain Architecture

### 1.1 Chain Structure

```typescript
interface AuditBlock {
  index: number;
  timestamp: number;
  previousHash: string;
  stateRoot: string;
  events: AuditEvent[];
  transitionsHash: string;
  signature: string;
  nonce: string;
}

interface AuditEvent {
  id: string;
  type: EventType;
  actor: string;
  resource: string;
  action: string;
  before: StateSnapshot;
  after: StateSnapshot;
  metadata: Record<string, any>;
  timestamp: number;
}

enum EventType {
  IDENTITY_REGISTERED = 'identity.registered',
  CREDENTIAL_ISSUED = 'credential.issued',
  CREDENTIAL_REVOKED = 'credential.revoked',
  PROOF_GENERATED = 'proof.generated',
  PROOF_VERIFIED = 'proof.verified',
  KEY_ROTATED = 'key.rotated',
  ALGORITHM_CHANGED = 'algorithm.changed',
  CONFIG_UPDATED = 'config.updated'
}
```

### 1.2 Deterministic State Representation

```typescript
class StateHasher {
  // Deterministic serialization
  serializeState(state: SystemState): Buffer {
    // Sort keys for determinism
    const sorted = this.sortKeys(state);

    // Canonical JSON encoding
    const canonical = this.canonicalJSON(sorted);

    return Buffer.from(canonical, 'utf8');
  }

  // Compute state root hash
  computeStateRoot(state: SystemState): string {
    const serialized = this.serializeState(state);
    return sha3_256(serialized).toString('hex');
  }

  // Merkle tree of state components
  computeMerkleRoot(components: Record<string, any>): string {
    const leaves = Object.keys(components)
      .sort() // Deterministic ordering
      .map(key => sha3_256(JSON.stringify(components[key])));

    return this.buildMerkleTree(leaves).root;
  }

  private sortKeys(obj: any): any {
    if (obj === null || typeof obj !== 'object') return obj;

    if (Array.isArray(obj)) {
      return obj.map(item => this.sortKeys(item));
    }

    return Object.keys(obj)
      .sort()
      .reduce((sorted, key) => {
        sorted[key] = this.sortKeys(obj[key]);
        return sorted;
      }, {} as any);
  }

  private canonicalJSON(obj: any): string {
    // RFC 8785 compliant JSON serialization
    return JSON.stringify(obj, null, 0);
  }
}
```

---

## 2. State Transition Hashing

### 2.1 Transition Function

```typescript
interface StateTransition {
  fromState: string; // Hash of previous state
  event: AuditEvent;
  toState: string; // Hash of new state
  transitionHash: string; // Hash(fromState || event || toState)
}

class StateTransitionHasher {
  computeTransition(
    prevState: SystemState,
    event: AuditEvent
  ): StateTransition {
    // 1. Hash previous state
    const fromStateHash = this.stateHasher.computeStateRoot(prevState);

    // 2. Apply event to get new state
    const newState = this.applyEvent(prevState, event);

    // 3. Hash new state
    const toStateHash = this.stateHasher.computeStateRoot(newState);

    // 4. Hash the transition
    const transitionData = Buffer.concat([
      Buffer.from(fromStateHash, 'hex'),
      Buffer.from(JSON.stringify(event)),
      Buffer.from(toStateHash, 'hex')
    ]);

    const transitionHash = sha3_256(transitionData).toString('hex');

    return {
      fromState: fromStateHash,
      event,
      toState: toStateHash,
      transitionHash
    };
  }

  // Deterministic event application
  applyEvent(state: SystemState, event: AuditEvent): SystemState {
    const newState = cloneDeep(state);

    switch (event.type) {
      case EventType.IDENTITY_REGISTERED:
        newState.identities.set(event.resource, event.after);
        break;

      case EventType.CREDENTIAL_ISSUED:
        newState.credentials.set(event.resource, event.after);
        break;

      case EventType.CREDENTIAL_REVOKED:
        newState.revocations.set(event.resource, event.after);
        break;

      // ... other events
    }

    // Update state version
    newState.version++;
    newState.lastModified = event.timestamp;

    return newState;
  }

  // Verify transition validity
  verifyTransition(transition: StateTransition): boolean {
    // Recompute transition hash
    const computed = this.computeTransition(
      this.getStateByHash(transition.fromState),
      transition.event
    );

    return computed.transitionHash === transition.transitionHash &&
           computed.toState === transition.toState;
  }
}
```

### 2.2 Block Construction

```typescript
class AuditChain {
  private blocks: AuditBlock[] = [];
  private currentState: SystemState;

  appendEvents(events: AuditEvent[]): AuditBlock {
    // 1. Get previous block
    const prevBlock = this.blocks[this.blocks.length - 1];
    const prevHash = prevBlock ? this.hashBlock(prevBlock) : '0'.repeat(64);

    // 2. Compute transitions for all events
    const transitions: StateTransition[] = [];
    let state = this.currentState;

    for (const event of events) {
      const transition = this.transitionHasher.computeTransition(state, event);
      transitions.push(transition);
      state = this.getStateByHash(transition.toState);
    }

    // 3. Compute transitions hash
    const transitionsHash = sha3_256(
      Buffer.from(transitions.map(t => t.transitionHash).join(''))
    ).toString('hex');

    // 4. Create block
    const block: AuditBlock = {
      index: this.blocks.length,
      timestamp: Date.now(),
      previousHash: prevHash,
      stateRoot: transitions[transitions.length - 1].toState,
      events,
      transitionsHash,
      signature: '',
      nonce: this.generateNonce()
    };

    // 5. Sign block
    block.signature = this.signBlock(block);

    // 6. Add to chain
    this.blocks.push(block);
    this.currentState = state;

    return block;
  }

  verifyChain(): ValidationResult {
    let prevHash = '0'.repeat(64);

    for (let i = 0; i < this.blocks.length; i++) {
      const block = this.blocks[i];

      // Check block index
      if (block.index !== i) {
        return { valid: false, error: `Block ${i} has wrong index` };
      }

      // Check previous hash
      if (block.previousHash !== prevHash) {
        return { valid: false, error: `Block ${i} has invalid previous hash` };
      }

      // Verify transitions
      const transitionsValid = this.verifyBlockTransitions(block);
      if (!transitionsValid) {
        return { valid: false, error: `Block ${i} has invalid transitions` };
      }

      // Verify signature
      if (!this.verifyBlockSignature(block)) {
        return { valid: false, error: `Block ${i} has invalid signature` };
      }

      prevHash = this.hashBlock(block);
    }

    return { valid: true };
  }

  private hashBlock(block: AuditBlock): string {
    const data = Buffer.concat([
      Buffer.from(block.index.toString()),
      Buffer.from(block.timestamp.toString()),
      Buffer.from(block.previousHash, 'hex'),
      Buffer.from(block.stateRoot, 'hex'),
      Buffer.from(block.transitionsHash, 'hex'),
      Buffer.from(block.nonce)
    ]);

    return sha3_256(data).toString('hex');
  }
}
```

---

## 3. Tamper Evidence

### 3.1 Tamper Detection

```typescript
class TamperDetector {
  detectTampering(chain: AuditChain): TamperReport {
    const issues: TamperIssue[] = [];

    // Check 1: Hash chain integrity
    for (let i = 1; i < chain.blocks.length; i++) {
      const block = chain.blocks[i];
      const prevBlock = chain.blocks[i - 1];
      const computedPrevHash = this.hashBlock(prevBlock);

      if (block.previousHash !== computedPrevHash) {
        issues.push({
          type: 'HASH_CHAIN_BREAK',
          blockIndex: i,
          expected: computedPrevHash,
          actual: block.previousHash
        });
      }
    }

    // Check 2: State root consistency
    for (const block of chain.blocks) {
      const recomputedStateRoot = this.recomputeStateRoot(block.events);
      if (block.stateRoot !== recomputedStateRoot) {
        issues.push({
          type: 'STATE_ROOT_MISMATCH',
          blockIndex: block.index,
          expected: recomputedStateRoot,
          actual: block.stateRoot
        });
      }
    }

    // Check 3: Signature verification
    for (const block of chain.blocks) {
      if (!this.verifyBlockSignature(block)) {
        issues.push({
          type: 'INVALID_SIGNATURE',
          blockIndex: block.index
        });
      }
    }

    // Check 4: Timestamp monotonicity
    for (let i = 1; i < chain.blocks.length; i++) {
      if (chain.blocks[i].timestamp < chain.blocks[i - 1].timestamp) {
        issues.push({
          type: 'TIMESTAMP_REGRESSION',
          blockIndex: i
        });
      }
    }

    return {
      tampered: issues.length > 0,
      issues,
      lastVerifiedBlock: issues.length > 0 ? issues[0].blockIndex - 1 : chain.blocks.length - 1
    };
  }

  // Proof of tampering
  generateTamperProof(issue: TamperIssue): TamperProof {
    return {
      issue,
      evidence: this.collectEvidence(issue),
      witnesses: this.getWitnesses(issue.blockIndex),
      timestamp: Date.now()
    };
  }
}
```

### 3.2 Immutability Enforcement

```typescript
// Write-once semantics
class ImmutableAuditLog {
  private storage: AppendOnlyStorage;
  private witnessed: Set<string> = new Set();

  async append(block: AuditBlock): Promise<void> {
    // 1. Verify block not already written
    if (await this.storage.exists(block.index)) {
      throw new Error('Block already exists - immutability violation');
    }

    // 2. Verify previous block exists (except genesis)
    if (block.index > 0 && !(await this.storage.exists(block.index - 1))) {
      throw new Error('Previous block not found');
    }

    // 3. Write block
    await this.storage.write(block.index, block);

    // 4. Witness block hash
    const blockHash = this.hashBlock(block);
    await this.witnessBlock(blockHash);

    // 5. Make storage immutable
    await this.storage.seal(block.index);
  }

  private async witnessBlock(blockHash: string): Promise<void> {
    // Publish hash to multiple witnesses
    const witnesses = [
      this.publishToBlockchain(blockHash),
      this.publishToTimestampAuthority(blockHash),
      this.publishToDistributedLedger(blockHash)
    ];

    await Promise.all(witnesses);
    this.witnessed.add(blockHash);
  }
}
```

---

## 4. Event Ordering

### 4.1 Logical Timestamps

```typescript
// Lamport timestamps for distributed ordering
class LogicalClock {
  private counter: number = 0;
  private nodeId: string;

  tick(): number {
    return ++this.counter;
  }

  update(receivedTime: number): void {
    this.counter = Math.max(this.counter, receivedTime) + 1;
  }

  timestamp(event: AuditEvent): LamportTimestamp {
    const time = this.tick();
    return {
      logical: time,
      nodeId: this.nodeId,
      physical: Date.now()
    };
  }
}

// Vector clocks for causality
class VectorClock {
  private clocks: Map<string, number> = new Map();

  increment(nodeId: string): void {
    const current = this.clocks.get(nodeId) || 0;
    this.clocks.set(nodeId, current + 1);
  }

  update(other: VectorClock): void {
    for (const [nodeId, time] of other.clocks) {
      const current = this.clocks.get(nodeId) || 0;
      this.clocks.set(nodeId, Math.max(current, time));
    }
  }

  happensBefore(other: VectorClock): boolean {
    let lessOrEqual = true;
    let strictlyLess = false;

    for (const [nodeId, time] of this.clocks) {
      const otherTime = other.clocks.get(nodeId) || 0;
      if (time > otherTime) lessOrEqual = false;
      if (time < otherTime) strictlyLess = true;
    }

    return lessOrEqual && strictlyLess;
  }
}
```

### 4.2 Event Ordering Guarantees

```typescript
interface OrderingGuarantee {
  type: 'causal' | 'total' | 'eventual';
  properties: string[];
}

class EventOrderingManager {
  // Causal ordering: If event A caused event B, A appears before B
  maintainCausalOrder(events: AuditEvent[]): AuditEvent[] {
    const sorted: AuditEvent[] = [];
    const processed = new Set<string>();

    function process(event: AuditEvent): void {
      if (processed.has(event.id)) return;

      // Process dependencies first
      for (const depId of event.dependencies || []) {
        const dep = events.find(e => e.id === depId);
        if (dep) process(dep);
      }

      sorted.push(event);
      processed.add(event.id);
    }

    events.forEach(process);
    return sorted;
  }

  // Total ordering: All nodes see same order
  achieveTotalOrder(events: AuditEvent[]): AuditEvent[] {
    return events.sort((a, b) => {
      // Primary: Lamport timestamp
      if (a.lamportTime !== b.lamportTime) {
        return a.lamportTime - b.lamportTime;
      }

      // Tie-break: Node ID
      return a.nodeId.localeCompare(b.nodeId);
    });
  }
}
```

---

## 5. Fork Resolution

### 5.1 Fork Detection

```typescript
interface Fork {
  forkPoint: number; // Block index where fork occurred
  branches: Branch[];
  detected: number;
}

interface Branch {
  blocks: AuditBlock[];
  tip: string; // Hash of latest block
  length: number;
  totalWork: number;
}

class ForkDetector {
  detectForks(chains: AuditChain[]): Fork[] {
    const forks: Fork[] = [];

    // Find common ancestor
    for (let i = 0; i < chains.length - 1; i++) {
      for (let j = i + 1; j < chains.length; j++) {
        const fork = this.findFork(chains[i], chains[j]);
        if (fork) forks.push(fork);
      }
    }

    return forks;
  }

  private findFork(chain1: AuditChain, chain2: AuditChain): Fork | null {
    const minLength = Math.min(chain1.blocks.length, chain2.blocks.length);

    // Find last common block
    let commonIndex = -1;
    for (let i = 0; i < minLength; i++) {
      const hash1 = this.hashBlock(chain1.blocks[i]);
      const hash2 = this.hashBlock(chain2.blocks[i]);

      if (hash1 !== hash2) {
        break;
      }
      commonIndex = i;
    }

    // Check if fork exists
    if (commonIndex === minLength - 1) {
      return null; // One chain is prefix of other
    }

    return {
      forkPoint: commonIndex,
      branches: [
        {
          blocks: chain1.blocks.slice(commonIndex + 1),
          tip: this.hashBlock(chain1.blocks[chain1.blocks.length - 1]),
          length: chain1.blocks.length - commonIndex - 1,
          totalWork: this.computeWork(chain1.blocks.slice(commonIndex + 1))
        },
        {
          blocks: chain2.blocks.slice(commonIndex + 1),
          tip: this.hashBlock(chain2.blocks[chain2.blocks.length - 1]),
          length: chain2.blocks.length - commonIndex - 1,
          totalWork: this.computeWork(chain2.blocks.slice(commonIndex + 1))
        }
      ],
      detected: Date.now()
    };
  }
}
```

### 5.2 Resolution Strategies

```typescript
enum ResolutionStrategy {
  LONGEST_CHAIN,
  MOST_WORK,
  EARLIEST_TIMESTAMP,
  MANUAL_REVIEW
}

class ForkResolver {
  async resolveFork(
    fork: Fork,
    strategy: ResolutionStrategy
  ): Promise<Branch> {
    switch (strategy) {
      case ResolutionStrategy.LONGEST_CHAIN:
        return this.selectLongestChain(fork);

      case ResolutionStrategy.MOST_WORK:
        return this.selectMostWork(fork);

      case ResolutionStrategy.EARLIEST_TIMESTAMP:
        return this.selectEarliestBranch(fork);

      case ResolutionStrategy.MANUAL_REVIEW:
        return await this.manualReview(fork);
    }
  }

  private selectLongestChain(fork: Fork): Branch {
    return fork.branches.reduce((longest, branch) =>
      branch.length > longest.length ? branch : longest
    );
  }

  private selectMostWork(fork: Fork): Branch {
    return fork.branches.reduce((mostWork, branch) =>
      branch.totalWork > mostWork.totalWork ? branch : mostWork
    );
  }

  // Consensus: 2/3 of witnesses must agree
  async consensusResolution(fork: Fork): Promise<Branch> {
    const votes = await this.collectWitnessVotes(fork);

    for (const branch of fork.branches) {
      const voteCount = votes.filter(v => v.branch === branch.tip).length;
      if (voteCount >= (2 * votes.length) / 3) {
        return branch;
      }
    }

    throw new Error('No consensus reached');
  }
}
```

---

## Appendix: Audit Event Schema

```typescript
// Complete audit event types
const AuditEventSchema = {
  IDENTITY_REGISTERED: {
    before: null,
    after: {
      id: 'string',
      publicKey: 'string',
      attributes: 'Attribute[]',
      createdAt: 'number'
    }
  },

  CREDENTIAL_ISSUED: {
    before: null,
    after: {
      id: 'string',
      identityId: 'string',
      issuer: 'string',
      attributes: 'Attribute[]',
      signature: 'string',
      issuedAt: 'number'
    }
  },

  CREDENTIAL_REVOKED: {
    before: {
      status: 'active'
    },
    after: {
      status: 'revoked',
      revokedAt: 'number',
      reason: 'string?'
    }
  },

  PROOF_GENERATED: {
    before: null,
    after: {
      proofId: 'string',
      claimType: 'ClaimType',
      statement: 'string',
      timestamp: 'number'
    }
  },

  PROOF_VERIFIED: {
    before: null,
    after: {
      proofId: 'string',
      valid: 'boolean',
      verifier: 'string',
      timestamp: 'number'
    }
  }
};
```

---

**Document Version**: 1.0
**Last Review**: 2026-02-23
**Next Review**: 2026-05-23
