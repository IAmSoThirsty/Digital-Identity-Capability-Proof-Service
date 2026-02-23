# Operational Hardening Guide

**Version:** 1.0
**Status:** Draft
**Last Updated:** 2026-02-23

## Table of Contents

1. [Overview](#overview)
2. [Rate Limiting and DoS Protection](#rate-limiting-and-dos-protection)
3. [ZK Proof Generation DoS Resilience](#zk-proof-generation-dos-resilience)
4. [Circuit Size Amplification Attacks](#circuit-size-amplification-attacks)
5. [Cache Poisoning Prevention](#cache-poisoning-prevention)
6. [Message Ordering in Distributed Mode](#message-ordering-in-distributed-mode)
7. [Partial Failure and Replay Handling](#partial-failure-and-replay-handling)
8. [Clock Drift and Cross-Region Latency](#clock-drift-and-cross-region-latency)
9. [Distributed Identity Collisions](#distributed-identity-collisions)
10. [Key Loss Recovery Procedures](#key-loss-recovery-procedures)
11. [Resource Exhaustion Mitigation](#resource-exhaustion-mitigation)
12. [Monitoring and Alerting](#monitoring-and-alerting)

## Overview

This document provides operational hardening guidance for the Digital Identity Capability Proof Service (DICPS) in production environments. It addresses resilience against denial-of-service attacks, distributed system failure modes, resource exhaustion, and real-world operational edge cases.

### Design Principles

1. **Defense in Depth**: Multiple layers of protection against each attack vector
2. **Graceful Degradation**: System remains partially functional under attack
3. **Resource Isolation**: Critical operations protected from resource exhaustion
4. **Observable Failures**: All failure modes produce actionable metrics
5. **Automated Recovery**: Self-healing mechanisms for common failure scenarios

## Rate Limiting and DoS Protection

### Multi-Tier Rate Limiting

```typescript
interface RateLimitTier {
  name: string;
  windowMs: number;
  maxRequests: number;
  priority: number;
}

interface RateLimitConfig {
  tiers: RateLimitTier[];
  bypassTokens?: string[];
  emergencyMode?: EmergencyModeConfig;
}

class MultiTierRateLimiter {
  private tiers: Map<string, TokenBucket[]>;
  private emergencyMode: boolean = false;

  constructor(private config: RateLimitConfig) {
    this.initializeTiers();
  }

  /**
   * Check if request should be rate limited
   * Implements sliding window counter with multiple time windows
   */
  async checkLimit(
    clientId: string,
    endpoint: string,
    operation: OperationType
  ): Promise<RateLimitResult> {
    // Check emergency mode first
    if (this.emergencyMode) {
      return this.checkEmergencyLimits(clientId, endpoint, operation);
    }

    const key = `${clientId}:${endpoint}`;
    const buckets = this.tiers.get(key) || this.createBuckets(key);

    // Check all tiers (shortest window first)
    for (const bucket of buckets) {
      if (!bucket.consume(1)) {
        return {
          allowed: false,
          tier: bucket.tier.name,
          retryAfter: bucket.getRetryAfter(),
          remaining: 0
        };
      }
    }

    return {
      allowed: true,
      remaining: this.getMinRemaining(buckets)
    };
  }

  /**
   * Enter emergency mode during active attack
   */
  activateEmergencyMode(reason: string): void {
    this.emergencyMode = true;
    this.config.emergencyMode = {
      maxRequestsPerSecond: 10,
      allowedOperations: ['verify'], // Only essential operations
      duration: 300000, // 5 minutes
      activatedAt: Date.now(),
      reason
    };

    this.logSecurityEvent({
      type: 'EMERGENCY_MODE_ACTIVATED',
      reason,
      timestamp: Date.now()
    });
  }
}

/**
 * Token bucket implementation with refill
 */
class TokenBucket {
  private tokens: number;
  private lastRefill: number;

  constructor(
    public tier: RateLimitTier,
    private capacity: number,
    private refillRate: number // tokens per ms
  ) {
    this.tokens = capacity;
    this.lastRefill = Date.now();
  }

  consume(count: number): boolean {
    this.refill();

    if (this.tokens >= count) {
      this.tokens -= count;
      return true;
    }
    return false;
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = now - this.lastRefill;
    const tokensToAdd = elapsed * this.refillRate;

    this.tokens = Math.min(this.capacity, this.tokens + tokensToAdd);
    this.lastRefill = now;
  }

  getRetryAfter(): number {
    const tokensNeeded = 1 - this.tokens;
    return Math.ceil(tokensNeeded / this.refillRate);
  }
}
```

### Distributed Rate Limiting

For multi-instance deployments:

```typescript
interface DistributedRateLimiter {
  backend: RateLimitBackend; // Redis, Memcached, etc.
  localCache: LRUCache<string, RateLimitState>;
  syncInterval: number;
}

class RedisRateLimiter implements DistributedRateLimiter {
  constructor(
    private redis: RedisClient,
    private config: RateLimitConfig
  ) {}

  /**
   * Check rate limit using Redis with Lua script for atomicity
   */
  async checkLimit(key: string, limit: number, windowMs: number): Promise<boolean> {
    const script = `
      local key = KEYS[1]
      local limit = tonumber(ARGV[1])
      local window = tonumber(ARGV[2])
      local now = tonumber(ARGV[3])

      local count = redis.call('INCR', key)

      if count == 1 then
        redis.call('PEXPIRE', key, window)
      end

      if count > limit then
        return 0
      end

      return 1
    `;

    const result = await this.redis.eval(
      script,
      1,
      key,
      limit.toString(),
      windowMs.toString(),
      Date.now().toString()
    );

    return result === 1;
  }

  /**
   * Sliding window rate limit with sorted sets
   */
  async slidingWindowCheck(
    key: string,
    limit: number,
    windowMs: number
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const windowStart = now - windowMs;

    const script = `
      local key = KEYS[1]
      local now = tonumber(ARGV[1])
      local windowStart = tonumber(ARGV[2])
      local limit = tonumber(ARGV[3])

      -- Remove old entries
      redis.call('ZREMRANGEBYSCORE', key, '-inf', windowStart)

      -- Count current window
      local count = redis.call('ZCARD', key)

      if count < limit then
        redis.call('ZADD', key, now, now)
        redis.call('PEXPIRE', key, ARGV[4])
        return {1, limit - count - 1}
      end

      return {0, 0}
    `;

    const result = await this.redis.eval(
      script,
      1,
      key,
      now.toString(),
      windowStart.toString(),
      limit.toString(),
      windowMs.toString()
    );

    return {
      allowed: result[0] === 1,
      remaining: result[1]
    };
  }
}
```

## ZK Proof Generation DoS Resilience

### Proof Generation Queue with Priority

```typescript
interface ProofRequest {
  id: string;
  circuit: string;
  inputs: any;
  priority: ProofPriority;
  submittedAt: number;
  timeout: number;
  clientId: string;
}

enum ProofPriority {
  CRITICAL = 0,    // Emergency/Security operations
  HIGH = 1,        // Interactive user operations
  NORMAL = 2,      // Standard requests
  LOW = 3,         // Batch/Background operations
  BULK = 4         // Mass operations
}

class ProofGenerationQueue {
  private queues: Map<ProofPriority, ProofRequest[]>;
  private workers: ProofWorker[];
  private maxQueueSize: number = 1000;
  private maxProofsPerClient: number = 10;
  private clientProofCounts: Map<string, number>;

  constructor(workerCount: number) {
    this.initializeQueues();
    this.workers = this.createWorkers(workerCount);
    this.clientProofCounts = new Map();
  }

  /**
   * Submit proof request with backpressure
   */
  async submitProof(request: ProofRequest): Promise<string> {
    // Check per-client limits
    const clientCount = this.clientProofCounts.get(request.clientId) || 0;
    if (clientCount >= this.maxProofsPerClient) {
      throw new Error('Client proof limit exceeded');
    }

    // Check queue size
    const queue = this.queues.get(request.priority);
    if (queue.length >= this.maxQueueSize) {
      // Apply backpressure - reject low priority requests
      if (request.priority >= ProofPriority.NORMAL) {
        throw new Error('Proof queue full - try again later');
      }
    }

    // Estimate proof generation time and check timeout
    const estimatedTime = this.estimateProofTime(request.circuit);
    if (estimatedTime > request.timeout) {
      throw new Error('Proof timeout too short for circuit complexity');
    }

    // Add to queue
    queue.push(request);
    this.clientProofCounts.set(request.clientId, clientCount + 1);

    // Notify workers
    this.notifyWorkers();

    return request.id;
  }

  /**
   * Estimate proof generation time based on circuit complexity
   */
  private estimateProofTime(circuit: string): number {
    const metrics = this.getCircuitMetrics(circuit);

    // Base time on constraint count and R1CS complexity
    const baseTime = metrics.constraints * 0.1; // 0.1ms per constraint
    const witnessTime = metrics.witnessComplexity * 10; // Witness generation
    const proofTime = 2000; // Groth16 proof generation ~2s

    return baseTime + witnessTime + proofTime;
  }

  /**
   * Circuit complexity validation to prevent amplification
   */
  validateCircuitComplexity(circuit: string, inputs: any): void {
    const metrics = this.getCircuitMetrics(circuit);

    // Reject circuits that are too large
    if (metrics.constraints > 1000000) {
      throw new Error('Circuit too complex - max 1M constraints');
    }

    // Check input size
    const inputSize = JSON.stringify(inputs).length;
    if (inputSize > 100000) {
      throw new Error('Input too large - max 100KB');
    }

    // Check for known malicious patterns
    this.detectMaliciousCircuits(circuit, inputs);
  }
}

/**
 * Proof worker with resource limits
 */
class ProofWorker {
  private currentProof: ProofRequest | null = null;
  private memoryLimit: number = 2 * 1024 * 1024 * 1024; // 2GB
  private cpuTimeLimit: number = 30000; // 30 seconds

  async generateProof(request: ProofRequest): Promise<Proof> {
    this.currentProof = request;

    // Set up resource monitoring
    const startMemory = process.memoryUsage().heapUsed;
    const startTime = Date.now();
    const timeoutHandle = setTimeout(() => {
      this.killProof('Timeout exceeded');
    }, this.cpuTimeLimit);

    try {
      // Monitor memory usage during generation
      const memoryCheckInterval = setInterval(() => {
        const currentMemory = process.memoryUsage().heapUsed;
        if (currentMemory - startMemory > this.memoryLimit) {
          this.killProof('Memory limit exceeded');
        }
      }, 1000);

      // Generate proof
      const proof = await this.generateProofUnsafe(request);

      clearInterval(memoryCheckInterval);
      clearTimeout(timeoutHandle);

      return proof;
    } catch (error) {
      clearTimeout(timeoutHandle);
      throw error;
    } finally {
      this.currentProof = null;
    }
  }

  private killProof(reason: string): void {
    // Kill proof generation and cleanup
    throw new Error(`Proof generation killed: ${reason}`);
  }
}
```

### Circuit Size Validation

```typescript
interface CircuitMetrics {
  constraints: number;
  witnessSize: number;
  witnessComplexity: number;
  publicInputs: number;
  privateInputs: number;
}

class CircuitValidator {
  private maxConstraints = 1000000;
  private maxWitnessSize = 100000;
  private knownMaliciousPatterns: RegExp[];

  /**
   * Validate circuit before accepting for proof generation
   */
  validateCircuit(circuitPath: string, inputs: any): CircuitMetrics {
    const metrics = this.analyzeCircuit(circuitPath);

    // Check constraint count
    if (metrics.constraints > this.maxConstraints) {
      throw new Error(
        `Circuit exceeds constraint limit: ${metrics.constraints} > ${this.maxConstraints}`
      );
    }

    // Check witness size
    if (metrics.witnessSize > this.maxWitnessSize) {
      throw new Error(
        `Witness size exceeds limit: ${metrics.witnessSize} > ${this.maxWitnessSize}`
      );
    }

    // Validate input sizes match circuit expectations
    this.validateInputs(metrics, inputs);

    // Check for amplification patterns
    this.detectAmplificationPatterns(circuitPath, metrics);

    return metrics;
  }

  /**
   * Detect circuits designed for amplification attacks
   */
  private detectAmplificationPatterns(circuitPath: string, metrics: CircuitMetrics): void {
    const circuitCode = fs.readFileSync(circuitPath, 'utf-8');

    // Check for suspicious patterns
    const suspiciousPatterns = [
      /for\s*\([^)]*;\s*[^;]*<\s*10000/g,  // Large loops
      /component\s+\w+\[10000\]/g,          // Large arrays
      /signal.*\[10000\]/g                  // Large signal arrays
    ];

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(circuitCode)) {
        this.logSuspiciousCircuit(circuitPath, pattern.source);
      }
    }

    // Check constraint-to-input ratio
    const ratio = metrics.constraints / (metrics.publicInputs + metrics.privateInputs);
    if (ratio > 10000) {
      throw new Error(
        `Suspicious constraint amplification detected: ${ratio}x amplification`
      );
    }
  }

  private analyzeCircuit(circuitPath: string): CircuitMetrics {
    // Parse R1CS file to get actual metrics
    const r1csPath = circuitPath.replace('.circom', '.r1cs');
    const r1cs = this.parseR1CS(r1csPath);

    return {
      constraints: r1cs.constraints.length,
      witnessSize: r1cs.nWitness,
      witnessComplexity: this.estimateWitnessComplexity(circuitPath),
      publicInputs: r1cs.nPublic,
      privateInputs: r1cs.nWitness - r1cs.nPublic - 1
    };
  }
}
```

## Cache Poisoning Prevention

### Cache Integrity Protection

```typescript
interface CacheEntry<T> {
  value: T;
  hash: string;
  timestamp: number;
  ttl: number;
  signature?: string;
}

class SecureCache<T> {
  private cache: Map<string, CacheEntry<T>>;
  private hashFunction: (data: any) => string;

  constructor() {
    this.cache = new Map();
    this.hashFunction = (data) => sha3_256(JSON.stringify(data)).toString('hex');
  }

  /**
   * Set cache value with integrity protection
   */
  async set(key: string, value: T, ttl: number, sign: boolean = false): Promise<void> {
    const hash = this.hashFunction(value);

    let signature: string | undefined;
    if (sign) {
      // Sign critical cache entries
      signature = await this.signCacheEntry(key, value, hash);
    }

    const entry: CacheEntry<T> = {
      value,
      hash,
      timestamp: Date.now(),
      ttl,
      signature
    };

    this.cache.set(key, entry);

    // Set expiration
    setTimeout(() => this.cache.delete(key), ttl);
  }

  /**
   * Get cache value with integrity verification
   */
  async get(key: string): Promise<T | null> {
    const entry = this.cache.get(key);

    if (!entry) {
      return null;
    }

    // Check TTL
    if (Date.now() - entry.timestamp > entry.ttl) {
      this.cache.delete(key);
      return null;
    }

    // Verify hash
    const computedHash = this.hashFunction(entry.value);
    if (computedHash !== entry.hash) {
      this.handleCachePoisoning(key, 'Hash mismatch');
      this.cache.delete(key);
      return null;
    }

    // Verify signature if present
    if (entry.signature) {
      const valid = await this.verifyCacheEntry(key, entry.value, entry.hash, entry.signature);
      if (!valid) {
        this.handleCachePoisoning(key, 'Signature invalid');
        this.cache.delete(key);
        return null;
      }
    }

    return entry.value;
  }

  /**
   * Handle cache poisoning detection
   */
  private handleCachePoisoning(key: string, reason: string): void {
    this.logSecurityEvent({
      type: 'CACHE_POISONING_DETECTED',
      key,
      reason,
      timestamp: Date.now()
    });

    // Alert security monitoring
    this.alertSecurityTeam({
      severity: 'HIGH',
      event: 'cache_poisoning',
      key,
      reason
    });
  }

  /**
   * Sign critical cache entries
   */
  private async signCacheEntry(key: string, value: T, hash: string): Promise<string> {
    const data = Buffer.concat([
      Buffer.from(key),
      Buffer.from(hash, 'hex'),
      Buffer.from(JSON.stringify(value))
    ]);

    return await this.cryptoService.sign(data);
  }
}
```

### Cache Key Namespacing

```typescript
/**
 * Prevent cache key collisions across different contexts
 */
class NamespacedCache {
  private namespace: string;
  private separator = '::';

  constructor(namespace: string) {
    this.namespace = this.sanitizeNamespace(namespace);
  }

  /**
   * Generate namespaced cache key
   */
  key(...parts: string[]): string {
    const sanitized = parts.map(p => this.sanitizeKey(p));
    return [this.namespace, ...sanitized].join(this.separator);
  }

  /**
   * Sanitize key components to prevent injection
   */
  private sanitizeKey(key: string): string {
    // Remove separator and control characters
    return key
      .replace(new RegExp(this.separator, 'g'), '_')
      .replace(/[\x00-\x1F\x7F]/g, '');
  }

  /**
   * Validate namespace to prevent traversal
   */
  private sanitizeNamespace(ns: string): string {
    if (!/^[a-zA-Z0-9_-]+$/.test(ns)) {
      throw new Error('Invalid namespace format');
    }
    return ns;
  }
}
```

## Message Ordering in Distributed Mode

### Causal Ordering with Vector Clocks

```typescript
type VectorClock = Map<string, number>;

interface CausalMessage {
  id: string;
  senderId: string;
  vectorClock: VectorClock;
  payload: any;
  timestamp: number;
}

class CausalOrderManager {
  private nodeId: string;
  private clock: VectorClock;
  private buffer: CausalMessage[];
  private delivered: Set<string>;

  constructor(nodeId: string, nodes: string[]) {
    this.nodeId = nodeId;
    this.clock = new Map(nodes.map(n => [n, 0]));
    this.buffer = [];
    this.delivered = new Set();
  }

  /**
   * Send message with vector clock
   */
  sendMessage(payload: any): CausalMessage {
    // Increment own clock
    this.clock.set(this.nodeId, (this.clock.get(this.nodeId) || 0) + 1);

    const message: CausalMessage = {
      id: this.generateMessageId(),
      senderId: this.nodeId,
      vectorClock: new Map(this.clock),
      payload,
      timestamp: Date.now()
    };

    return message;
  }

  /**
   * Receive message and deliver when causally ready
   */
  receiveMessage(message: CausalMessage): void {
    // Check if already delivered
    if (this.delivered.has(message.id)) {
      return;
    }

    // Add to buffer
    this.buffer.push(message);

    // Try to deliver messages
    this.tryDeliverMessages();
  }

  /**
   * Deliver messages that are causally ready
   */
  private tryDeliverMessages(): void {
    let delivered = true;

    while (delivered) {
      delivered = false;

      for (let i = 0; i < this.buffer.length; i++) {
        const message = this.buffer[i];

        if (this.isCausallyReady(message)) {
          // Deliver message
          this.deliverMessage(message);

          // Update clock
          this.updateClock(message);

          // Remove from buffer
          this.buffer.splice(i, 1);
          delivered = true;
          break;
        }
      }
    }
  }

  /**
   * Check if message is causally ready for delivery
   */
  private isCausallyReady(message: CausalMessage): boolean {
    // For each node, message clock must be <= local clock + 1 for sender
    for (const [nodeId, messageClock] of message.vectorClock.entries()) {
      const localClock = this.clock.get(nodeId) || 0;

      if (nodeId === message.senderId) {
        // Sender's clock should be exactly one ahead
        if (messageClock !== localClock + 1) {
          return false;
        }
      } else {
        // Other clocks should not be ahead
        if (messageClock > localClock) {
          return false;
        }
      }
    }

    return true;
  }

  /**
   * Update local clock after delivering message
   */
  private updateClock(message: CausalMessage): void {
    for (const [nodeId, messageClock] of message.vectorClock.entries()) {
      const localClock = this.clock.get(nodeId) || 0;
      this.clock.set(nodeId, Math.max(localClock, messageClock));
    }
  }

  private deliverMessage(message: CausalMessage): void {
    this.delivered.add(message.id);
    this.handleDeliveredMessage(message);
  }

  private handleDeliveredMessage(message: CausalMessage): void {
    // Process delivered message
    console.log(`Delivered message ${message.id} from ${message.senderId}`);
  }
}
```

### Total Ordering with Lamport Timestamps

```typescript
interface LamportMessage {
  id: string;
  senderId: string;
  lamportTimestamp: number;
  payload: any;
  physicalTimestamp: number;
}

class TotalOrderManager {
  private nodeId: string;
  private lamportClock: number = 0;
  private queue: LamportMessage[];
  private acknowledged: Map<string, Set<string>>; // messageId -> nodeIds

  constructor(nodeId: string, private nodes: string[]) {
    this.nodeId = nodeId;
    this.queue = [];
    this.acknowledged = new Map();
  }

  /**
   * Send message with Lamport timestamp
   */
  sendMessage(payload: any): LamportMessage {
    this.lamportClock++;

    const message: LamportMessage = {
      id: this.generateMessageId(),
      senderId: this.nodeId,
      lamportTimestamp: this.lamportClock,
      payload,
      physicalTimestamp: Date.now()
    };

    this.queue.push(message);
    this.sortQueue();

    return message;
  }

  /**
   * Receive message and update clock
   */
  receiveMessage(message: LamportMessage): void {
    // Update Lamport clock
    this.lamportClock = Math.max(this.lamportClock, message.lamportTimestamp) + 1;

    // Add to queue
    this.queue.push(message);
    this.sortQueue();

    // Send acknowledgment
    this.sendAck(message.id);

    // Try to deliver messages
    this.tryDeliverMessages();
  }

  /**
   * Receive acknowledgment for a message
   */
  receiveAck(messageId: string, fromNode: string): void {
    if (!this.acknowledged.has(messageId)) {
      this.acknowledged.set(messageId, new Set());
    }
    this.acknowledged.get(messageId)!.add(fromNode);

    // Try to deliver messages
    this.tryDeliverMessages();
  }

  /**
   * Deliver messages that have been acknowledged by all nodes
   */
  private tryDeliverMessages(): void {
    while (this.queue.length > 0) {
      const message = this.queue[0];

      // Check if acknowledged by all nodes
      const acks = this.acknowledged.get(message.id) || new Set();
      const allAcked = this.nodes.every(node =>
        node === this.nodeId || acks.has(node)
      );

      if (allAcked) {
        // Deliver message
        this.deliverMessage(message);
        this.queue.shift();
        this.acknowledged.delete(message.id);
      } else {
        // Messages are ordered, so stop if first is not ready
        break;
      }
    }
  }

  /**
   * Sort queue by Lamport timestamp, then by node ID for ties
   */
  private sortQueue(): void {
    this.queue.sort((a, b) => {
      if (a.lamportTimestamp !== b.lamportTimestamp) {
        return a.lamportTimestamp - b.lamportTimestamp;
      }
      return a.senderId.localeCompare(b.senderId);
    });
  }
}
```

## Partial Failure and Replay Handling

### Idempotency Tokens

```typescript
interface IdempotentRequest {
  idempotencyKey: string;
  operation: string;
  parameters: any;
  clientId: string;
  timestamp: number;
}

interface IdempotentResponse {
  result: any;
  timestamp: number;
  status: 'success' | 'error';
}

class IdempotencyManager {
  private store: Map<string, IdempotentResponse>;
  private ttl: number = 24 * 60 * 60 * 1000; // 24 hours

  /**
   * Execute operation with idempotency guarantee
   */
  async execute(
    request: IdempotentRequest,
    operation: () => Promise<any>
  ): Promise<any> {
    // Check if we've seen this request before
    const cached = this.store.get(request.idempotencyKey);

    if (cached) {
      // Check if cached response is still valid
      if (Date.now() - cached.timestamp < this.ttl) {
        if (cached.status === 'error') {
          throw new Error('Previous attempt failed - use new idempotency key');
        }
        return cached.result;
      } else {
        // Expired, remove from store
        this.store.delete(request.idempotencyKey);
      }
    }

    // Execute operation
    try {
      const result = await operation();

      // Store successful result
      this.store.set(request.idempotencyKey, {
        result,
        timestamp: Date.now(),
        status: 'success'
      });

      // Set expiration
      setTimeout(() => {
        this.store.delete(request.idempotencyKey);
      }, this.ttl);

      return result;
    } catch (error) {
      // Store error for a shorter period
      this.store.set(request.idempotencyKey, {
        result: null,
        timestamp: Date.now(),
        status: 'error'
      });

      setTimeout(() => {
        this.store.delete(request.idempotencyKey);
      }, 60000); // 1 minute for errors

      throw error;
    }
  }

  /**
   * Generate idempotency key from request
   */
  static generateKey(operation: string, parameters: any, clientId: string): string {
    const data = JSON.stringify({ operation, parameters, clientId });
    return sha3_256(data).toString('hex');
  }
}
```

### Distributed Transaction Recovery

```typescript
interface Transaction {
  id: string;
  operations: Operation[];
  state: TransactionState;
  startedAt: number;
  timeout: number;
}

enum TransactionState {
  INITIATED = 'INITIATED',
  PREPARING = 'PREPARING',
  PREPARED = 'PREPARED',
  COMMITTING = 'COMMITTING',
  COMMITTED = 'COMMITTED',
  ABORTING = 'ABORTING',
  ABORTED = 'ABORTED'
}

interface Operation {
  id: string;
  type: string;
  parameters: any;
  node: string;
  state: OperationState;
}

enum OperationState {
  PENDING = 'PENDING',
  PREPARED = 'PREPARED',
  COMMITTED = 'COMMITTED',
  ABORTED = 'ABORTED'
}

class TwoPhaseCommitCoordinator {
  private transactions: Map<string, Transaction>;

  async executeTransaction(operations: Operation[]): Promise<void> {
    const txId = this.generateTransactionId();
    const transaction: Transaction = {
      id: txId,
      operations,
      state: TransactionState.INITIATED,
      startedAt: Date.now(),
      timeout: 30000 // 30 seconds
    };

    this.transactions.set(txId, transaction);

    try {
      // Phase 1: Prepare
      await this.prepare(transaction);

      // Phase 2: Commit
      await this.commit(transaction);
    } catch (error) {
      // Abort on any failure
      await this.abort(transaction);
      throw error;
    }
  }

  /**
   * Phase 1: Prepare all operations
   */
  private async prepare(transaction: Transaction): Promise<void> {
    transaction.state = TransactionState.PREPARING;

    const preparePromises = transaction.operations.map(async (op) => {
      const prepared = await this.sendPrepare(op);
      if (!prepared) {
        throw new Error(`Operation ${op.id} failed to prepare`);
      }
      op.state = OperationState.PREPARED;
    });

    await Promise.all(preparePromises);
    transaction.state = TransactionState.PREPARED;
  }

  /**
   * Phase 2: Commit all operations
   */
  private async commit(transaction: Transaction): Promise<void> {
    transaction.state = TransactionState.COMMITTING;

    const commitPromises = transaction.operations.map(async (op) => {
      await this.sendCommit(op);
      op.state = OperationState.COMMITTED;
    });

    await Promise.all(commitPromises);
    transaction.state = TransactionState.COMMITTED;
  }

  /**
   * Abort transaction and rollback
   */
  private async abort(transaction: Transaction): Promise<void> {
    transaction.state = TransactionState.ABORTING;

    const abortPromises = transaction.operations.map(async (op) => {
      if (op.state === OperationState.PREPARED) {
        await this.sendAbort(op);
      }
      op.state = OperationState.ABORTED;
    });

    await Promise.all(abortPromises);
    transaction.state = TransactionState.ABORTED;
  }

  /**
   * Recover transactions after node failure
   */
  async recoverTransactions(): Promise<void> {
    for (const [txId, transaction] of this.transactions.entries()) {
      const age = Date.now() - transaction.startedAt;

      if (age > transaction.timeout) {
        // Transaction timed out
        if (transaction.state === TransactionState.PREPARED) {
          // All operations prepared, try to commit
          try {
            await this.commit(transaction);
          } catch (error) {
            await this.abort(transaction);
          }
        } else {
          // Not all prepared, abort
          await this.abort(transaction);
        }
      }
    }
  }
}
```

## Clock Drift and Cross-Region Latency

### Hybrid Logical Clocks

```typescript
interface HLCTimestamp {
  physicalTime: number;  // Wall clock time
  logicalTime: number;   // Logical counter
  nodeId: string;        // Node identifier
}

class HybridLogicalClock {
  private nodeId: string;
  private lastPhysicalTime: number = 0;
  private logicalTime: number = 0;
  private maxDrift: number = 5000; // 5 seconds max drift

  constructor(nodeId: string) {
    this.nodeId = nodeId;
  }

  /**
   * Generate new timestamp
   */
  now(): HLCTimestamp {
    const physicalTime = Date.now();

    if (physicalTime > this.lastPhysicalTime) {
      this.lastPhysicalTime = physicalTime;
      this.logicalTime = 0;
    } else {
      this.logicalTime++;
    }

    return {
      physicalTime: this.lastPhysicalTime,
      logicalTime: this.logicalTime,
      nodeId: this.nodeId
    };
  }

  /**
   * Update clock based on received timestamp
   */
  update(received: HLCTimestamp): HLCTimestamp {
    const physicalTime = Date.now();
    const maxPT = Math.max(physicalTime, this.lastPhysicalTime, received.physicalTime);

    // Check for clock drift
    if (Math.abs(physicalTime - received.physicalTime) > this.maxDrift) {
      this.handleClockDrift(physicalTime, received.physicalTime);
    }

    if (maxPT === this.lastPhysicalTime && maxPT === received.physicalTime) {
      this.logicalTime = Math.max(this.logicalTime, received.logicalTime) + 1;
    } else if (maxPT === this.lastPhysicalTime) {
      this.logicalTime++;
    } else if (maxPT === received.physicalTime) {
      this.logicalTime = received.logicalTime + 1;
    } else {
      this.logicalTime = 0;
    }

    this.lastPhysicalTime = maxPT;

    return {
      physicalTime: this.lastPhysicalTime,
      logicalTime: this.logicalTime,
      nodeId: this.nodeId
    };
  }

  /**
   * Compare two HLC timestamps
   */
  compare(a: HLCTimestamp, b: HLCTimestamp): number {
    if (a.physicalTime !== b.physicalTime) {
      return a.physicalTime - b.physicalTime;
    }
    if (a.logicalTime !== b.logicalTime) {
      return a.logicalTime - b.logicalTime;
    }
    return a.nodeId.localeCompare(b.nodeId);
  }

  /**
   * Handle detected clock drift
   */
  private handleClockDrift(localTime: number, remoteTime: number): void {
    const drift = Math.abs(localTime - remoteTime);

    this.logWarning({
      type: 'CLOCK_DRIFT_DETECTED',
      drift,
      localTime,
      remoteTime,
      nodeId: this.nodeId
    });

    // Alert if drift is severe
    if (drift > this.maxDrift * 2) {
      this.alertOperations({
        severity: 'CRITICAL',
        issue: 'Severe clock drift detected',
        drift,
        recommendation: 'Check NTP synchronization'
      });
    }
  }
}
```

### NTP Synchronization Monitoring

```typescript
interface NTPStatus {
  offset: number;      // Time offset in ms
  delay: number;       // Network delay in ms
  jitter: number;      // Clock jitter in ms
  synchronized: boolean;
  lastSync: number;
}

class NTPMonitor {
  private ntpServers: string[];
  private syncInterval: number = 300000; // 5 minutes
  private maxOffset: number = 1000; // 1 second
  private status: NTPStatus;

  constructor(ntpServers: string[]) {
    this.ntpServers = ntpServers;
    this.startMonitoring();
  }

  /**
   * Check NTP synchronization status
   */
  async checkSync(): Promise<NTPStatus> {
    try {
      const responses = await Promise.all(
        this.ntpServers.map(server => this.queryNTP(server))
      );

      // Use median offset to handle outliers
      const offsets = responses.map(r => r.offset).sort((a, b) => a - b);
      const medianOffset = offsets[Math.floor(offsets.length / 2)];

      const status: NTPStatus = {
        offset: medianOffset,
        delay: responses[0].delay,
        jitter: this.calculateJitter(offsets),
        synchronized: Math.abs(medianOffset) < this.maxOffset,
        lastSync: Date.now()
      };

      this.status = status;

      // Alert if not synchronized
      if (!status.synchronized) {
        this.handleDesync(status);
      }

      return status;
    } catch (error) {
      throw new Error(`NTP sync failed: ${error.message}`);
    }
  }

  /**
   * Handle clock desynchronization
   */
  private handleDesync(status: NTPStatus): void {
    this.logError({
      type: 'CLOCK_DESYNC',
      offset: status.offset,
      threshold: this.maxOffset
    });

    // Enter degraded mode if clock is unreliable
    this.enterDegradedMode('Clock desynchronization detected');
  }

  private calculateJitter(offsets: number[]): number {
    const mean = offsets.reduce((a, b) => a + b, 0) / offsets.length;
    const variance = offsets.reduce((sum, offset) => {
      return sum + Math.pow(offset - mean, 2);
    }, 0) / offsets.length;
    return Math.sqrt(variance);
  }

  private startMonitoring(): void {
    setInterval(() => this.checkSync(), this.syncInterval);
  }
}
```

## Distributed Identity Collisions

### Collision-Resistant ID Generation

```typescript
interface DistributedID {
  timestamp: number;    // 42 bits - milliseconds since epoch
  nodeId: number;       // 10 bits - node identifier
  sequence: number;     // 12 bits - sequence number
}

class SnowflakeIDGenerator {
  private epoch: number = 1609459200000; // 2021-01-01
  private nodeId: number;
  private sequence: number = 0;
  private lastTimestamp: number = -1;

  // Bit allocations
  private timestampBits = 42;
  private nodeIdBits = 10;
  private sequenceBits = 12;

  private maxNodeId = (1 << this.nodeIdBits) - 1;
  private maxSequence = (1 << this.sequenceBits) - 1;

  constructor(nodeId: number) {
    if (nodeId > this.maxNodeId) {
      throw new Error(`Node ID must be between 0 and ${this.maxNodeId}`);
    }
    this.nodeId = nodeId;
  }

  /**
   * Generate unique distributed ID
   */
  generate(): string {
    let timestamp = Date.now();

    if (timestamp < this.lastTimestamp) {
      // Clock moved backwards - wait until it catches up
      throw new Error('Clock moved backwards - refusing to generate ID');
    }

    if (timestamp === this.lastTimestamp) {
      // Same millisecond - increment sequence
      this.sequence = (this.sequence + 1) & this.maxSequence;

      if (this.sequence === 0) {
        // Sequence overflow - wait for next millisecond
        timestamp = this.waitNextMillis(this.lastTimestamp);
      }
    } else {
      // New millisecond - reset sequence
      this.sequence = 0;
    }

    this.lastTimestamp = timestamp;

    // Construct ID
    const timeSinceEpoch = timestamp - this.epoch;
    const id =
      (BigInt(timeSinceEpoch) << BigInt(this.nodeIdBits + this.sequenceBits)) |
      (BigInt(this.nodeId) << BigInt(this.sequenceBits)) |
      BigInt(this.sequence);

    return id.toString();
  }

  /**
   * Parse distributed ID
   */
  parse(id: string): DistributedID {
    const bigId = BigInt(id);

    const sequence = Number(bigId & BigInt(this.maxSequence));
    const nodeId = Number(
      (bigId >> BigInt(this.sequenceBits)) & BigInt(this.maxNodeId)
    );
    const timestamp = Number(
      bigId >> BigInt(this.nodeIdBits + this.sequenceBits)
    ) + this.epoch;

    return { timestamp, nodeId, sequence };
  }

  private waitNextMillis(lastTimestamp: number): number {
    let timestamp = Date.now();
    while (timestamp <= lastTimestamp) {
      timestamp = Date.now();
    }
    return timestamp;
  }
}

/**
 * Collision detection and resolution
 */
class CollisionDetector {
  private seen: Set<string>;
  private bloomFilter: BloomFilter;

  constructor() {
    this.seen = new Set();
    this.bloomFilter = new BloomFilter(1000000, 0.001); // 1M items, 0.1% FP rate
  }

  /**
   * Check for ID collision
   */
  checkCollision(id: string): boolean {
    // Quick bloom filter check
    if (!this.bloomFilter.mightContain(id)) {
      this.bloomFilter.add(id);
      return false;
    }

    // Confirm with exact check
    if (this.seen.has(id)) {
      this.handleCollision(id);
      return true;
    }

    this.seen.add(id);
    return false;
  }

  /**
   * Handle detected collision
   */
  private handleCollision(id: string): void {
    this.logCriticalError({
      type: 'ID_COLLISION_DETECTED',
      id,
      timestamp: Date.now()
    });

    throw new Error(`ID collision detected: ${id}`);
  }
}
```

## Key Loss Recovery Procedures

### Hierarchical Deterministic Key Recovery

```typescript
interface RecoveryConfig {
  mnemonic?: string;          // BIP39 mnemonic
  masterSeed?: Buffer;        // Master seed
  derivationPath: string;     // BIP32 path
  threshold: number;          // Shamir threshold
  shares: number;             // Total shares
}

class KeyRecoveryService {
  /**
   * Generate recoverable key with backup options
   */
  async generateRecoverableKey(config: RecoveryConfig): Promise<{
    privateKey: string;
    publicKey: string;
    recovery: RecoveryData;
  }> {
    // Generate or use provided mnemonic
    const mnemonic = config.mnemonic || this.generateMnemonic();

    // Derive key from mnemonic
    const seed = await this.mnemonicToSeed(mnemonic);
    const node = this.deriveKey(seed, config.derivationPath);

    // Create Shamir secret shares for backup
    const shares = this.createSecretShares(
      node.privateKey,
      config.threshold,
      config.shares
    );

    // Create recovery data
    const recovery: RecoveryData = {
      mnemonic,
      derivationPath: config.derivationPath,
      shares,
      threshold: config.threshold,
      publicKey: node.publicKey,
      createdAt: Date.now()
    };

    return {
      privateKey: node.privateKey,
      publicKey: node.publicKey,
      recovery
    };
  }

  /**
   * Recover key from mnemonic
   */
  async recoverFromMnemonic(
    mnemonic: string,
    derivationPath: string
  ): Promise<{ privateKey: string; publicKey: string }> {
    // Validate mnemonic
    if (!this.validateMnemonic(mnemonic)) {
      throw new Error('Invalid mnemonic');
    }

    // Derive key
    const seed = await this.mnemonicToSeed(mnemonic);
    const node = this.deriveKey(seed, derivationPath);

    return {
      privateKey: node.privateKey,
      publicKey: node.publicKey
    };
  }

  /**
   * Recover key from Shamir shares
   */
  recoverFromShares(shares: string[]): string {
    // Validate share count
    if (shares.length < this.getThreshold(shares)) {
      throw new Error('Insufficient shares for recovery');
    }

    // Reconstruct secret
    const privateKey = this.reconstructSecret(shares);

    return privateKey;
  }

  /**
   * Create Shamir secret shares using Shamir's Secret Sharing
   */
  private createSecretShares(
    secret: string,
    threshold: number,
    shares: number
  ): string[] {
    // Polynomial-based secret sharing
    const secretBytes = Buffer.from(secret, 'hex');
    const polynomial = this.generatePolynomial(secretBytes, threshold - 1);

    const shareList: string[] = [];
    for (let i = 1; i <= shares; i++) {
      const share = this.evaluatePolynomial(polynomial, i);
      shareList.push(this.encodeShare(i, share));
    }

    return shareList;
  }

  /**
   * Reconstruct secret from shares using Lagrange interpolation
   */
  private reconstructSecret(shares: string[]): string {
    const points = shares.map(s => this.decodeShare(s));
    const secret = this.lagrangeInterpolate(points, 0);
    return secret.toString('hex');
  }
}

/**
 * Social recovery with guardians
 */
interface Guardian {
  id: string;
  publicKey: string;
  encryptedShare: string;
  addedAt: number;
}

class SocialRecoveryService {
  private guardians: Map<string, Guardian>;
  private threshold: number;

  constructor(threshold: number) {
    this.threshold = threshold;
    this.guardians = new Map();
  }

  /**
   * Add guardian for social recovery
   */
  async addGuardian(
    guardianId: string,
    guardianPublicKey: string,
    share: string
  ): Promise<void> {
    // Encrypt share with guardian's public key
    const encryptedShare = await this.encryptForGuardian(
      share,
      guardianPublicKey
    );

    const guardian: Guardian = {
      id: guardianId,
      publicKey: guardianPublicKey,
      encryptedShare,
      addedAt: Date.now()
    };

    this.guardians.set(guardianId, guardian);
  }

  /**
   * Initiate recovery process
   */
  async initiateRecovery(newPublicKey: string): Promise<string> {
    // Create recovery request
    const recoveryId = this.generateRecoveryId();

    // Notify guardians
    await this.notifyGuardians(recoveryId, newPublicKey);

    return recoveryId;
  }

  /**
   * Submit guardian approval
   */
  async submitGuardianApproval(
    recoveryId: string,
    guardianId: string,
    decryptedShare: string,
    signature: string
  ): Promise<void> {
    // Verify guardian signature
    const guardian = this.guardians.get(guardianId);
    if (!guardian) {
      throw new Error('Unknown guardian');
    }

    const valid = await this.verifyGuardianSignature(
      guardianId,
      recoveryId,
      signature,
      guardian.publicKey
    );

    if (!valid) {
      throw new Error('Invalid guardian signature');
    }

    // Store approved share
    this.storeApprovedShare(recoveryId, guardianId, decryptedShare);

    // Check if threshold reached
    await this.checkRecoveryThreshold(recoveryId);
  }

  /**
   * Check if recovery threshold is met and complete recovery
   */
  private async checkRecoveryThreshold(recoveryId: string): Promise<void> {
    const approvedShares = this.getApprovedShares(recoveryId);

    if (approvedShares.length >= this.threshold) {
      // Reconstruct key
      const privateKey = this.reconstructSecret(approvedShares);

      // Complete recovery
      await this.completeRecovery(recoveryId, privateKey);
    }
  }
}
```

## Resource Exhaustion Mitigation

### Memory Pressure Handling

```typescript
interface MemoryMetrics {
  heapUsed: number;
  heapTotal: number;
  external: number;
  arrayBuffers: number;
  rss: number;
}

class MemoryPressureMonitor {
  private warningThreshold = 0.85;  // 85% of heap
  private criticalThreshold = 0.95; // 95% of heap
  private checkInterval = 1000;     // Check every second

  constructor() {
    this.startMonitoring();
  }

  /**
   * Monitor memory usage and trigger pressure responses
   */
  private startMonitoring(): void {
    setInterval(() => {
      const metrics = this.getMemoryMetrics();
      const pressure = this.calculatePressure(metrics);

      if (pressure >= this.criticalThreshold) {
        this.handleCriticalPressure(metrics);
      } else if (pressure >= this.warningThreshold) {
        this.handleWarningPressure(metrics);
      }
    }, this.checkInterval);
  }

  /**
   * Get current memory metrics
   */
  private getMemoryMetrics(): MemoryMetrics {
    const usage = process.memoryUsage();
    return {
      heapUsed: usage.heapUsed,
      heapTotal: usage.heapTotal,
      external: usage.external,
      arrayBuffers: usage.arrayBuffers,
      rss: usage.rss
    };
  }

  /**
   * Calculate memory pressure (0-1)
   */
  private calculatePressure(metrics: MemoryMetrics): number {
    return metrics.heapUsed / metrics.heapTotal;
  }

  /**
   * Handle warning level memory pressure
   */
  private handleWarningPressure(metrics: MemoryMetrics): void {
    this.logWarning({
      type: 'MEMORY_PRESSURE_WARNING',
      metrics,
      pressure: this.calculatePressure(metrics)
    });

    // Trigger garbage collection if available
    if (global.gc) {
      global.gc();
    }

    // Clear non-essential caches
    this.clearCaches('non-essential');

    // Reduce queue sizes
    this.reduceQueueSizes(0.5);
  }

  /**
   * Handle critical memory pressure
   */
  private handleCriticalPressure(metrics: MemoryMetrics): void {
    this.logError({
      type: 'MEMORY_PRESSURE_CRITICAL',
      metrics,
      pressure: this.calculatePressure(metrics)
    });

    // Aggressive garbage collection
    if (global.gc) {
      global.gc();
      global.gc(); // Force twice
    }

    // Clear all caches
    this.clearCaches('all');

    // Reject new requests
    this.enableBackpressure();

    // Kill low-priority tasks
    this.killLowPriorityTasks();

    // Alert operations
    this.alertCriticalMemory(metrics);
  }
}

/**
 * CPU throttling under load
 */
class CPUThrottler {
  private maxCPUPercent = 80;
  private measureInterval = 1000;
  private throttleActive = false;

  async monitorCPU(): Promise<void> {
    setInterval(async () => {
      const cpuUsage = await this.getCPUUsage();

      if (cpuUsage > this.maxCPUPercent && !this.throttleActive) {
        this.activateThrottle();
      } else if (cpuUsage < this.maxCPUPercent * 0.7 && this.throttleActive) {
        this.deactivateThrottle();
      }
    }, this.measureInterval);
  }

  private activateThrottle(): void {
    this.throttleActive = true;

    // Reduce worker pool size
    this.reduceWorkerPool(0.5);

    // Increase operation delays
    this.addOperationDelay(100);

    // Reduce batch sizes
    this.reduceBatchSizes(0.5);

    this.logWarning({
      type: 'CPU_THROTTLE_ACTIVATED',
      timestamp: Date.now()
    });
  }
}
```

## Monitoring and Alerting

### Comprehensive Metrics Collection

```typescript
interface SystemMetrics {
  timestamp: number;
  cpu: CPUMetrics;
  memory: MemoryMetrics;
  network: NetworkMetrics;
  operations: OperationMetrics;
  errors: ErrorMetrics;
}

interface OperationMetrics {
  proofGeneration: LatencyMetrics;
  proofVerification: LatencyMetrics;
  credentialIssuance: LatencyMetrics;
  credentialRevocation: LatencyMetrics;
}

interface LatencyMetrics {
  count: number;
  p50: number;
  p95: number;
  p99: number;
  max: number;
  errors: number;
}

class MetricsCollector {
  private metrics: Map<string, number[]>;
  private errorCounts: Map<string, number>;

  /**
   * Record operation latency
   */
  recordLatency(operation: string, latency: number): void {
    if (!this.metrics.has(operation)) {
      this.metrics.set(operation, []);
    }
    this.metrics.get(operation)!.push(latency);
  }

  /**
   * Record error
   */
  recordError(operation: string, error: Error): void {
    const key = `${operation}:${error.name}`;
    this.errorCounts.set(key, (this.errorCounts.get(key) || 0) + 1);
  }

  /**
   * Calculate percentiles
   */
  calculatePercentiles(operation: string): LatencyMetrics {
    const latencies = this.metrics.get(operation) || [];
    if (latencies.length === 0) {
      return { count: 0, p50: 0, p95: 0, p99: 0, max: 0, errors: 0 };
    }

    const sorted = latencies.sort((a, b) => a - b);

    return {
      count: sorted.length,
      p50: this.percentile(sorted, 0.5),
      p95: this.percentile(sorted, 0.95),
      p99: this.percentile(sorted, 0.99),
      max: sorted[sorted.length - 1],
      errors: this.getErrorCount(operation)
    };
  }

  private percentile(sorted: number[], p: number): number {
    const index = Math.ceil(sorted.length * p) - 1;
    return sorted[index];
  }
}

/**
 * Alert manager with escalation
 */
interface Alert {
  severity: 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL';
  type: string;
  message: string;
  timestamp: number;
  metadata: any;
}

class AlertManager {
  private alerts: Alert[];
  private escalationRules: Map<string, EscalationRule>;

  async sendAlert(alert: Alert): Promise<void> {
    this.alerts.push(alert);

    // Check for escalation
    const rule = this.escalationRules.get(alert.type);
    if (rule && this.shouldEscalate(alert, rule)) {
      await this.escalateAlert(alert, rule);
    }

    // Send to monitoring system
    await this.sendToMonitoring(alert);

    // Log alert
    this.logAlert(alert);
  }

  private shouldEscalate(alert: Alert, rule: EscalationRule): boolean {
    // Count recent alerts of same type
    const recentAlerts = this.alerts.filter(a =>
      a.type === alert.type &&
      Date.now() - a.timestamp < rule.timeWindow
    );

    return recentAlerts.length >= rule.threshold;
  }

  private async escalateAlert(alert: Alert, rule: EscalationRule): Promise<void> {
    // Notify on-call engineer
    await this.notifyOnCall(alert);

    // Create incident ticket
    await this.createIncident(alert);

    // Trigger automated response if configured
    if (rule.autoResponse) {
      await this.triggerAutoResponse(alert);
    }
  }
}
```

## Appendices

### A. Performance Benchmarks

Expected performance under various load conditions:

- **Normal Load**: 1000 req/s, p99 < 100ms
- **High Load**: 5000 req/s, p99 < 500ms
- **Peak Load**: 10000 req/s, p99 < 2s
- **Under Attack**: 50000 req/s, graceful degradation

### B. Runbook References

- **Memory Pressure**: ops/runbooks/memory-pressure.md
- **CPU Saturation**: ops/runbooks/cpu-saturation.md
- **Clock Drift**: ops/runbooks/clock-drift.md
- **Key Recovery**: ops/runbooks/key-recovery.md

### C. Related Documents

- [SECURITY_PROOFS.md](./SECURITY_PROOFS.md) - Formal security proofs
- [ADVERSARIAL_MODEL.md](./ADVERSARIAL_MODEL.md) - Threat modeling
- [CRYPTO_AGILITY.md](./CRYPTO_AGILITY.md) - Algorithm rotation
- [AUDIT_CHAIN.md](./AUDIT_CHAIN.md) - State integrity

---

*Document Version: 1.0*
*Last Review: 2026-02-23*
*Next Review: 2026-08-23*
