# DICPS Adversarial Model and Attack Analysis
**Comprehensive Adversarial Modeling and Mitigation Strategies**
**Version:** 1.0
**Status:** Draft
**Last Updated:** 2026-02-23

---

## Table of Contents

1. [Adversary Models](#1-adversary-models)
2. [Malicious Issuer Attacks](#2-malicious-issuer-attacks)
3. [Malicious Verifier Attacks](#3-malicious-verifier-attacks)
4. [Colluding Verifier Sets](#4-colluding-verifier-sets)
5. [Revocation Registry Attacks](#5-revocation-registry-attacks)
6. [Replay and Re-binding Attacks](#6-replay-and-re-binding-attacks)
7. [Correlation and Linkability](#7-correlation-and-linkability)
8. [Economic Attack Vectors](#8-economic-attack-vectors)
9. [Mitigation Strategies](#9-mitigation-strategies)

---

## 1. Adversary Models

### 1.1 Adversary Classifications

#### 1.1.1 Computational Power
```
Type A: Polynomial-Time Bounded (PPT)
  - Most realistic adversary
  - Can perform ≤ 2^40 operations
  - Cannot break cryptographic primitives

Type B: Computationally Unbounded
  - Theoretical model
  - Can perform any computation
  - Information-theoretic security required
  - Used for analyzing privacy leakage

Type C: Quantum Adversary
  - Has access to quantum computer
  - Can break some classical assumptions
  - Grover: √speedup on search
  - Shor: Polynomial-time discrete log
```

#### 1.1.2 System Access
```
Level 1: External Observer
  - Can observe public communications
  - Cannot modify messages
  - Cannot access internal state

Level 2: Active Attacker
  - Can modify/inject messages
  - Can initiate protocol runs
  - Cannot compromise keys

Level 3: Malicious Insider
  - Controls some system component
  - Can deviate from protocol
  - Knows some secret keys

Level 4: Global Adversary
  - Controls network infrastructure
  - Can monitor all traffic
  - Can delay/drop messages
```

#### 1.1.3 Corruption Model
```
Static Corruption:
  - Adversary chooses victims before protocol starts
  - Cannot adaptively corrupt

Adaptive Corruption:
  - Adversary can corrupt parties during execution
  - More powerful but more realistic

Threshold Corruption:
  - At most t out of n parties corrupted
  - Common in multi-party settings
```

### 1.2 Security Model Definitions

```typescript
interface AdversaryCapabilities {
  // Computational
  computationalBound: 'PPT' | 'Unbounded' | 'Quantum';
  operationsPerSecond: number;

  // Network
  canObserveTraffic: boolean;
  canModifyMessages: boolean;
  canDelayMessages: boolean;
  canDropMessages: boolean;

  // System Access
  compromisedComponents: Set<ComponentId>;
  knowsSecrets: Set<SecretId>;

  // Corruption
  corruptionType: 'Static' | 'Adaptive' | 'Threshold';
  maxCorruptions: number;
}

interface SecurityGoal {
  property: 'Privacy' | 'Integrity' | 'Availability';
  adversaryModel: AdversaryCapabilities;
  guarantee: string;
  assumptions: string[];
}
```

---

## 2. Malicious Issuer Attacks

### 2.1 Attack Vectors

#### 2.1.1 False Credential Issuance

**Attack Description**:
```
Malicious issuer I* issues credentials for false attributes:
  - Credential: {age: 18} for user who is actually 15
  - Credential: {license: 'PE'} for unlicensed individual
  - Credential: {clearance: 5} without proper authorization
```

**Impact**:
```
HIGH: User can prove false statements
  - Access to age-restricted content illegitimately
  - Unauthorized professional practice
  - Security breach in clearance systems
```

**Mitigation**:
```
M1: Multi-Issuer Attestation
  - Require credentials from k out of n issuers
  - Prevents single malicious issuer attack
  - Threshold: k ≥ ⌈n/2⌉ + 1 for Byzantine tolerance

M2: Auditable Issuance Log
  - All credentials logged to append-only ledger
  - Periodic audits check for anomalies
  - Statistical analysis detects outliers

M3: Issuer Reputation System
  - Track issuer behavior over time
  - Downgrade/revoke malicious issuers
  - Weight proofs by issuer reputation

M4: Cross-Verification
  - Periodic random checks with authoritative sources
  - Sample credentials and verify attributes
  - Detection probability: p = sample_rate
```

#### 2.1.2 Backdoor Credentials

**Attack Description**:
```
Issuer I* creates special credentials with backdoor:
  - Credential appears normal
  - Contains hidden signal for colluding verifier
  - Allows tracking specific users
```

**Example**:
```typescript
// Malicious credential structure
interface BackdoorCredential extends Credential {
  // Normal fields
  id: string;
  attributes: Attribute[];
  signature: string;

  // Hidden backdoor
  metadata: {
    tracking_id: string; // Unique to specific user
    issuer_signal: string; // Known only to colluding parties
  };
}
```

**Detection**:
```
D1: Credential Structure Validation
  - Enforce strict credential schema
  - Reject credentials with unexpected fields
  - Hash-based commitment to structure

D2: Statistical Analysis
  - Monitor for unusual credential patterns
  - Detect correlation between credentials and issuers
  - Alert on anomalies

D3: Open Inspection
  - Make credential format public
  - Allow third-party audits
  - Community review of implementations
```

#### 2.1.3 Over-Issuance

**Attack Description**:
```
Malicious issuer issues excessive credentials:
  - Creates Sybil identities
  - Issues multiple credentials per identity
  - Floods system with false credentials
```

**Impact**:
```
- Degrades system statistics
- Enables mass false proofs
- Denial of service on verifiers
```

**Mitigation**:
```
M1: Rate Limiting
  per_issuer_limit = max_credentials_per_hour
  if (issued_this_hour > per_issuer_limit):
    reject_issuance()

M2: Cost-Based Deterrence
  - Charge fees for credential issuance
  - Require stake deposit from issuers
  - Slash stake for malicious behavior

M3: Reputation-Based Quotas
  quota = base_quota * reputation_score
  - High reputation ⟹ Higher quotas
  - Low reputation ⟹ Lower quotas
  - Adaptive based on behavior
```

### 2.2 Issuer Collusion Attacks

**Multi-Issuer Collusion**:
```
Scenario: k colluding issuers I1, ..., Ik
Goal: Issue false credentials that pass multi-issuer checks

Attack:
  All k issuers agree to issue false credential C
  User gets k attestations for C
  System accepts C as valid

Defense:
  Require k > threshold_safe where:
    threshold_safe ≥ 2/3 * total_issuers

  Byzantine Fault Tolerance:
    Can tolerate up to ⌊(n-1)/3⌋ colluding issuers
```

---

## 3. Malicious Verifier Attacks

### 3.1 Privacy Attacks

#### 3.1.1 Proof Correlation

**Attack Description**:
```
Malicious verifier V* collects proofs from users:
  - User U provides proof π1 for service S1
  - User U provides proof π2 for service S2
  - V* tries to link π1 and π2 to same user
```

**Attack Methods**:
```
Method 1: Timing Correlation
  - Record proof submission times
  - Correlate with other activities
  - Build behavioral profiles

Method 2: Auxiliary Information
  - Combine proofs with side-channel data
  - IP addresses, browser fingerprints
  - Statistical correlation

Method 3: Challenge-Response
  - Send specific challenges to users
  - Observe proof patterns
  - Fingerprint proof generation behavior
```

**Mitigation**:
```
M1: Proof Randomization
  - Include fresh random salt in each proof
  - Different proofs unlinkable by construction
  - Implementation: salt ← {0,1}^λ

M2: Anonymity Network
  - Use Tor or similar for proof submission
  - Break IP correlation
  - Mix proof origins

M3: Proof Batching
  - Submit multiple proofs together
  - Hide individual proof timing
  - k-anonymity: At least k users per batch

M4: Blind Signatures
  - User blinds proof before submission
  - Verifier cannot correlate
  - Unblind for actual verification
```

#### 3.1.2 Timing Attacks

**Attack Description**:
```
Verifier V* measures proof verification time:
  - Different attributes have different verification times
  - V* infers information from timing
  - Example: Complex proofs take longer
```

**Timing Leak Examples**:
```
Leak 1: Attribute Value
  if (verification_time > threshold):
    infer: attribute_value is "complex"

Leak 2: Circuit Path
  Different circuit paths have different costs
  Timing reveals which path was taken

Leak 3: Witness Structure
  Sparse vs dense witnesses
  Different computation patterns
```

**Mitigation**:
```
M1: Constant-Time Verification
  - Pad verification to fixed duration
  - Always execute full verification
  - No early termination

M2: Noise Addition
  - Add random delay to verification
  - Randomness: Δt ← Uniform(0, max_noise)
  - Drowns timing signals

M3: Batch Verification
  - Verify multiple proofs together
  - Total time independent of individual proofs
  - Amortize verification cost
```

### 3.2 Denial of Service Attacks

#### 3.2.1 Proof Flooding

**Attack**:
```
Malicious verifier requests excessive proofs:
  - Overwhelm prover with proof requests
  - Exhaust computational resources
  - Deny service to legitimate verifiers
```

**Mitigation**:
```
M1: Rate Limiting
  max_requests_per_verifier_per_hour = 100
  if (requests > limit):
    throttle_or_block()

M2: Proof-of-Work
  - Verifier must solve puzzle to request proof
  - Cost scales with request rate
  - Deter automated attacks

M3: Priority System
  - Trusted verifiers get priority
  - Reputation-based queue
  - Fair scheduling algorithm
```

#### 3.2.2 Verification Amplification

**Attack**:
```
Send complex proofs that are expensive to verify:
  - Craft proofs requiring maximum verification time
  - Small proof request ⟹ Large verification cost
  - Amplification factor: cost_verify / cost_request
```

**Defense**:
```
D1: Complexity Bounds
  - Limit maximum proof complexity
  - Reject proofs exceeding bounds
  - max_constraints = 10^6

D2: Resource Quotas
  - Allocate fixed resources per verifier
  - Queue excess requests
  - Fair resource distribution

D3: Adaptive Throttling
  if (verification_load > threshold):
    increase_proof_cost()
    reduce_acceptance_rate()
```

---

## 4. Colluding Verifier Sets

### 4.1 Distributed Tracking

**Attack Scenario**:
```
V1, V2, ..., Vk collude to track user U:

Step 1: User provides proof to V1
Step 2: User provides proof to V2
...
Step k: Verifiers share proofs
Step k+1: Correlate across services
Step k+2: Build complete user profile
```

**Correlation Techniques**:
```
T1: Temporal Correlation
  - Match proof submission times
  - Window: ±Δt tolerance
  - Success rate: P(match | same user)

T2: Attribute Correlation
  - Cross-reference public signals
  - Find overlapping attributes
  - Bayesian inference

T3: Behavioral Patterns
  - Service access patterns
  - Proof request frequencies
  - Statistical fingerprinting
```

**Mitigation**:
```
M1: Unlinkable Proofs
  - Each proof cryptographically independent
  - Random salt: salt ← {0,1}^λ
  - Commitment: C = Hash(attribute, salt)

M2: Minimal Disclosure
  - Prove only necessary claims
  - Don't reveal more than required
  - Multi-statement batching

M3: Proof Mixing Service
  - Submit proofs through mixer
  - Re-randomize before delivery
  - k-anonymity guarantees

M4: Time Obfuscation
  - Random delays before submission
  - Break temporal correlation
  - Delay: Δt ← Exp(λ)
```

### 4.2 Information Pooling

**Attack Model**:
```
Colluding verifiers pool information:
  DB = Union(V1.proofs, V2.proofs, ..., Vk.proofs)

  Query: Find all proofs from user U
  Result: Complete activity history

  Privacy loss: P(identify user | k verifiers) increases with k
```

**Privacy Degradation**:
```
Single Verifier: ε-differential privacy
k Verifiers: k·ε privacy loss (composition)

Privacy budget exhaustion:
  After k queries, privacy ≈ 0
```

**Defense**:
```
D1: Privacy Budget Accounting
  - Track cumulative privacy loss
  - Refuse service when budget exhausted
  - Reset: After time period T

D2: Differential Privacy
  - Add calibrated noise to proofs
  - Guarantee: (ε, δ)-DP
  - Composition-aware

D3: Cryptographic Mixing
  - Use anonymous credentials
  - Proof unlinkability by construction
  - Forward privacy

D4: Decentralized Verification
  - No single verifier sees all proofs
  - Distributed verification protocol
  - Threshold verification
```

---

## 5. Revocation Registry Attacks

### 5.1 Registry Corruption

**Attack 5.1.1: False Revocation**
```
Malicious registry operator revokes valid credentials:
  Input: Valid credential C
  Action: Add C to revocation list
  Impact: User cannot use legitimate credential
```

**Mitigation**:
```
M1: Multi-Authority Revocation
  - Require k out of n authorities to revoke
  - Byzantine tolerance: n ≥ 3f + 1, k ≥ 2f + 1
  - Prevents single point of failure

M2: Revocation Proof
  - Revocation requires signed proof of cause
  - Auditable revocation log
  - Challenge mechanism for users

M3: Revocation Appeals
  - User can appeal revocation
  - Independent arbitration
  - Restore if revocation invalid
```

**Attack 5.1.2: Concealing Revocation**
```
Hide revoked credentials from some verifiers:
  - Selective disclosure of revocation list
  - Verifier V1 sees full list
  - Verifier V2 sees partial list
  - Allows use of revoked credentials
```

**Defense**:
```
D1: Merkle Tree Commitment
  - Root hash commits to full revocation set
  - Verifiers check root against trusted source
  - Proof of inclusion/exclusion

D2: Gossip Protocol
  - Verifiers share revocation information
  - Detect inconsistencies
  - Reconcile differences

D3: Blockchain Anchoring
  - Publish revocation root on blockchain
  - Immutable, auditable record
  - Fork detection
```

### 5.2 Revocation Spam

**Attack**:
```
Adversary floods revocation registry:
  - Submit massive revocation requests
  - Exhaust storage/bandwidth
  - Deny service to legitimate revocations
```

**Impact Analysis**:
```
Storage DoS:
  Revocations: N per second
  Storage growth: N × sizeof(RevocationRecord)
  Time to fill: Capacity / (N × sizeof(RevocationRecord))

Bandwidth DoS:
  Sync bandwidth: N × sizeof(RevocationRecord) × num_verifiers
  Network saturation threshold

Processing DoS:
  Merkle tree updates: O(N log N)
  CPU exhaustion
```

**Mitigation**:
```
M1: Rate Limiting
  max_revocations_per_issuer_per_hour = 1000
  if (revocations > limit):
    queue_or_reject()

M2: Proof-of-Authority
  - Only authorized entities can revoke
  - Require stake for revocation
  - Slash stake for spam

M3: Cost-Based Deterrence
  - Charge fee per revocation
  - Fee increases with rate
  - Economic disincentive

M4: Bloom Filter Optimization
  - Space-efficient revocation tracking
  - False positive rate: p = (1 - e^(-kn/m))^k
  - Significantly reduces storage
```

---

## 6. Replay and Re-binding Attacks

### 6.1 Cross-Protocol Replay

**Attack 6.1.1: Proof Reuse**
```
Attacker reuses proof across different contexts:

Scenario 1: Age proof for website A
  User proves: age ≥ 18 for website A

Scenario 2: Attacker intercepts proof
  Attacker replays proof to website B
  Website B accepts proof

Impact: User tracked across services
```

**Mitigation**:
```
M1: Context Binding
  proof = Generate(claim, witness, context)
  where context = Hash(verifier_id, timestamp, nonce)

  Verification checks:
    Verify(proof, context)
    if context.verifier_id ≠ my_id: reject
    if context.timestamp < now - Δt: reject

M2: Challenge-Response
  Verifier sends challenge: ch ← {0,1}^λ
  Prover includes ch in proof
  Proof only valid for this challenge

M3: Proof Expiration
  proof.valid_until = timestamp + lifetime
  if (now > proof.valid_until): reject
```

**Attack 6.1.2: Protocol Version Confusion**
```
Replay proof from protocol v1 to protocol v2:
  - Different security assumptions
  - Weaker guarantees in v1
  - Accepted by v2 due to confusion
```

**Defense**:
```
D1: Version Tagging
  proof.version = "v2"
  if (proof.version ≠ my_version): reject

D2: Protocol Negotiation
  Handshake determines protocol version
  Both parties agree before proof exchange
  Version mismatch ⟹ abort

D3: Cryptographic Domain Separation
  Hash inputs include protocol version
  Different versions ⟹ different proofs
  Prevents cross-version attacks
```

### 6.2 Proof Re-binding

**Attack**:
```
Bind proof to different identity/statement:

Original: Prove("age ≥ 18", witness_Alice, Alice_ID)
Attack: Rebind(proof, Bob_ID)
Result: Bob uses Alice's proof
```

**Mitigation**:
```
M1: Identity Binding
  proof includes commitment to identity
  C_id = Hash(identity_public_key, salt)
  Verification checks commitment

M2: Statement Binding
  proof cryptographically tied to statement
  Different statement ⟹ Different proof
  No malleability

M3: Signature of Knowledge
  Prove knowledge of private key for identity
  Links proof to identity holder
  Prevents transfer
```

---

## 7. Correlation and Linkability

### 7.1 Correlation Attacks

**Attack 7.1.1: Public Signal Correlation**
```
Attacker analyzes public signals across proofs:

Proof 1: [Hash1, Result1]
Proof 2: [Hash2, Result2]
...
Proof k: [Hashk, Resultk]

Statistical analysis:
  - Frequency analysis of hashes
  - Correlation with known distributions
  - Inference of private data
```

**Example**:
```
Age proof public signals: [H(age, salt), 1]

Attack:
  Collect many proofs for "age ≥ 18"
  Assume uniform age distribution
  Build histogram of H(age, salt)
  Statistical inference of age values

Success probability:
  P(infer age | k proofs) = f(k, distribution)
```

**Defense**:
```
D1: High-Entropy Salts
  salt ← {0,1}^λ where λ ≥ 256
  Each proof has unique hash
  No correlation possible

D2: Commitment Scheme
  Use cryptographically secure commitment
  Hiding property: Cannot infer committed value
  Binding property: Cannot change value

D3: Zero-Knowledge Enhancement
  Prove in zero-knowledge even the hash
  No public signals except "valid/invalid"
  Perfect privacy (at cost of efficiency)
```

**Attack 7.1.2: Timing Correlation**
```
Correlate proof generation times with events:

Event: User visits age-restricted site
Timing: Record access time t1
Proof: Generated at time t2
Correlation: If |t1 - t2| < threshold, link

Success rate: Depends on user population density
```

**Mitigation**:
```
M1: Proof Pre-generation
  - Generate proofs in advance
  - Store encrypted proof cache
  - Submit from cache (no generation time correlation)

M2: Random Delays
  - Add random delay before proof generation
  - Delay: Δt ← Exp(λ)
  - Break temporal correlation

M3: Batch Generation
  - Generate multiple proofs together
  - Submit at random times
  - k-anonymity guarantee
```

### 7.2 Linkability Analysis

**Linkability Metric**:
```
Definition: Probability that two proofs are from same user

L(π1, π2) = P(same user | π1, π2, auxiliary info)

Perfect Unlinkability: L(π1, π2) = P(same user) = 1/N
  where N is total number of users

Practical Goal: L(π1, π2) ≤ 1/N + ε
  where ε is negligibly small
```

**Factors Affecting Linkability**:
```
F1: Deterministic Components
  - Same attribute ⟹ Same hash (without salt)
  - Determinism ⟹ Linkability

F2: Auxiliary Information
  - IP addresses
  - Browser fingerprints
  - Timing patterns
  - Service usage patterns

F3: Statistical Patterns
  - Rare attributes more linkable
  - Common attributes less linkable
  - Entropy: H(attribute) affects linkability
```

**Unlinkability Guarantee**:
```
Theorem: With random salt per proof
  L(π1, π2) = 1/N + negl(λ)

Proof:
  Hash collision probability: 2^(-λ)
  With λ = 256: collision prob ≈ 0
  Without collision, proofs independent
  Therefore: Unlinkable except by auxiliary info
```

---

## 8. Economic Attack Vectors

### 8.1 Cost Asymmetry Exploitation

**Attack 8.1.1: Verification DoS**
```
Exploit cost asymmetry between proof generation and verification:

Cost_generate: O(|C| × log|C|) where |C| is circuit size
Cost_verify: O(|public_inputs|)

Attack:
  Generate many proofs (attacker cost)
  Force verifier to verify (verifier cost)

Amplification:
  If Cost_verify > Cost_generate:
    Attacker wins economically
```

**Mitigation**:
```
M1: Proof-of-Work for Submission
  - Require PoW before accepting proof
  - PoW difficulty: adjustable based on load
  - Cost_submit > Cost_verify

M2: Micropayments
  - Charge small fee per proof verification
  - Fee covers verification cost
  - Economic disincentive for spam

M3: Reputation Staking
  - Stake tokens to submit proofs
  - Slash stake for invalid/spam proofs
  - Reputation-based rate limits
```

**Attack 8.1.2: Revocation Spam Economics**
```
Spam revocation registry to increase costs:

Revenue Model:
  Attacker submits R revocations
  Cost to attacker: C_submit × R
  Cost to system: C_process × R + C_storage × R

Attack succeeds if:
  C_submit × R < C_process × R + C_storage × R
```

**Defense**:
```
D1: Increasing Cost Model
  Cost(n) = base_cost × (1 + α)^n
  where n is revocation rate
  Exponentially expensive to spam

D2: Deposit Requirement
  - Require deposit for revocation
  - Refund if revocation valid
  - Forfeit if spam detected

D3: Proof-of-Stake Revocation
  - Only staked authorities can revoke
  - Stake slashed for abuse
  - Economic security
```

### 8.2 Sybil Economics

**Attack**:
```
Create many fake identities to:
  - Amplify reputation attacks
  - Manipulate statistics
  - Overwhelm defenses

Sybil Cost Analysis:
  Cost per identity: C_id
  Value per identity: V_id
  Attack succeeds if: V_id > C_id
```

**Defenses**:
```
D1: Identity Cost
  - Require proof-of-personhood
  - Biometric verification
  - Government ID linkage
  - Minimum cost: C_id > V_id

D2: Stake Requirements
  - Stake tokens per identity
  - Stake locked for duration
  - Slashing for misbehavior

D3: Rate Limiting
  - Limit actions per identity
  - Time-based quotas
  - Reduce value of additional identities
```

---

## 9. Mitigation Strategies

### 9.1 Defense in Depth

**Layer 1: Cryptographic**
```
- Zero-knowledge proofs
- Unlinkable commitments
- Secure randomness
- Constant-time operations
```

**Layer 2: Protocol**
```
- Challenge-response
- Nonce/timestamp binding
- Version tagging
- Context binding
```

**Layer 3: Network**
```
- Rate limiting
- Proof-of-work
- Traffic analysis resistance
- Anonymity networks (Tor)
```

**Layer 4: Economic**
```
- Staking requirements
- Fee structures
- Reputation systems
- Slashing conditions
```

**Layer 5: Governance**
```
- Multi-party authorization
- Auditing requirements
- Appeal mechanisms
- Transparency reports
```

### 9.2 Monitoring and Detection

**Anomaly Detection**:
```typescript
interface AnomalyDetector {
  // Statistical anomalies
  detectOutliers(data: MetricData[]): Alert[];

  // Behavioral anomalies
  detectAnomalousBehavior(actor: ActorId): Risk Score;

  // Attack patterns
  detectKnownAttacks(traffic: NetworkTraffic): Attack[];

  // Correlation
  detectCorrelation(events: Event[]): CorrelationReport;
}

// Example: Revocation spam detection
function detectRevocationSpam(revocations: Revocation[]): boolean {
  const rate = revocations.length / time_window;
  const mean = historical_mean_rate;
  const stddev = historical_stddev;

  // Z-score test
  const z_score = (rate - mean) / stddev;
  return z_score > threshold; // e.g., threshold = 3
}
```

### 9.3 Incident Response

**Response Protocol**:
```
Phase 1: Detection (T+0)
  - Automated monitoring alerts
  - Manual report review
  - Triage and classification

Phase 2: Containment (T+1h)
  - Isolate affected components
  - Block malicious actors
  - Prevent spread

Phase 3: Eradication (T+4h)
  - Remove attack vectors
  - Patch vulnerabilities
  - Update defenses

Phase 4: Recovery (T+24h)
  - Restore normal operations
  - Validate system integrity
  - Monitor for recurrence

Phase 5: Post-Mortem (T+7d)
  - Root cause analysis
  - Lessons learned
  - Preventive measures
```

---

## Appendix A: Attack Taxonomy

```
Category 1: Cryptographic Attacks
  - Proof forgery
  - Collision attacks
  - Preimage attacks

Category 2: Protocol Attacks
  - Replay attacks
  - Re-binding attacks
  - Version confusion

Category 3: Privacy Attacks
  - Correlation
  - Linkability
  - De-anonymization

Category 4: Denial of Service
  - Proof flooding
  - Verification amplification
  - Resource exhaustion

Category 5: Economic Attacks
  - Cost asymmetry exploitation
  - Sybil attacks
  - Revocation spam

Category 6: Insider Attacks
  - Malicious issuer
  - Malicious verifier
  - Registry corruption
```

---

## Appendix B: Risk Assessment Matrix

```
Risk = Likelihood × Impact

Likelihood Scale:
  1: Very Unlikely (< 1% per year)
  2: Unlikely (1-10% per year)
  3: Possible (10-50% per year)
  4: Likely (50-90% per year)
  5: Very Likely (> 90% per year)

Impact Scale:
  1: Negligible (no real harm)
  2: Minor (limited harm)
  3: Moderate (significant harm)
  4: Major (severe harm)
  5: Critical (catastrophic harm)

Risk Levels:
  1-4: Low (Accept)
  5-9: Medium (Monitor)
  10-15: High (Mitigate)
  16-25: Critical (Must Fix)
```

**Risk Register**:
```
Attack: Malicious Issuer False Credentials
  Likelihood: 3 (Possible)
  Impact: 4 (Major)
  Risk: 12 (High)
  Mitigation: Multi-issuer attestation

Attack: Proof Correlation by Colluding Verifiers
  Likelihood: 4 (Likely)
  Impact: 3 (Moderate)
  Risk: 12 (High)
  Mitigation: Random salts, mixing service

Attack: Revocation Spam
  Likelihood: 2 (Unlikely)
  Impact: 2 (Minor)
  Risk: 4 (Low)
  Mitigation: Rate limiting, costs
```

---

**Document Version**: 1.0
**Last Review**: 2026-02-23
**Next Review**: 2026-05-23
