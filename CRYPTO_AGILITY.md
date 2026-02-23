# DICPS Cryptographic Agility Framework
**Algorithm Rotation, Governance, and Migration Strategies**
**Version:** 1.0
**Status:** Draft
**Last Updated:** 2026-02-23

---

## Table of Contents

1. [Overview](#1-overview)
2. [Algorithm Lifecycle](#2-algorithm-lifecycle)
3. [Rotation Governance](#3-rotation-governance)
4. [Migration Procedures](#4-migration-procedures)
5. [Compatibility Management](#5-compatibility-management)
6. [Emergency Procedures](#6-emergency-procedures)

---

## 1. Overview

### 1.1 Purpose

Cryptographic agility enables the system to:
- Adapt to emerging threats
- Transition to stronger algorithms
- Replace compromised primitives
- Support algorithmic diversity
- Plan for post-quantum security

### 1.2 Agility Requirements

```typescript
interface CryptographicPrimitive {
  id: string;
  algorithm: string;
  parameters: Record<string, any>;
  status: 'current' | 'deprecated' | 'sunset' | 'compromised';
  validFrom: number;
  validUntil: number | null;
  securityLevel: number; // bits
  quantumResistant: boolean;
}

interface AgilitySupportMatrix {
  signatures: CryptographicPrimitive[];
  hashes: CryptographicPrimitive[];
  commitments: CryptographicPrimitive[];
  zkSystems: CryptographicPrimitive[];
  keyAgreement: CryptographicPrimitive[];
}
```

---

## 2. Algorithm Lifecycle

### 2.1 Lifecycle Stages

```
RESEARCH → CANDIDATE → STANDARDIZED → CURRENT → DEPRECATED → SUNSET → FORBIDDEN

RESEARCH:
  - Under investigation
  - No production use
  - Security analysis ongoing

CANDIDATE:
  - Proposed for adoption
  - Limited testing
  - Community review

STANDARDIZED:
  - Published standard (NIST, IETF, etc.)
  - Approved for production
  - Migration planning begins

CURRENT:
  - Recommended for new deployments
  - Full support
  - Actively maintained

DEPRECATED:
  - Still supported but not recommended
  - Migration encouraged
  - Security updates only

SUNSET:
  - Support ending soon
  - Migration mandatory
  - No new deployments

FORBIDDEN:
  - Compromised or broken
  - Must not be used
  - Immediate migration required
```

### 2.2 Transition Timelines

```yaml
Standard Transition (Algorithm Upgrade):
  Phase 1 - Announcement: T-365 days
    - Publish migration plan
    - Notify all stakeholders
    - Begin development

  Phase 2 - Development: T-270 days
    - Implement new algorithm
    - Test compatibility
    - Prepare migration tools

  Phase 3 - Testing: T-180 days
    - Beta testing
    - Security audit
    - Performance validation

  Phase 4 - Rollout: T-90 days
    - Gradual deployment
    - Support both algorithms
    - Monitor closely

  Phase 5 - Migration: T-0 to T+180 days
    - Migrate existing data
    - Update clients
    - Deprecate old algorithm

  Phase 6 - Sunset: T+365 days
    - Remove old algorithm support
    - Complete transition
    - Post-mortem review

Emergency Transition (Compromise):
  Phase 1 - Immediate: T+0 hours
    - Disable compromised algorithm
    - Emergency announcement
    - Activate incident response

  Phase 2 - Rapid Deployment: T+24 hours
    - Deploy replacement algorithm
    - Emergency patches
    - Priority support

  Phase 3 - Forced Migration: T+7 days
    - Mandate algorithm change
    - Assisted migration
    - Compatibility mode

  Phase 4 - Cleanup: T+30 days
    - Remove compromised algorithm
    - Security review
    - Lessons learned
```

### 2.3 Algorithm Status Tracking

```typescript
class AlgorithmRegistry {
  private algorithms: Map<string, CryptographicPrimitive>;
  private transitions: Map<string, AlgorithmTransition[]>;

  registerAlgorithm(primitive: CryptographicPrimitive): void {
    this.algorithms.set(primitive.id, primitive);
    this.auditLog.append({
      event: 'ALGORITHM_REGISTERED',
      algorithm: primitive.id,
      timestamp: Date.now()
    });
  }

  deprecateAlgorithm(id: string, reason: string, sunsetDate: number): void {
    const algo = this.algorithms.get(id);
    if (!algo) throw new Error('Algorithm not found');

    algo.status = 'deprecated';
    algo.validUntil = sunsetDate;

    this.transitions.set(id, [{
      from: 'current',
      to: 'deprecated',
      timestamp: Date.now(),
      reason,
      sunsetDate
    }]);

    this.notifyStakeholders({
      type: 'DEPRECATION_NOTICE',
      algorithm: id,
      reason,
      sunsetDate
    });
  }

  getCurrentAlgorithms(type: AlgorithmType): CryptographicPrimitive[] {
    return Array.from(this.algorithms.values())
      .filter(a => a.algorithm.startsWith(type) && a.status === 'current');
  }

  checkCompliance(usage: AlgorithmUsage): ComplianceResult {
    const algo = this.algorithms.get(usage.algorithmId);

    if (!algo) {
      return { compliant: false, reason: 'Unknown algorithm' };
    }

    if (algo.status === 'forbidden') {
      return { compliant: false, reason: 'Algorithm compromised' };
    }

    if (algo.status === 'sunset' && usage.timestamp > Date.now()) {
      return { compliant: false, reason: 'Algorithm sunset' };
    }

    if (algo.validUntil && usage.timestamp > algo.validUntil) {
      return { compliant: false, reason: 'Algorithm expired' };
    }

    return { compliant: true };
  }
}
```

---

## 3. Rotation Governance

### 3.1 Decision Authority

```
Tier 1 Decisions (Routine Upgrades):
  Authority: Technical Committee
  Quorum: 3/5 members
  Notice Period: 90 days
  Examples:
    - Increase hash output size
    - Update library version
    - Performance optimizations

Tier 2 Decisions (Algorithm Changes):
  Authority: Security Board
  Quorum: 5/7 members
  Notice Period: 180 days
  Examples:
    - Change signature scheme
    - Adopt new ZK system
    - Modify key sizes

Tier 3 Decisions (Emergency Response):
  Authority: Emergency Response Team
  Quorum: 2/3 members (any 2)
  Notice Period: Immediate
  Examples:
    - Algorithm compromise
    - Zero-day vulnerability
    - Critical security flaw

Tier 4 Decisions (Post-Quantum Migration):
  Authority: Full Governance Body
  Quorum: 2/3 of all members
  Notice Period: 365 days
  Examples:
    - Transition to PQC
    - Major protocol revision
    - Architectural changes
```

### 3.2 Approval Process

```typescript
interface AlgorithmProposal {
  id: string;
  proposer: string;
  algorithm: CryptographicPrimitive;
  justification: string;
  securityAnalysis: SecurityReport;
  performanceAnalysis: PerformanceReport;
  migrationPlan: MigrationPlan;
  timeline: Timeline;
}

interface ApprovalWorkflow {
  stages: ApprovalStage[];
}

enum ApprovalStage {
  SUBMISSION = 'submission',
  TECHNICAL_REVIEW = 'technical_review',
  SECURITY_AUDIT = 'security_audit',
  COMMUNITY_FEEDBACK = 'community_feedback',
  BOARD_VOTE = 'board_vote',
  IMPLEMENTATION = 'implementation',
  DEPLOYMENT = 'deployment'
}

async function processProposal(proposal: AlgorithmProposal): Promise<Decision> {
  // Stage 1: Technical Review
  const techReview = await technicalCommittee.review(proposal);
  if (!techReview.approved) {
    return { approved: false, reason: techReview.reason };
  }

  // Stage 2: Security Audit
  const secAudit = await securityAuditor.audit(proposal.algorithm);
  if (secAudit.severity === 'critical') {
    return { approved: false, reason: 'Critical security issues' };
  }

  // Stage 3: Community Feedback (30 days)
  const feedback = await collectFeedback(proposal, duration: 30 * 24 * 60 * 60 * 1000);
  const concerns = feedback.filter(f => f.type === 'concern');

  // Stage 4: Board Vote
  const vote = await securityBoard.vote(proposal, {
    technicalReview: techReview,
    securityAudit: secAudit,
    communityFeedback: feedback
  });

  if (vote.approved) {
    await scheduleDeployment(proposal);
  }

  return vote;
}
```

### 3.3 Stakeholder Communication

```yaml
Communication Plan:
  Tier 1 (Routine):
    Channels:
      - Technical blog
      - Release notes
      - API changelog
    Audience:
      - Developers
      - Integrators
    Frequency:
      - Quarterly updates

  Tier 2 (Algorithm Change):
    Channels:
      - Security advisory
      - Email notification
      - Blog post
      - Documentation update
    Audience:
      - All users
      - Security teams
      - Compliance officers
    Frequency:
      - At decision + 30/60/90 days + deployment

  Tier 3 (Emergency):
    Channels:
      - Emergency alert system
      - Email blast
      - Twitter/social media
      - Press release
    Audience:
      - Everyone
      - Security community
      - Media
    Frequency:
      - Immediate + hourly updates

  Tier 4 (Major Migration):
    Channels:
      - All of the above
      - Webinars
      - Migration workshops
      - Direct outreach
    Audience:
      - Entire ecosystem
    Frequency:
      - Continuous throughout migration
```

---

## 4. Migration Procedures

### 4.1 Signature Algorithm Migration

**Example: ECDSA (secp256k1) → EdDSA (Ed25519)**

```typescript
interface SignatureMigration {
  oldAlgorithm: 'ECDSA-secp256k1';
  newAlgorithm: 'EdDSA-Ed25519';
  migrationPhase: MigrationPhase;
}

enum MigrationPhase {
  PREPARATION,
  DUAL_SUPPORT,
  TRANSITION,
  DEPRECATION,
  COMPLETION
}

// Phase 1: Preparation
async function prepareMigration(): Promise<void> {
  // 1. Generate new keys
  const newKeys = await generateEdDSAKeys();

  // 2. Publish new public keys
  await publishKeys({
    algorithm: 'EdDSA-Ed25519',
    publicKey: newKeys.publicKey,
    validFrom: futureDate,
    purposes: ['signing', 'verification']
  });

  // 3. Update trust anchors
  await distributeTrustAnchors({
    keys: [oldKey, newKey], // Both during transition
    validationRules: 'accept_both'
  });
}

// Phase 2: Dual Support
async function enableDualSupport(): Promise<void> {
  // Support verification of both algorithms
  function verifySignature(message: Buffer, signature: Signature): boolean {
    if (signature.algorithm === 'ECDSA-secp256k1') {
      return verifyECDSA(message, signature);
    } else if (signature.algorithm === 'EdDSA-Ed25519') {
      return verifyEdDSA(message, signature);
    }
    throw new Error('Unsupported algorithm');
  }

  // Sign with new algorithm, include old signature for compatibility
  function signWithBoth(message: Buffer): DualSignature {
    return {
      primary: signEdDSA(message, newPrivateKey),
      legacy: signECDSA(message, oldPrivateKey),
      validUntil: transitionDeadline
    };
  }
}

// Phase 3: Transition
async function transitionToNew(): Promise<void> {
  // Prefer new algorithm, accept old
  function prioritizeNew(signatures: Signature[]): Signature {
    const newSig = signatures.find(s => s.algorithm === 'EdDSA-Ed25519');
    if (newSig) return newSig;

    const oldSig = signatures.find(s => s.algorithm === 'ECDSA-secp256k1');
    if (oldSig && Date.now() < deprecationDate) return oldSig;

    throw new Error('No valid signature');
  }

  // Migrate stored signatures
  await migrateDatabase(async (record) => {
    if (record.signature.algorithm === 'ECDSA-secp256k1') {
      const newSig = await reSign(record.data, newPrivateKey);
      record.signature = newSig;
    }
    return record;
  });
}

// Phase 4: Deprecation
async function deprecateOld(): Promise<void> {
  // Stop accepting old signatures
  function verifySignature(message: Buffer, signature: Signature): boolean {
    if (signature.algorithm === 'ECDSA-secp256k1') {
      throw new Error('ECDSA-secp256k1 deprecated. Use EdDSA-Ed25519.');
    }
    return verifyEdDSA(message, signature);
  }

  // Remove old keys
  await revokeKeys({
    algorithm: 'ECDSA-secp256k1',
    reason: 'Algorithm migration complete'
  });
}

// Phase 5: Completion
async function completeMigration(): Promise<void> {
  // Remove all old algorithm code
  // Update documentation
  // Post-mortem review

  await auditLog.append({
    event: 'MIGRATION_COMPLETE',
    fromAlgorithm: 'ECDSA-secp256k1',
    toAlgorithm: 'EdDSA-Ed25519',
    duration: migrationDuration,
    recordsMigrated: recordCount,
    timestamp: Date.now()
  });
}
```

### 4.2 Hash Function Migration

**Example: SHA-256 → SHA-3 (Keccak)**

```typescript
// Backward-compatible hash migration
class HashFunctionMigrator {
  private oldHash: HashFunction = sha256;
  private newHash: HashFunction = sha3_256;
  private transitionDate: number;

  // During transition: Use both hashes
  hashWithVersion(data: Buffer, version: 'v1' | 'v2'): Buffer {
    if (version === 'v1') {
      return this.oldHash(Buffer.concat([Buffer.from('v1'), data]));
    } else {
      return this.newHash(Buffer.concat([Buffer.from('v2'), data]));
    }
  }

  // Verify hash with version detection
  verifyHash(data: Buffer, hash: Buffer): boolean {
    // Try new version first
    const v2Hash = this.hashWithVersion(data, 'v2');
    if (constantTimeEqual(hash, v2Hash)) return true;

    // Fall back to old version if before transition
    if (Date.now() < this.transitionDate) {
      const v1Hash = this.hashWithVersion(data, 'v1');
      return constantTimeEqual(hash, v1Hash);
    }

    return false;
  }

  // Migrate stored hashes
  async migrateHashes(storage: HashStorage): Promise<void> {
    await storage.updateAll(async (record) => {
      const oldHash = record.hash;
      const newHash = this.hashWithVersion(record.data, 'v2');

      // Store both during transition
      record.hash = newHash;
      record.legacyHash = oldHash;
      record.version = 'v2';

      return record;
    });
  }
}
```

### 4.3 ZK Proof System Migration

**Challenge**: Cannot easily migrate existing proofs

**Strategy**: Version-based circuit deployment

```typescript
interface CircuitVersion {
  version: string;
  circuit: Circuit;
  provingKey: ProvingKey;
  verificationKey: VerificationKey;
  validFrom: number;
  validUntil: number | null;
}

class ZKSystemMigrator {
  private circuits: Map<string, CircuitVersion[]> = new Map();

  registerCircuitVersion(
    claimType: ClaimType,
    version: CircuitVersion
  ): void {
    if (!this.circuits.has(claimType)) {
      this.circuits.set(claimType, []);
    }

    this.circuits.get(claimType)!.push(version);
  }

  generateProof(
    claimType: ClaimType,
    witness: Witness
  ): VersionedProof {
    // Use latest circuit version
    const versions = this.circuits.get(claimType)!;
    const latest = versions
      .filter(v => v.validFrom <= Date.now())
      .sort((a, b) => b.validFrom - a.validFrom)[0];

    const proof = groth16.prove(
      latest.provingKey,
      witness
    );

    return {
      version: latest.version,
      proof,
      claimType
    };
  }

  verifyProof(versionedProof: VersionedProof): boolean {
    const version = this.circuits
      .get(versionedProof.claimType)!
      .find(v => v.version === versionedProof.version);

    if (!version) {
      throw new Error(`Unknown circuit version: ${versionedProof.version}`);
    }

    // Check if version is still valid
    if (version.validUntil && Date.now() > version.validUntil) {
      throw new Error(`Circuit version expired: ${versionedProof.version}`);
    }

    return groth16.verify(
      version.verificationKey,
      versionedProof.proof.publicSignals,
      versionedProof.proof
    );
  }

  // Trigger re-proving with new circuit
  async migrateProofs(identityId: string): Promise<void> {
    const credentials = await getCredentials(identityId);

    for (const credential of credentials) {
      // User must re-prove with new circuit
      await notifyUser({
        identityId,
        message: 'Please re-generate proofs with updated circuit',
        credentialId: credential.id,
        deadline: Date.now() + 90 * 24 * 60 * 60 * 1000 // 90 days
      });
    }
  }
}
```

---

## 5. Compatibility Management

### 5.1 Version Negotiation

```typescript
interface VersionNegotiation {
  supportedVersions: string[];
  preferredVersion: string;
}

function negotiateVersion(
  client: VersionNegotiation,
  server: VersionNegotiation
): string | null {
  // Find intersection of supported versions
  const commonVersions = client.supportedVersions
    .filter(v => server.supportedVersions.includes(v));

  if (commonVersions.length === 0) {
    return null; // No compatible version
  }

  // Prefer newest version
  const sorted = commonVersions.sort((a, b) => {
    return compareVersions(b, a); // Descending
  });

  return sorted[0];
}

// Protocol handshake
async function protocolHandshake(
  client: Client,
  server: Server
): Promise<ProtocolVersion> {
  const clientNegotiation: VersionNegotiation = {
    supportedVersions: ['v2.1', 'v2.0', 'v1.9'],
    preferredVersion: 'v2.1'
  };

  const serverResponse = await server.negotiate(clientNegotiation);

  const agreedVersion = negotiateVersion(
    clientNegotiation,
    serverResponse
  );

  if (!agreedVersion) {
    throw new Error('No compatible protocol version');
  }

  return {
    version: agreedVersion,
    features: getFeatures(agreedVersion)
  };
}
```

### 5.2 Feature Flags

```typescript
interface FeatureFlags {
  enableNewSignatureAlgorithm: boolean;
  enableDualHashSupport: boolean;
  enforceNewCircuitVersions: boolean;
  allowLegacyProofs: boolean;
}

class FeatureFlagManager {
  private flags: Map<string, FeatureFlag> = new Map();

  setFlag(name: string, config: FeatureFlagConfig): void {
    this.flags.set(name, {
      name,
      enabled: config.enabled,
      rolloutPercentage: config.rolloutPercentage || 100,
      validFrom: config.validFrom || Date.now(),
      validUntil: config.validUntil
    });
  }

  isEnabled(name: string, context?: Record<string, any>): boolean {
    const flag = this.flags.get(name);
    if (!flag) return false;

    // Check time validity
    if (Date.now() < flag.validFrom) return false;
    if (flag.validUntil && Date.now() > flag.validUntil) return false;

    // Check rollout percentage
    if (context?.userId) {
      const hash = sha256(flag.name + context.userId);
      const percentage = parseInt(hash.slice(0, 8), 16) % 100;
      if (percentage >= flag.rolloutPercentage) return false;
    }

    return flag.enabled;
  }

  // Gradual rollout
  async rolloutGradually(
    name: string,
    startPercentage: number,
    endPercentage: number,
    durationDays: number
  ): Promise<void> {
    const stepSize = (endPercentage - startPercentage) / durationDays;
    let currentPercentage = startPercentage;

    for (let day = 0; day < durationDays; day++) {
      currentPercentage += stepSize;

      this.setFlag(name, {
        enabled: true,
        rolloutPercentage: currentPercentage
      });

      await sleep(24 * 60 * 60 * 1000); // 1 day

      // Monitor for issues
      const metrics = await getMetrics(name);
      if (metrics.errorRate > THRESHOLD) {
        // Rollback
        this.setFlag(name, { enabled: false });
        throw new Error('Rollout halted due to errors');
      }
    }
  }
}
```

---

## 6. Emergency Procedures

### 6.1 Algorithm Compromise Response

```yaml
Emergency Response Plan:

T+0 (Immediate):
  Actions:
    - Disable compromised algorithm
    - Block new usage
    - Alert security team
    - Activate incident response

  Responsibilities:
    - On-call engineer: Disable algorithm
    - Security lead: Assess impact
    - Communications: Draft announcement

T+1 hour:
  Actions:
    - Deploy emergency patch
    - Enable replacement algorithm
    - Notify all users
    - Begin damage assessment

  Responsibilities:
    - Engineering: Deploy patch
    - Security: Impact analysis
    - Communications: Send alerts

T+4 hours:
  Actions:
    - Force migration to new algorithm
    - Revoke affected credentials
    - Update documentation
    - Hold stakeholder call

  Responsibilities:
    - Engineering: Migration tools
    - Security: Credential review
    - Support: User assistance

T+24 hours:
  Actions:
    - Complete migration
    - Verify system integrity
    - Post-mortem begins
    - Public report drafted

T+7 days:
  Actions:
    - Remove compromised algorithm
    - Publish post-mortem
    - Implement preventive measures
    - Update security procedures
```

### 6.2 Rollback Procedures

```typescript
interface RollbackPlan {
  trigger: RollbackTrigger;
  steps: RollbackStep[];
  validation: ValidationCriteria;
}

enum RollbackTrigger {
  ERROR_RATE_HIGH,
  SECURITY_ISSUE,
  COMPATIBILITY_FAILURE,
  MANUAL_OVERRIDE
}

async function executeRollback(
  migration: Migration,
  reason: RollbackTrigger
): Promise<void> {
  // 1. Immediate: Stop migration
  await migration.pause();

  // 2. Revert to previous state
  await revertToSnapshot({
    timestamp: migration.startTime,
    components: migration.affectedComponents
  });

  // 3. Re-enable old algorithm
  await enableAlgorithm({
    algorithm: migration.oldAlgorithm,
    status: 'current',
    emergency: true
  });

  // 4. Notify stakeholders
  await notifyRollback({
    migration: migration.id,
    reason,
    status: 'rolled_back',
    nextSteps: 'Investigation ongoing'
  });

  // 5. Post-rollback verification
  const verification = await verifySystemState();
  if (!verification.healthy) {
    await escalateToEmergencyTeam();
  }
}
```

---

## Appendix A: Supported Algorithms

```yaml
Current Algorithms (as of 2026-02-23):

Signatures:
  - ECDSA (secp256k1): Current
  - EdDSA (Ed25519): Current
  - BLS (BLS12-381): Candidate

Hashes:
  - SHA-256: Current
  - SHA-3 (Keccak-256): Current
  - Poseidon: Current (ZK-specific)

ZK Proof Systems:
  - Groth16: Current
  - PLONK: Candidate
  - STARKs: Research

Post-Quantum Candidates:
  - Dilithium (signatures): Candidate
  - Kyber (key agreement): Candidate
  - SPHINCS+ (signatures): Research
```

---

**Document Version**: 1.0
**Last Review**: 2026-02-23
**Next Review**: 2026-05-23
