# DICPS Protocol Specifications
**Version:** 1.0
**Last Updated:** 2026-02-23

---

## Table of Contents

1. [Overview](#1-overview)
2. [Core Protocols](#2-core-protocols)
3. [Message Formats](#3-message-formats)
4. [State Machines](#4-state-machines)
5. [Error Codes](#5-error-codes)
6. [Security Protocols](#6-security-protocols)

---

## 1. Overview

This document specifies all protocols used in the Digital Identity Capability Proof Service, including message formats, state transitions, and error handling.

---

## 2. Core Protocols

### 2.1 Identity Registration Protocol (IRP)

**Protocol Identifier:** `DICPS-IRP-v1.0`

**Purpose:** Register a new identity in the system

#### 2.1.1 Message Flow

```
Client                          Server
  |                               |
  |----(1) IDENTITY_REG_REQ------>|
  |                               |
  |                               |----(2) Validate
  |                               |       Public Key
  |                               |
  |                               |----(3) Generate
  |                               |       Identity ID
  |                               |
  |                               |----(4) Store
  |                               |       Identity
  |                               |
  |<---(5) IDENTITY_REG_RESP------|
  |                               |
```

#### 2.1.2 Request Format

```typescript
interface IdentityRegistrationRequest {
  version: '1.0';
  timestamp: number;
  publicKey: string;
  attributes: Array<{
    name: string;
    value: string | number | boolean;
    timestamp: number;
  }>;
  nonce: string;
}
```

**Validation Rules:**
- `version` MUST be '1.0'
- `timestamp` MUST be within ±300 seconds of server time
- `publicKey` MUST be valid base64-encoded key (256+ bits)
- `attributes` MUST contain at least one element
- `nonce` MUST be unique per request (prevents replay)

#### 2.1.3 Response Format

```typescript
interface IdentityRegistrationResponse {
  version: '1.0';
  success: boolean;
  identity?: {
    id: string;
    publicKey: string;
    attributes: Attribute[];
    createdAt: number;
  };
  error?: {
    code: string;
    message: string;
    details?: any;
  };
}
```

#### 2.1.4 State Transitions

```
[START] → VALIDATING → GENERATING_ID → STORING → [SUCCESS]
             ↓              ↓             ↓
           [FAIL]         [FAIL]        [FAIL]
```

#### 2.1.5 Error Codes

- `IRP-001`: Invalid public key format
- `IRP-002`: Duplicate public key
- `IRP-003`: Invalid attributes
- `IRP-004`: Timestamp out of range
- `IRP-005`: Duplicate nonce (replay attack)
- `IRP-006`: Storage failure

---

### 2.2 Credential Issuance Protocol (CIP)

**Protocol Identifier:** `DICPS-CIP-v1.0`

**Purpose:** Issue a verifiable credential to an identity

#### 2.2.1 Message Flow

```
Client                          Server
  |                               |
  |----(1) CREDENTIAL_ISS_REQ---->|
  |                               |
  |                               |----(2) Verify
  |                               |       Identity
  |                               |
  |                               |----(3) Sign
  |                               |       Credential
  |                               |
  |                               |----(4) Store
  |                               |       Credential
  |                               |
  |<---(5) CREDENTIAL_ISS_RESP----|
  |                               |
```

#### 2.2.2 Request Format

```typescript
interface CredentialIssuanceRequest {
  version: '1.0';
  timestamp: number;
  identityId: string;
  attributes: Attribute[];
  expiresAt?: number;
  requestSignature: string; // Signed by identity's private key
}
```

**Validation Rules:**
- `identityId` MUST exist in registry
- `attributes` MUST be non-empty
- `expiresAt` if present MUST be > current time
- `requestSignature` MUST verify against identity's public key

#### 2.2.3 Response Format

```typescript
interface CredentialIssuanceResponse {
  version: '1.0';
  success: boolean;
  credential?: {
    id: string;
    identityId: string;
    issuer: string;
    attributes: Attribute[];
    signature: string;
    issuedAt: number;
    expiresAt?: number;
  };
  error?: ErrorResponse;
}
```

#### 2.2.4 Signature Algorithm

```
signature = ECDSA_Sign(
  SHA256(
    identityId ||
    JSON.stringify(attributes) ||
    issuer ||
    issuedAt
  ),
  issuerPrivateKey
)
```

---

### 2.3 Zero-Knowledge Proof Generation Protocol (ZKPGP)

**Protocol Identifier:** `DICPS-ZKPGP-v1.0`

**Purpose:** Generate a zero-knowledge proof for a claim

#### 2.3.1 Message Flow

```
Client                          Server
  |                               |
  |----(1) PROOF_GEN_REQ--------->|
  | {claim, privateData}          |
  |                               |
  |                               |----(2) Prepare
  |                               |       Circuit Inputs
  |                               |
  |                               |----(3) Compute
  |                               |       Witness
  |                               |
  |                               |----(4) Generate
  |                               |       Proof
  |                               |
  |<---(5) PROOF_GEN_RESP---------|
  | {proof, publicSignals}        |
  |                               |
```

#### 2.3.2 Request Format

```typescript
interface ProofGenerationRequest {
  version: '1.0';
  timestamp: number;
  claim: {
    type: ClaimType;
    parameters: Record<string, any>;
  };
  privateData: Record<string, any>;
  salt: number;
}
```

**Claim-Specific Private Data:**

For `AGE_OVER`:
```typescript
{
  age: number;           // Actual age
  salt: number;          // Random salt for privacy
}
```

For `LICENSE_VALID`:
```typescript
{
  licenseType: string;   // License type
  expirationDate: number; // Expiration timestamp
  salt: number;
}
```

For `CLEARANCE_LEVEL`:
```typescript
{
  clearanceLevel: number; // Actual clearance (0-5)
  salt: number;
}
```

For `ROLE_AUTHORIZATION`:
```typescript
{
  role: string;          // Actual role
  salt: number;
}
```

#### 2.3.3 Response Format

```typescript
interface ProofGenerationResponse {
  version: '1.0';
  success: boolean;
  proof?: {
    proof: {
      pi_a: string[];
      pi_b: string[][];
      pi_c: string[];
      protocol: 'groth16';
      curve: 'bn128';
    };
    publicSignals: string[];
    statement: string;
  };
  error?: ErrorResponse;
}
```

#### 2.3.4 Circuit Input Preparation

For each claim type:

**AGE_OVER Circuit:**
```
Inputs:
  - age (private)
  - threshold (public)
  - salt (private)

Outputs:
  - ageHash = Poseidon(age, salt)
  - isOver = (age >= threshold) ? 1 : 0

Public Signals: [ageHash, isOver]
```

**LICENSE_VALID Circuit:**
```
Inputs:
  - licenseType (private)
  - requiredLicenseType (public)
  - expirationDate (private)
  - currentDate (public)
  - salt (private)

Outputs:
  - licenseHash = Poseidon(licenseType, expirationDate, salt)
  - isValid = (licenseType == requiredLicenseType &&
               expirationDate > currentDate) ? 1 : 0

Public Signals: [licenseHash, isValid]
```

---

### 2.4 Proof Verification Protocol (PVP)

**Protocol Identifier:** `DICPS-PVP-v1.0`

**Purpose:** Verify a zero-knowledge proof

#### 2.4.1 Message Flow

```
Client                          Server
  |                               |
  |----(1) PROOF_VER_REQ--------->|
  | {proof}                       |
  |                               |
  |                               |----(2) Validate
  |                               |       Structure
  |                               |
  |                               |----(3) Verify
  |                               |       Crypto
  |                               |
  |                               |----(4) Extract
  |                               |       Result
  |                               |
  |<---(5) PROOF_VER_RESP---------|
  | {valid, statement}            |
  |                               |
```

#### 2.4.2 Request Format

```typescript
interface ProofVerificationRequest {
  version: '1.0';
  timestamp: number;
  proof: {
    proof: ProofData;
    publicSignals: string[];
    statement: string;
  };
}
```

#### 2.4.3 Response Format

```typescript
interface ProofVerificationResponse {
  version: '1.0';
  success: boolean;
  result?: {
    valid: boolean;
    statement: string;
    timestamp: number;
    verifiedBy: string;
  };
  error?: ErrorResponse;
}
```

#### 2.4.4 Verification Steps

1. **Structure Validation**
   - Verify proof has all required fields
   - Check publicSignals array length matches circuit
   - Validate statement format

2. **Cryptographic Verification**
   - Load verification key for claim type
   - Execute snarkjs.groth16.verify()
   - Check pairing equations

3. **Result Extraction**
   - Extract claim result from last public signal
   - Map 1→true, 0→false

4. **Response Construction**
   - Build verification result
   - Include timestamp and verifier identity

---

### 2.5 Credential Revocation Protocol (CRP)

**Protocol Identifier:** `DICPS-CRP-v1.0`

**Purpose:** Revoke a credential

#### 2.5.1 Message Flow

```
Client                          Server
  |                               |
  |----(1) REVOCATION_REQ-------->|
  |                               |
  |                               |----(2) Verify
  |                               |       Authority
  |                               |
  |                               |----(3) Create
  |                               |       Record
  |                               |
  |                               |----(4) Update
  |                               |       Merkle Tree
  |                               |
  |<---(5) REVOCATION_RESP--------|
  |                               |
```

#### 2.5.2 Request Format

```typescript
interface RevocationRequest {
  version: '1.0';
  timestamp: number;
  credentialId: string;
  reason?: string;
  authoritySignature: string; // Signed by authorized party
}
```

#### 2.5.3 Response Format

```typescript
interface RevocationResponse {
  version: '1.0';
  success: boolean;
  record?: {
    credentialId: string;
    revokedAt: number;
    reason?: string;
    merkleRoot: string; // New Merkle root after revocation
  };
  error?: ErrorResponse;
}
```

---

## 3. Message Formats

### 3.1 Standard Message Envelope

All messages MUST use this envelope:

```typescript
interface MessageEnvelope<T> {
  version: string;        // Protocol version
  messageId: string;      // Unique message ID
  timestamp: number;      // Unix timestamp (milliseconds)
  sender: string;         // Sender identifier
  recipient?: string;     // Optional recipient
  payload: T;             // Actual message content
  signature?: string;     // Optional message signature
}
```

### 3.2 Error Response Format

```typescript
interface ErrorResponse {
  code: string;           // Error code (e.g., "IRP-001")
  message: string;        // Human-readable message
  details?: any;          // Additional error details
  timestamp: number;      // When error occurred
  requestId: string;      // Original request ID
}
```

### 3.3 Pagination Format

For list operations:

```typescript
interface PaginatedRequest {
  page: number;           // Page number (1-indexed)
  pageSize: number;       // Items per page (max 100)
  sortBy?: string;        // Field to sort by
  sortOrder?: 'asc' | 'desc';
}

interface PaginatedResponse<T> {
  items: T[];
  pagination: {
    page: number;
    pageSize: number;
    totalItems: number;
    totalPages: number;
    hasNext: boolean;
    hasPrevious: boolean;
  };
}
```

---

## 4. State Machines

### 4.1 Identity Lifecycle

```
[CREATED] → [ACTIVE] → [SUSPENDED] → [ACTIVE]
              ↓
          [ARCHIVED]
```

**States:**
- `CREATED`: Initial state after registration
- `ACTIVE`: Identity can issue/verify credentials
- `SUSPENDED`: Temporarily disabled
- `ARCHIVED`: Permanently disabled

**Transitions:**
- `activate`: CREATED → ACTIVE
- `suspend`: ACTIVE → SUSPENDED
- `reactivate`: SUSPENDED → ACTIVE
- `archive`: ACTIVE | SUSPENDED → ARCHIVED

### 4.2 Credential Lifecycle

```
[ISSUED] → [ACTIVE] → [EXPIRED]
             ↓
         [REVOKED]
```

**States:**
- `ISSUED`: Created but not yet active
- `ACTIVE`: Valid and usable
- `EXPIRED`: Passed expiration date
- `REVOKED`: Explicitly revoked

**Transitions:**
- `activate`: ISSUED → ACTIVE
- `expire`: ACTIVE → EXPIRED (automatic at expiresAt)
- `revoke`: ACTIVE → REVOKED

### 4.3 Proof Lifecycle

```
[GENERATED] → [VERIFIED] → [CONSUMED]
                ↓
            [REJECTED]
```

**States:**
- `GENERATED`: Proof created
- `VERIFIED`: Proof passed verification
- `REJECTED`: Proof failed verification
- `CONSUMED`: Proof used (one-time use)

---

## 5. Error Codes

### 5.1 Identity Registration (IRP-xxx)

| Code    | Description                    | HTTP Status |
|---------|--------------------------------|-------------|
| IRP-001 | Invalid public key format      | 400         |
| IRP-002 | Duplicate public key           | 409         |
| IRP-003 | Invalid attributes             | 400         |
| IRP-004 | Timestamp out of range         | 400         |
| IRP-005 | Duplicate nonce                | 400         |
| IRP-006 | Storage failure                | 500         |

### 5.2 Credential Issuance (CIP-xxx)

| Code    | Description                    | HTTP Status |
|---------|--------------------------------|-------------|
| CIP-001 | Identity not found             | 404         |
| CIP-002 | Invalid signature              | 401         |
| CIP-003 | Invalid expiration             | 400         |
| CIP-004 | Signing failed                 | 500         |
| CIP-005 | Storage failure                | 500         |

### 5.3 Proof Generation (ZKPGP-xxx)

| Code       | Description                 | HTTP Status |
|------------|-----------------------------|-------------|
| ZKPGP-001  | Unsupported claim type      | 400         |
| ZKPGP-002  | Invalid private data        | 400         |
| ZKPGP-003  | Circuit not initialized     | 500         |
| ZKPGP-004  | Witness computation failed  | 500         |
| ZKPGP-005  | Proof generation failed     | 500         |

### 5.4 Proof Verification (PVP-xxx)

| Code    | Description                    | HTTP Status |
|---------|--------------------------------|-------------|
| PVP-001 | Invalid proof structure        | 400         |
| PVP-002 | Invalid public signals         | 400         |
| PVP-003 | Verification key not found     | 404         |
| PVP-004 | Cryptographic verification failed | 200*     |

*Note: Verification failure returns 200 with valid=false

### 5.5 Revocation (CRP-xxx)

| Code    | Description                    | HTTP Status |
|---------|--------------------------------|-------------|
| CRP-001 | Credential not found           | 404         |
| CRP-002 | Already revoked                | 409         |
| CRP-003 | Unauthorized                   | 403         |
| CRP-004 | Merkle update failed           | 500         |

---

## 6. Security Protocols

### 6.1 Authentication Protocol

**Protocol:** OAuth 2.0 / Bearer Token

```
Client                          Server
  |                               |
  |----(1) POST /auth/token------>|
  | {credentials}                 |
  |                               |
  |<---(2) {token, expiresAt}-----|
  |                               |
  |----(3) GET /api/resource----->|
  | Authorization: Bearer {token} |
  |                               |
  |<---(4) {resource}-------------|
  |                               |
```

### 6.2 Message Signing Protocol

All sensitive requests MUST be signed:

```typescript
signature = ECDSA_Sign(
  SHA256(
    messageId ||
    timestamp ||
    JSON.stringify(payload)
  ),
  senderPrivateKey
)
```

### 6.3 Replay Prevention

- All requests MUST include unique `nonce`
- Server MUST track nonces for 5 minutes
- Duplicate nonces MUST be rejected

### 6.4 Rate Limiting

```yaml
rate_limits:
  identity_registration:
    per_ip: 10/hour
    per_user: 100/day

  credential_issuance:
    per_identity: 50/hour
    per_issuer: 1000/hour

  proof_generation:
    per_client: 100/minute
    per_ip: 500/minute

  proof_verification:
    per_client: 200/minute
    per_ip: 1000/minute
```

---

## Appendix A: Protocol Versioning

### Version Format

```
{major}.{minor}

major: Breaking changes
minor: Backward-compatible changes
```

### Version Negotiation

```typescript
interface VersionNegotiationRequest {
  supportedVersions: string[];
}

interface VersionNegotiationResponse {
  selectedVersion: string;
  serverVersions: string[];
}
```

---

## Appendix B: Test Vectors

### B.1 Identity Registration

**Input:**
```json
{
  "version": "1.0",
  "timestamp": 1708685742064,
  "publicKey": "0x04a1b2c3d4...",
  "attributes": [
    {"name": "age", "value": 25, "timestamp": 1708685742064}
  ],
  "nonce": "abc123"
}
```

**Expected Output:**
```json
{
  "version": "1.0",
  "success": true,
  "identity": {
    "id": "id_...",
    "publicKey": "0x04a1b2c3d4...",
    "attributes": [...],
    "createdAt": 1708685742064
  }
}
```

### B.2 Proof Generation (Age Over 18)

**Input:**
```json
{
  "claim": {
    "type": "AGE_OVER",
    "parameters": {"threshold": 18}
  },
  "privateData": {
    "age": 25,
    "salt": 12345
  }
}
```

**Expected Public Signals:**
```json
[
  "1234567890...",  // ageHash
  "1"               // isOver (1 = true)
]
```

---

**Document Version:** 1.0
**Effective Date:** 2026-02-23
**Review Date:** 2026-03-23
