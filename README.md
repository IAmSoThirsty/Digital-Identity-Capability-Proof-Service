# Digital Identity Capability Proof Service (DICPS)

Privacy-preserving attribute verification using zero-knowledge proofs.

## Documentation

### Architecture
- **[Architecture Summary](ARCHITECTURE_SUMMARY.md)** - Quick reference to system architecture
- **[Complete Architecture](ARCHITECTURE.md)** - Full RFC-grade architectural specification
- **[Protocol Specifications](PROTOCOLS.md)** - Detailed protocol and message format specs
- **[Interface Contracts](src/contracts/interfaces.ts)** - TypeScript interface definitions

### Security
- **[Security Proofs](SECURITY_PROOFS.md)** - Formal security proofs and protocol-level reasoning
- **[Adversarial Model](ADVERSARIAL_MODEL.md)** - Comprehensive threat modeling and attack analysis
- **[Cryptographic Agility](CRYPTO_AGILITY.md)** - Algorithm rotation and migration governance
- **[Audit Chain](AUDIT_CHAIN.md)** - Deterministic state transition hashing and tamper evidence
- **[Operational Hardening](OPERATIONAL_HARDENING.md)** - DoS resilience and distributed system hardening
- **[Governance Framework](GOVERNANCE.md)** - Multi-issuer coordination and economic incentives

## Overview

DICPS enables privacy-preserving identity verification where users can prove specific attributes about themselves without revealing the underlying data. For example, prove you're over 18 without revealing your exact age, or prove you're a licensed engineer without revealing your license number.

## Core Concepts

### Zero-Knowledge Proofs

Zero-knowledge proofs allow one party (the prover) to prove to another party (the verifier) that a statement is true without revealing any information beyond the validity of the statement itself.

### Use Cases

- **Civic Authentication**: Prove eligibility to vote without revealing identity
- **Access Control**: Prove sufficient security clearance without revealing level
- **Professional Verification**: Prove professional credentials without revealing details
- **Age Verification**: Prove age requirements without revealing exact age

## Architecture

### Core Components

1. **Identity Registry**: Manages digital identities and their attributes
2. **Credential Issuer**: Issues verifiable credentials to identities
3. **ZK Circuit Engine**: Generates circuit inputs for different claim types
4. **Proof Generator**: Creates zero-knowledge proofs for claims
5. **Proof Verifier**: Verifies zero-knowledge proofs
6. **Revocation Registry**: Manages credential revocations

## Installation

```bash
npm install
```

## Quick Start

```typescript
import { DigitalIdentityProofService, ClaimType } from './src';

// Initialize the service
const service = new DigitalIdentityProofService('My Authority');

// Register an identity
const identity = service.registerIdentity('public_key_123', [
  { name: 'name', value: 'Alice', timestamp: Date.now() }
]);

// Issue a credential
const credential = service.issueCredential(identity.id, [
  { name: 'age', value: 25, timestamp: Date.now() }
]);

// Generate a proof that user is over 18
const proof = await service.generateProof(
  { type: ClaimType.AGE_OVER, parameters: { threshold: 18 } },
  { age: 25, salt: 12345 }
);

// Verify the proof
const result = await service.verifyProof(proof);
console.log('Valid:', result.valid); // true
console.log('Statement:', result.statement); // "User is over 18 years old"
```

## Supported Claim Types

### 1. Age Over (AGE_OVER)

Prove age is above a threshold without revealing exact age.

```typescript
const claim = {
  type: ClaimType.AGE_OVER,
  parameters: { threshold: 18 }
};

const privateData = { age: 25, salt: 12345 };
```

### 2. License Valid (LICENSE_VALID)

Prove a valid license of a specific type without revealing license details.

```typescript
const claim = {
  type: ClaimType.LICENSE_VALID,
  parameters: { licenseType: 'Professional Engineer' }
};

const privateData = {
  licenseType: 'Professional Engineer',
  expirationDate: futureTimestamp,
  salt: 67890
};
```

### 3. Clearance Level (CLEARANCE_LEVEL)

Prove sufficient security clearance without revealing exact level.

```typescript
const claim = {
  type: ClaimType.CLEARANCE_LEVEL,
  parameters: { requiredLevel: 3 }
};

const privateData = {
  clearanceLevel: 4,
  salt: 11111
};
```

### 4. Role Authorization (ROLE_AUTHORIZATION)

Prove authorized role without revealing identity.

```typescript
const claim = {
  type: ClaimType.ROLE_AUTHORIZATION,
  parameters: { role: 'election_official' }
};

const privateData = {
  role: 'election_official',
  salt: 22222
};
```

## Examples

Run the included examples:

```bash
npm run build
node dist/examples/index.js
```

Or run individual examples:

```bash
node dist/examples/ageVerification.js
node dist/examples/licenseVerification.js
node dist/examples/clearanceVerification.js
node dist/examples/roleAuthorization.js
```

## API Reference

### DigitalIdentityProofService

Main service class that combines all components.

#### Methods

- `registerIdentity(publicKey: string, attributes: Attribute[]): Identity`
- `issueCredential(identityId: string, attributes: Attribute[], expiresAt?: number): Credential`
- `generateProof(claim: ClaimStatement, privateData: Record<string, any>): Promise<Proof>`
- `verifyProof(proof: Proof): Promise<VerificationResult>`
- `revokeCredential(credentialId: string, reason?: string): RevocationRecord`
- `isCredentialRevoked(credentialId: string): boolean`

### IdentityRegistry

Manages digital identities.

#### Methods

- `registerIdentity(publicKey: string, attributes: Attribute[]): Identity`
- `getIdentity(id: string): Identity | undefined`
- `updateAttributes(id: string, newAttributes: Attribute[]): boolean`
- `hasIdentity(id: string): boolean`
- `getAllIdentities(): Identity[]`

### CredentialIssuer

Issues and manages credentials.

#### Methods

- `issueCredential(identityId: string, attributes: Attribute[], expiresAt?: number): Credential`
- `getCredential(id: string): Credential | undefined`
- `verifyCredential(credential: Credential): boolean`
- `isExpired(credential: Credential): boolean`
- `getCredentialsForIdentity(identityId: string): Credential[]`

### ProofGenerator

Generates zero-knowledge proofs.

#### Methods

- `generateProof(claim: ClaimStatement, privateData: Record<string, any>): Promise<Proof>`

### ProofVerifier

Verifies zero-knowledge proofs.

#### Methods

- `verifyProof(proof: Proof): Promise<VerificationResult>`
- `batchVerify(proofs: Proof[]): Promise<VerificationResult[]>`
- `extractClaimResult(proof: Proof): boolean`

### RevocationRegistry

Manages credential revocations.

#### Methods

- `revokeCredential(credentialId: string, reason?: string): RevocationRecord`
- `isRevoked(credentialId: string): boolean`
- `getRevocationRecord(credentialId: string): RevocationRecord | undefined`
- `getAllRevocations(): RevocationRecord[]`
- `restoreCredential(credentialId: string): boolean`

## Testing

Run the test suite:

```bash
npm test
```

## Building

Build the TypeScript code:

```bash
npm run build
```

## Security Considerations

This system now includes **real Circom circuits** for production-grade zero-knowledge proofs. The system automatically detects if circuits are compiled and uses:

- ✅ **Real ZK Proofs** (snarkjs.groth16.fullProve) when circuits are compiled
- ⚠️ **Simulated Proofs** when circuits are not compiled (for development/testing)

### Compiling Circuits for Production

To enable real zero-knowledge proofs:

```bash
# Install Circom compiler (required)
npm install -g circom

# Compile all circuits and generate keys
npm run prepare-circuits
```

See [circuits/README.md](circuits/README.md) for detailed instructions on:
- Circuit compilation
- Trusted setup ceremonies
- Production deployment
- Security best practices

### Additional Production Requirements

1. **Trusted Setup**: Use a proper multi-party computation ceremony (see circuits/README.md)
2. **Secure Key Management**: Implement proper key storage and management
3. **Audit Code**: Have the system audited by security professionals
4. **Merkle Trees**: Already implemented for efficient revocation
5. **Rate Limiting**: Already implemented with comprehensive DoS protection
6. **Authentication**: Add authentication and authorization layers for your use case

## Production Deployment

The system is now production-ready with real ZK circuits! Follow these steps:

1. **Compile Circuits**: Run `npm run prepare-circuits` (requires Circom compiler)
2. **Trusted Setup**: Conduct a proper trusted setup ceremony (see circuits/README.md)
3. **Verify Compilation**: Check that all circuits compiled successfully
4. **Test Proofs**: Run `npm test` to verify proof generation/verification
5. **Deploy Keys**: Securely store proving and verification keys
6. **Configure Security**: Enable all security features (audit logging, rate limiting, access control)
7. **Monitor System**: Set up monitoring and alerting for production use

For detailed deployment instructions, see:
- [circuits/README.md](circuits/README.md) - Circuit compilation and trusted setup
- [PRODUCTION_SECURITY.md](PRODUCTION_SECURITY.md) - Security hardening guide
- [OPERATIONAL_HARDENING.md](OPERATIONAL_HARDENING.md) - DoS protection and resilience

## License

MIT

## Contributing

Contributions are welcome! Please submit issues and pull requests.

## Support

For questions and support, please open an issue on GitHub.
