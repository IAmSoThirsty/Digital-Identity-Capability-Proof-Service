/**
 * Digital Identity Capability Proof Service
 * Production-grade privacy-preserving attribute verification using zero-knowledge proofs
 */

export { IdentityRegistry } from './IdentityRegistry';
export { CredentialIssuer } from './CredentialIssuer';
export { ZKCircuitEngine } from './ZKCircuitEngine';
export { CircuitKeys } from './CircuitKeys';
export { ProofGenerator } from './ProofGenerator';
export { ProofVerifier } from './ProofVerifier';
export { RevocationRegistry } from './RevocationRegistry';

// Export security modules
export * from './security';
export * from './errors/SystemErrors';
export { SparseMerkleTree, MerkleProof, SparseMerkleTreeState } from './crypto/SparseMerkleTree';

export {
  Identity,
  Attribute,
  Credential,
  Proof,
  VerificationResult,
  RevocationRecord,
  ClaimType,
  ClaimStatement
} from './types';

// Main service class that combines all components
import { IdentityRegistry } from './IdentityRegistry';
import { CredentialIssuer } from './CredentialIssuer';
import { ProofGenerator } from './ProofGenerator';
import { ProofVerifier } from './ProofVerifier';
import { RevocationRegistry } from './RevocationRegistry';
import { ClaimStatement, Attribute, Credential, Proof, VerificationResult } from './types';
import { NotFoundError, ValidationError } from './errors/SystemErrors';
import { InputValidator } from './security/InputValidator';

/**
 * Production-grade Digital Identity Proof Service
 * Orchestrates all components with comprehensive validation
 */
export class DigitalIdentityProofService {
  private identityRegistry: IdentityRegistry;
  private credentialIssuer: CredentialIssuer;
  private proofGenerator: ProofGenerator;
  private proofVerifier: ProofVerifier;
  private revocationRegistry: RevocationRegistry;

  constructor(issuerName: string = 'Default Issuer') {
    // Validate issuer name
    if (!issuerName || typeof issuerName !== 'string' || issuerName.length > 100) {
      throw new ValidationError('Invalid issuer name');
    }

    this.identityRegistry = new IdentityRegistry();
    this.credentialIssuer = new CredentialIssuer(issuerName);
    this.proofGenerator = new ProofGenerator();
    this.proofVerifier = new ProofVerifier();
    this.revocationRegistry = new RevocationRegistry();
  }

  /**
   * Register a new identity with validation
   */
  registerIdentity(publicKey: string, attributes: Attribute[]) {
    return this.identityRegistry.registerIdentity(publicKey, attributes);
  }

  /**
   * Issue a credential with validation
   */
  issueCredential(identityId: string, attributes: Attribute[], expiresAt?: number) {
    // Validate identity exists
    InputValidator.validateIdentityId(identityId);

    if (!this.identityRegistry.hasIdentity(identityId)) {
      throw new NotFoundError('Identity', identityId);
    }

    return this.credentialIssuer.issueCredential(identityId, attributes, expiresAt);
  }

  /**
   * Generate a proof for a claim
   */
  async generateProof(claim: ClaimStatement, privateData: Record<string, any>): Promise<Proof> {
    return this.proofGenerator.generateProof(claim, privateData);
  }

  /**
   * Verify a proof
   */
  async verifyProof(proof: Proof): Promise<VerificationResult> {
    return this.proofVerifier.verifyProof(proof);
  }

  /**
   * Revoke a credential
   */
  revokeCredential(credentialId: string, reason?: string) {
    return this.revocationRegistry.revokeCredential(credentialId, reason);
  }

  /**
   * Check if a credential is revoked
   */
  isCredentialRevoked(credentialId: string): boolean {
    return this.revocationRegistry.isRevoked(credentialId);
  }

  /**
   * Get the identity registry
   */
  getIdentityRegistry(): IdentityRegistry {
    return this.identityRegistry;
  }

  /**
   * Get the credential issuer
   */
  getCredentialIssuer(): CredentialIssuer {
    return this.credentialIssuer;
  }

  /**
   * Get the proof generator
   */
  getProofGenerator(): ProofGenerator {
    return this.proofGenerator;
  }

  /**
   * Get the proof verifier
   */
  getProofVerifier(): ProofVerifier {
    return this.proofVerifier;
  }

  /**
   * Get the revocation registry
   */
  getRevocationRegistry(): RevocationRegistry {
    return this.revocationRegistry;
  }
}
