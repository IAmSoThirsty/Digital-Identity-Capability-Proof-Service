import { Credential, Attribute } from './types';
import { randomBytes, createHash } from 'crypto';

/**
 * Credential Issuer
 * Issues verifiable credentials to identities
 */
export class CredentialIssuer {
  private issuerName: string;
  private issuerPrivateKey: string;
  private credentials: Map<string, Credential>;

  constructor(issuerName: string, issuerPrivateKey?: string) {
    this.issuerName = issuerName;
    this.issuerPrivateKey = issuerPrivateKey || this.generatePrivateKey();
    this.credentials = new Map();
  }

  /**
   * Issue a credential to an identity
   */
  issueCredential(
    identityId: string,
    attributes: Attribute[],
    expiresAt?: number
  ): Credential {
    const id = this.generateCredentialId();

    const credential: Credential = {
      id,
      identityId,
      issuer: this.issuerName,
      attributes,
      signature: this.signCredential(identityId, attributes),
      issuedAt: Date.now(),
      expiresAt
    };

    this.credentials.set(id, credential);
    return credential;
  }

  /**
   * Get a credential by ID
   */
  getCredential(id: string): Credential | undefined {
    return this.credentials.get(id);
  }

  /**
   * Verify a credential signature
   */
  verifyCredential(credential: Credential): boolean {
    const expectedSignature = this.signCredential(
      credential.identityId,
      credential.attributes
    );
    return credential.signature === expectedSignature;
  }

  /**
   * Check if a credential is expired
   */
  isExpired(credential: Credential): boolean {
    if (!credential.expiresAt) {
      return false;
    }
    return Date.now() > credential.expiresAt;
  }

  /**
   * Get all credentials for an identity
   */
  getCredentialsForIdentity(identityId: string): Credential[] {
    return Array.from(this.credentials.values()).filter(
      c => c.identityId === identityId
    );
  }

  /**
   * Generate a credential ID
   */
  private generateCredentialId(): string {
    return 'cred_' + randomBytes(16).toString('hex');
  }

  /**
   * Generate a private key
   */
  private generatePrivateKey(): string {
    return randomBytes(32).toString('hex');
  }

  /**
   * Sign a credential using a simple hash-based signature
   * In production, use proper cryptographic signatures (e.g., ECDSA)
   */
  private signCredential(identityId: string, attributes: Attribute[]): string {
    const data = JSON.stringify({ identityId, attributes });
    return createHash('sha256')
      .update(data + this.issuerPrivateKey)
      .digest('hex');
  }
}
