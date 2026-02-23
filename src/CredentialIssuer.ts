import { Credential, Attribute } from './types';
import { randomBytes } from 'crypto';
import { InputValidator } from './security/InputValidator';
import { CryptoUtils } from './security/CryptoUtils';
import { NotFoundError, CredentialError, ValidationError } from './errors/SystemErrors';

/**
 * Production-grade Credential Issuer
 * Issues verifiable credentials with cryptographic signatures
 */
export class CredentialIssuer {
  private issuerName: string;
  private issuerPrivateKey: Buffer;
  private credentials: Map<string, Credential>;
  private credentialIndex: Map<string, string[]>; // identityId -> credentialIds

  constructor(issuerName: string, issuerPrivateKey?: string) {
    // Validate issuer name
    if (!issuerName || issuerName.length > 100) {
      throw new ValidationError('Invalid issuer name');
    }
    this.issuerName = InputValidator.sanitizeString(issuerName, 100);

    // Initialize or validate private key
    if (issuerPrivateKey) {
      if (!/^[0-9a-f]{64}$/i.test(issuerPrivateKey)) {
        throw new ValidationError('Invalid private key format');
      }
      this.issuerPrivateKey = Buffer.from(issuerPrivateKey, 'hex');
    } else {
      this.issuerPrivateKey = CryptoUtils.generateSecureRandom(32);
    }

    this.credentials = new Map();
    this.credentialIndex = new Map();
  }

  /**
   * Issue a credential with comprehensive validation and cryptographic signature
   */
  issueCredential(
    identityId: string,
    attributes: Attribute[],
    expiresAt?: number
  ): Credential {
    // Validate inputs
    InputValidator.validateIdentityId(identityId);
    InputValidator.validateAttributes(attributes);

    if (expiresAt !== undefined) {
      InputValidator.validateExpiration(expiresAt);
    }

    const id = this.generateCredentialId();
    const issuedAt = Date.now();

    // Create credential data for signing
    const credentialData = {
      id,
      identityId,
      issuer: this.issuerName,
      attributes: this.normalizeAttributes(attributes),
      issuedAt,
      expiresAt
    };

    // Generate cryptographic signature
    const signature = this.signCredential(credentialData);

    const credential: Credential = {
      ...credentialData,
      signature
    };

    // Store credential
    this.credentials.set(id, credential);

    // Update index
    if (!this.credentialIndex.has(identityId)) {
      this.credentialIndex.set(identityId, []);
    }
    this.credentialIndex.get(identityId)!.push(id);

    return credential;
  }

  /**
   * Get a credential by ID with validation
   */
  getCredential(id: string): Credential | undefined {
    try {
      InputValidator.validateCredentialId(id);
    } catch {
      return undefined;
    }
    return this.credentials.get(id);
  }

  /**
   * Verify a credential signature using constant-time comparison
   */
  verifyCredential(credential: Credential): boolean {
    try {
      // Validate credential structure
      if (!credential.id || !credential.identityId || !credential.signature) {
        return false;
      }

      // Reconstruct credential data for verification
      const credentialData = {
        id: credential.id,
        identityId: credential.identityId,
        issuer: credential.issuer,
        attributes: this.normalizeAttributes(credential.attributes),
        issuedAt: credential.issuedAt,
        expiresAt: credential.expiresAt
      };

      // Compute expected signature
      const expectedSignature = this.signCredential(credentialData);

      // Constant-time comparison to prevent timing attacks
      return CryptoUtils.constantTimeEqual(credential.signature, expectedSignature);
    } catch {
      return false;
    }
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
   * Check if a credential is valid (signature + expiration)
   */
  isValid(credential: Credential): boolean {
    return this.verifyCredential(credential) && !this.isExpired(credential);
  }

  /**
   * Get all credentials for an identity with pagination
   */
  getCredentialsForIdentity(
    identityId: string,
    limit: number = 100,
    offset: number = 0
  ): Credential[] {
    try {
      InputValidator.validateIdentityId(identityId);
    } catch {
      return [];
    }

    // Validate pagination
    if (limit <= 0 || limit > 1000) {
      limit = 100;
    }
    if (offset < 0) {
      offset = 0;
    }

    const credentialIds = this.credentialIndex.get(identityId) || [];
    const paginatedIds = credentialIds.slice(offset, offset + limit);

    return paginatedIds
      .map(id => this.credentials.get(id))
      .filter((c): c is Credential => c !== undefined);
  }

  /**
   * Get credential count for identity
   */
  getCredentialCount(identityId: string): number {
    const credentialIds = this.credentialIndex.get(identityId) || [];
    return credentialIds.length;
  }

  /**
   * Get issuer public identifier
   */
  getIssuerName(): string {
    return this.issuerName;
  }

  /**
   * Normalize attributes for consistent hashing/signing
   */
  private normalizeAttributes(attributes: Attribute[]): Attribute[] {
    return attributes
      .map(attr => ({
        name: attr.name,
        value: attr.value,
        timestamp: attr.timestamp
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  /**
   * Generate a credential ID with cryptographic randomness
   */
  private generateCredentialId(): string {
    return 'cred_' + CryptoUtils.generateSecureRandom(16).toString('hex');
  }

  /**
   * Sign credential using HMAC-based signature
   * In production with blockchain/DID, this would use ECDSA
   */
  private signCredential(credentialData: any): string {
    const data = JSON.stringify(credentialData);
    const dataBuffer = Buffer.from(data, 'utf-8');

    // Derive signing key from master key
    const salt = Buffer.from(this.issuerName, 'utf-8');
    const signingKey = CryptoUtils.deriveKey(
      this.issuerPrivateKey,
      salt,
      'credential-signature',
      32
    );

    // Create signature using HMAC
    const signature = CryptoUtils.hash(
      Buffer.concat([dataBuffer, signingKey])
    );

    // Secure zero the signing key
    CryptoUtils.secureZero(signingKey);

    return signature;
  }
}
