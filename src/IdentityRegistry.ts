import { Identity, Attribute } from './types';
import { randomBytes } from 'crypto';
import { InputValidator } from './security/InputValidator';
import { NotFoundError, ConflictError } from './errors/SystemErrors';

/**
 * Production-grade Identity Registry
 * Manages the registration and storage of digital identities with comprehensive security
 */
export class IdentityRegistry {
  private identities: Map<string, Identity>;
  private publicKeyIndex: Map<string, string>; // publicKey -> identityId

  constructor() {
    this.identities = new Map();
    this.publicKeyIndex = new Map();
  }

  /**
   * Register a new identity with input validation and duplicate prevention
   */
  registerIdentity(publicKey: string, attributes: Attribute[]): Identity {
    // Input validation
    InputValidator.validatePublicKey(publicKey);
    InputValidator.validateAttributes(attributes);

    // Check for duplicate public key
    if (this.publicKeyIndex.has(publicKey)) {
      const existingId = this.publicKeyIndex.get(publicKey)!;
      throw new ConflictError('Public key already registered', {
        existingIdentityId: existingId
      });
    }

    const id = this.generateIdentityId();

    const identity: Identity = {
      id,
      publicKey,
      attributes,
      createdAt: Date.now()
    };

    this.identities.set(id, identity);
    this.publicKeyIndex.set(publicKey, id);
    return identity;
  }

  /**
   * Retrieve an identity by ID with validation
   */
  getIdentity(id: string): Identity | undefined {
    try {
      InputValidator.validateIdentityId(id);
    } catch {
      return undefined;
    }
    return this.identities.get(id);
  }

  /**
   * Update identity attributes with validation
   */
  updateAttributes(id: string, newAttributes: Attribute[]): boolean {
    InputValidator.validateIdentityId(id);
    InputValidator.validateAttributes(newAttributes);

    const identity = this.identities.get(id);
    if (!identity) {
      throw new NotFoundError('Identity', id);
    }

    identity.attributes = newAttributes;
    this.identities.set(id, identity);
    return true;
  }

  /**
   * Check if an identity exists
   */
  hasIdentity(id: string): boolean {
    try {
      InputValidator.validateIdentityId(id);
      return this.identities.has(id);
    } catch {
      return false;
    }
  }

  /**
   * Get all identities with pagination
   */
  getAllIdentities(limit: number = 100, offset: number = 0): Identity[] {
    // Validate and bound pagination
    if (limit <= 0 || limit > 1000) {
      limit = 100;
    }
    if (offset < 0) {
      offset = 0;
    }

    const identities = Array.from(this.identities.values());
    return identities.slice(offset, offset + limit);
  }

  /**
   * Find identity by public key
   */
  findByPublicKey(publicKey: string): Identity | undefined {
    try {
      InputValidator.validatePublicKey(publicKey);
    } catch {
      return undefined;
    }

    const identityId = this.publicKeyIndex.get(publicKey);
    if (!identityId) {
      return undefined;
    }

    return this.identities.get(identityId);
  }

  /**
   * Get identity count
   */
  getIdentityCount(): number {
    return this.identities.size;
  }

  /**
   * Generate a unique identity ID with cryptographic randomness
   */
  private generateIdentityId(): string {
    return 'id_' + randomBytes(16).toString('hex');
  }
}
