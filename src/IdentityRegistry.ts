import { Identity, Attribute } from './types';
import { randomBytes } from 'crypto';

/**
 * Identity Registry
 * Manages the registration and storage of digital identities
 */
export class IdentityRegistry {
  private identities: Map<string, Identity>;

  constructor() {
    this.identities = new Map();
  }

  /**
   * Register a new identity
   */
  registerIdentity(publicKey: string, attributes: Attribute[]): Identity {
    const id = this.generateIdentityId();

    const identity: Identity = {
      id,
      publicKey,
      attributes,
      createdAt: Date.now()
    };

    this.identities.set(id, identity);
    return identity;
  }

  /**
   * Retrieve an identity by ID
   */
  getIdentity(id: string): Identity | undefined {
    return this.identities.get(id);
  }

  /**
   * Update identity attributes
   */
  updateAttributes(id: string, newAttributes: Attribute[]): boolean {
    const identity = this.identities.get(id);
    if (!identity) {
      return false;
    }

    identity.attributes = newAttributes;
    this.identities.set(id, identity);
    return true;
  }

  /**
   * Check if an identity exists
   */
  hasIdentity(id: string): boolean {
    return this.identities.has(id);
  }

  /**
   * Get all identities (for admin purposes)
   */
  getAllIdentities(): Identity[] {
    return Array.from(this.identities.values());
  }

  /**
   * Generate a unique identity ID
   */
  private generateIdentityId(): string {
    return 'id_' + randomBytes(16).toString('hex');
  }
}
