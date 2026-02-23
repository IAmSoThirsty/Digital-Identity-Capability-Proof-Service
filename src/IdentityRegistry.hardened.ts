import { Identity, Attribute } from './types';
import { randomBytes } from 'crypto';
import { InputValidator } from './security/InputValidator';
import { AuditLogger } from './security/AuditLogger';
import { AccessControl } from './security/AccessControl';
import { RateLimiter, DEFAULT_RATE_LIMITS } from './security/RateLimiter';
import { NotFoundError, ConflictError, RateLimitError } from './errors/SystemErrors';

/**
 * Production-grade Identity Registry
 * Manages the registration and storage of digital identities with comprehensive security
 */
export class IdentityRegistry {
  private identities: Map<string, Identity>;
  private publicKeyIndex: Map<string, string>; // publicKey -> identityId
  private auditLogger: AuditLogger;
  private accessControl: AccessControl;
  private rateLimiter: RateLimiter;

  constructor(
    auditLogger?: AuditLogger,
    accessControl?: AccessControl,
    rateLimiter?: RateLimiter
  ) {
    this.identities = new Map();
    this.publicKeyIndex = new Map();
    this.auditLogger = auditLogger || new AuditLogger();
    this.accessControl = accessControl || new AccessControl();
    this.rateLimiter = rateLimiter || new RateLimiter();
  }

  /**
   * Register a new identity with comprehensive validation and security
   */
  async registerIdentity(
    publicKey: string,
    attributes: Attribute[],
    actorId?: string
  ): Promise<Identity> {
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

    // Rate limiting
    const rateLimit = await this.rateLimiter.checkLimit(
      `identity_create_${actorId || 'anonymous'}`,
      DEFAULT_RATE_LIMITS.identityCreate.capacity,
      DEFAULT_RATE_LIMITS.identityCreate.refillRate
    );

    if (!rateLimit.allowed) {
      this.auditLogger.logRateLimitViolation(
        actorId || 'anonymous',
        'identity_create',
        DEFAULT_RATE_LIMITS.identityCreate.capacity
      );
      throw new RateLimitError(rateLimit.retryAfter || 60);
    }

    // Generate identity
    const id = this.generateIdentityId();
    const identity: Identity = {
      id,
      publicKey,
      attributes,
      createdAt: Date.now()
    };

    // Store identity
    this.identities.set(id, identity);
    this.publicKeyIndex.set(publicKey, id);

    // Set ownership
    this.accessControl.setResourceOwner(id, actorId || id);

    // Audit log
    this.auditLogger.logIdentityRegistration(
      id,
      publicKey,
      actorId || 'system'
    );

    return identity;
  }

  /**
   * Retrieve an identity by ID with access control
   */
  getIdentity(id: string, actorId?: string): Identity | undefined {
    InputValidator.validateIdentityId(id);

    const identity = this.identities.get(id);

    if (!identity) {
      return undefined;
    }

    // Check access control
    if (actorId) {
      const hasPermission =
        this.accessControl.hasPermission(actorId, 'IDENTITY_READ') ||
        this.accessControl.hasPermission(actorId, 'IDENTITY_READ_OWN', id);

      if (!hasPermission) {
        this.auditLogger.logAccessControl(
          actorId,
          id,
          'READ',
          false,
          'Insufficient permissions'
        );
        return undefined;
      }
    }

    // Audit log
    this.auditLogger.logDataAccess(
      actorId || 'system',
      'identity',
      id,
      'READ'
    );

    return identity;
  }

  /**
   * Update identity attributes with validation and access control
   */
  updateAttributes(
    id: string,
    newAttributes: Attribute[],
    actorId?: string
  ): boolean {
    InputValidator.validateIdentityId(id);
    InputValidator.validateAttributes(newAttributes);

    const identity = this.identities.get(id);
    if (!identity) {
      throw new NotFoundError('Identity', id);
    }

    // Check access control
    if (actorId) {
      this.accessControl.requirePermission(actorId, 'IDENTITY_UPDATE_OWN', id);
    }

    // Update attributes
    identity.attributes = newAttributes;
    this.identities.set(id, identity);

    // Audit log
    this.auditLogger.logDataAccess(
      actorId || 'system',
      'identity',
      id,
      'WRITE'
    );

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
   * Get all identities (admin only, with pagination)
   */
  getAllIdentities(
    actorId: string,
    limit: number = 100,
    offset: number = 0
  ): Identity[] {
    // Require admin permission
    this.accessControl.requirePermission(actorId, 'IDENTITY_READ');

    // Validate pagination
    if (limit <= 0 || limit > 1000) {
      limit = 100;
    }
    if (offset < 0) {
      offset = 0;
    }

    // Audit log
    this.auditLogger.log({
      type: 'IDENTITY_LIST',
      severity: 'INFO',
      actor: actorId,
      resource: 'identity',
      action: 'LIST',
      details: { limit, offset },
      outcome: 'SUCCESS'
    });

    const identities = Array.from(this.identities.values());
    return identities.slice(offset, offset + limit);
  }

  /**
   * Delete identity (admin only, with secure deletion)
   */
  deleteIdentity(id: string, actorId: string): boolean {
    InputValidator.validateIdentityId(id);

    // Require admin permission
    this.accessControl.requirePermission(actorId, 'IDENTITY_DELETE');

    const identity = this.identities.get(id);
    if (!identity) {
      throw new NotFoundError('Identity', id);
    }

    // Remove from indices
    this.publicKeyIndex.delete(identity.publicKey);
    this.identities.delete(id);

    // Audit log
    this.auditLogger.logDataAccess(actorId, 'identity', id, 'DELETE');

    return true;
  }

  /**
   * Find identity by public key
   */
  findByPublicKey(publicKey: string, actorId?: string): Identity | undefined {
    try {
      InputValidator.validatePublicKey(publicKey);
    } catch {
      return undefined;
    }

    const identityId = this.publicKeyIndex.get(publicKey);
    if (!identityId) {
      return undefined;
    }

    return this.getIdentity(identityId, actorId);
  }

  /**
   * Get identity count
   */
  getIdentityCount(): number {
    return this.identities.size;
  }

  /**
   * Get audit logger
   */
  getAuditLogger(): AuditLogger {
    return this.auditLogger;
  }

  /**
   * Get access control
   */
  getAccessControl(): AccessControl {
    return this.accessControl;
  }

  /**
   * Generate a unique identity ID with cryptographic randomness
   */
  private generateIdentityId(): string {
    return 'id_' + randomBytes(16).toString('hex');
  }
}
