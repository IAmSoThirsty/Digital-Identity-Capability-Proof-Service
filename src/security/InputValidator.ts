import { Attribute, ClaimStatement } from '../types';

/**
 * Production-grade input validation
 * Prevents injection attacks, validates constraints, ensures type safety
 */
export class InputValidator {
  // Public key format: hex string (64 or 66 chars for compressed/uncompressed)
  private static readonly PUBLIC_KEY_REGEX = /^(0x)?[0-9a-fA-F]{64,130}$/;

  // Attribute name: alphanumeric with underscores, max 64 chars
  private static readonly ATTRIBUTE_NAME_REGEX = /^[a-zA-Z0-9_]{1,64}$/;

  // Max attribute value size: 1KB
  private static readonly MAX_ATTRIBUTE_VALUE_SIZE = 1024;

  // Max attributes per identity/credential
  private static readonly MAX_ATTRIBUTES = 100;

  /**
   * Validate public key format
   */
  static validatePublicKey(publicKey: string): void {
    if (!publicKey || typeof publicKey !== 'string') {
      throw new ValidationError('Public key must be a non-empty string');
    }

    if (!this.PUBLIC_KEY_REGEX.test(publicKey)) {
      throw new ValidationError('Invalid public key format. Expected hex string (64-130 chars)');
    }

    // Sanitize to prevent injection
    const sanitized = publicKey.replace(/[^0-9a-fA-Fx]/g, '');
    if (sanitized !== publicKey) {
      throw new ValidationError('Public key contains invalid characters');
    }
  }

  /**
   * Validate attributes array
   */
  static validateAttributes(attributes: Attribute[]): void {
    if (!Array.isArray(attributes)) {
      throw new ValidationError('Attributes must be an array');
    }

    if (attributes.length === 0) {
      throw new ValidationError('At least one attribute is required');
    }

    if (attributes.length > this.MAX_ATTRIBUTES) {
      throw new ValidationError(`Too many attributes. Maximum: ${this.MAX_ATTRIBUTES}`);
    }

    const seenNames = new Set<string>();

    for (const attr of attributes) {
      this.validateAttribute(attr);

      // Check for duplicate attribute names
      if (seenNames.has(attr.name)) {
        throw new ValidationError(`Duplicate attribute name: ${attr.name}`);
      }
      seenNames.add(attr.name);
    }
  }

  /**
   * Validate single attribute
   */
  static validateAttribute(attribute: Attribute): void {
    if (!attribute || typeof attribute !== 'object') {
      throw new ValidationError('Attribute must be an object');
    }

    // Validate name
    if (!attribute.name || typeof attribute.name !== 'string') {
      throw new ValidationError('Attribute name must be a non-empty string');
    }

    if (!this.ATTRIBUTE_NAME_REGEX.test(attribute.name)) {
      throw new ValidationError(
        `Invalid attribute name: ${attribute.name}. Must be alphanumeric with underscores (max 64 chars)`
      );
    }

    // Validate value
    if (attribute.value === undefined || attribute.value === null) {
      throw new ValidationError('Attribute value cannot be null or undefined');
    }

    // Validate value size
    const valueSize = JSON.stringify(attribute.value).length;
    if (valueSize > this.MAX_ATTRIBUTE_VALUE_SIZE) {
      throw new ValidationError(
        `Attribute value too large: ${valueSize} bytes. Maximum: ${this.MAX_ATTRIBUTE_VALUE_SIZE}`
      );
    }

    // Validate timestamp
    if (typeof attribute.timestamp !== 'number' || attribute.timestamp <= 0) {
      throw new ValidationError('Attribute timestamp must be a positive number');
    }

    // Timestamp should not be in the future (with 5 min tolerance)
    const maxFutureTime = Date.now() + 5 * 60 * 1000;
    if (attribute.timestamp > maxFutureTime) {
      throw new ValidationError('Attribute timestamp cannot be in the future');
    }

    // Timestamp should not be too old (10 years)
    const minPastTime = Date.now() - 10 * 365 * 24 * 60 * 60 * 1000;
    if (attribute.timestamp < minPastTime) {
      throw new ValidationError('Attribute timestamp is too old');
    }
  }

  /**
   * Validate claim statement
   */
  static validateClaimStatement(claim: ClaimStatement): void {
    if (!claim || typeof claim !== 'object') {
      throw new ValidationError('Claim statement must be an object');
    }

    if (!claim.type || typeof claim.type !== 'string') {
      throw new ValidationError('Claim type must be a non-empty string');
    }

    const validTypes = ['AGE_OVER', 'LICENSE_VALID', 'CLEARANCE_LEVEL', 'ROLE_AUTHORIZATION'];
    if (!validTypes.includes(claim.type)) {
      throw new ValidationError(`Invalid claim type: ${claim.type}`);
    }

    if (!claim.parameters || typeof claim.parameters !== 'object') {
      throw new ValidationError('Claim parameters must be an object');
    }

    // Validate type-specific parameters
    switch (claim.type) {
      case 'AGE_OVER':
        this.validateAgeOverParameters(claim.parameters);
        break;
      case 'LICENSE_VALID':
        this.validateLicenseParameters(claim.parameters);
        break;
      case 'CLEARANCE_LEVEL':
        this.validateClearanceParameters(claim.parameters);
        break;
      case 'ROLE_AUTHORIZATION':
        this.validateRoleParameters(claim.parameters);
        break;
    }
  }

  /**
   * Validate AGE_OVER parameters
   */
  private static validateAgeOverParameters(params: any): void {
    if (typeof params.threshold !== 'number') {
      throw new ValidationError('Age threshold must be a number');
    }

    if (params.threshold < 0 || params.threshold > 150) {
      throw new ValidationError('Age threshold must be between 0 and 150');
    }

    if (!Number.isInteger(params.threshold)) {
      throw new ValidationError('Age threshold must be an integer');
    }
  }

  /**
   * Validate LICENSE_VALID parameters
   */
  private static validateLicenseParameters(params: any): void {
    if (!params.licenseType || typeof params.licenseType !== 'string') {
      throw new ValidationError('License type must be a non-empty string');
    }

    if (params.licenseType.length > 100) {
      throw new ValidationError('License type too long (max 100 chars)');
    }

    // Sanitize license type
    const sanitized = params.licenseType.replace(/[^a-zA-Z0-9_\- ]/g, '');
    if (sanitized !== params.licenseType) {
      throw new ValidationError('License type contains invalid characters');
    }
  }

  /**
   * Validate CLEARANCE_LEVEL parameters
   */
  private static validateClearanceParameters(params: any): void {
    if (typeof params.requiredLevel !== 'number') {
      throw new ValidationError('Required clearance level must be a number');
    }

    if (params.requiredLevel < 0 || params.requiredLevel > 10) {
      throw new ValidationError('Clearance level must be between 0 and 10');
    }

    if (!Number.isInteger(params.requiredLevel)) {
      throw new ValidationError('Clearance level must be an integer');
    }
  }

  /**
   * Validate ROLE_AUTHORIZATION parameters
   */
  private static validateRoleParameters(params: any): void {
    if (!params.role || typeof params.role !== 'string') {
      throw new ValidationError('Role must be a non-empty string');
    }

    if (params.role.length > 100) {
      throw new ValidationError('Role name too long (max 100 chars)');
    }

    // Sanitize role name
    const sanitized = params.role.replace(/[^a-zA-Z0-9_\-]/g, '');
    if (sanitized !== params.role) {
      throw new ValidationError('Role name contains invalid characters');
    }
  }

  /**
   * Validate identity ID format
   */
  static validateIdentityId(id: string): void {
    if (!id || typeof id !== 'string') {
      throw new ValidationError('Identity ID must be a non-empty string');
    }

    if (!/^id_[0-9a-f]{32}$/.test(id)) {
      throw new ValidationError('Invalid identity ID format');
    }
  }

  /**
   * Validate credential ID format
   */
  static validateCredentialId(id: string): void {
    if (!id || typeof id !== 'string') {
      throw new ValidationError('Credential ID must be a non-empty string');
    }

    if (!/^cred_[0-9a-f]{32}$/.test(id)) {
      throw new ValidationError('Invalid credential ID format');
    }
  }

  /**
   * Validate expiration timestamp
   */
  static validateExpiration(expiresAt?: number): void {
    if (expiresAt === undefined) {
      return; // Optional
    }

    if (typeof expiresAt !== 'number' || expiresAt <= 0) {
      throw new ValidationError('Expiration must be a positive number');
    }

    // Expiration should be in the future
    if (expiresAt <= Date.now()) {
      throw new ValidationError('Expiration must be in the future');
    }

    // Expiration should not be more than 10 years in future
    const maxFuture = Date.now() + 10 * 365 * 24 * 60 * 60 * 1000;
    if (expiresAt > maxFuture) {
      throw new ValidationError('Expiration too far in future (max 10 years)');
    }
  }

  /**
   * Sanitize string to prevent injection
   */
  static sanitizeString(input: string, maxLength: number = 1000): string {
    if (typeof input !== 'string') {
      throw new ValidationError('Input must be a string');
    }

    // Remove null bytes
    let sanitized = input.replace(/\0/g, '');

    // Trim whitespace
    sanitized = sanitized.trim();

    // Enforce max length
    if (sanitized.length > maxLength) {
      throw new ValidationError(`String too long (max ${maxLength} chars)`);
    }

    return sanitized;
  }

  /**
   * Validate circuit inputs
   */
  static validateCircuitInputs(inputs: Record<string, any>): void {
    if (!inputs || typeof inputs !== 'object') {
      throw new ValidationError('Circuit inputs must be an object');
    }

    // Check for required fields based on circuit type
    for (const [key, value] of Object.entries(inputs)) {
      // All circuit inputs should be numbers or bigints
      if (typeof value !== 'number' && typeof value !== 'bigint' && typeof value !== 'string') {
        throw new ValidationError(`Invalid circuit input type for ${key}`);
      }

      // Validate numeric ranges (prevent overflow)
      if (typeof value === 'number') {
        if (!Number.isFinite(value)) {
          throw new ValidationError(`Circuit input ${key} must be finite`);
        }

        if (value < 0) {
          throw new ValidationError(`Circuit input ${key} must be non-negative`);
        }

        // Check against field prime (BN128 curve order)
        const FIELD_PRIME = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
        if (BigInt(Math.floor(value)) >= FIELD_PRIME) {
          throw new ValidationError(`Circuit input ${key} exceeds field prime`);
        }
      }
    }
  }
}

/**
 * Custom validation error
 */
export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
    Object.setPrototypeOf(this, ValidationError.prototype);
  }
}
