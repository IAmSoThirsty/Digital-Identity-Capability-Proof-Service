import { ClaimType, ClaimStatement } from './types';
import { buildPoseidon } from 'circomlibjs';
import { CryptoUtils } from './security/CryptoUtils';
import { InputValidator } from './security/InputValidator';
import { ProofGenerationError, ConfigurationError } from './errors/SystemErrors';

/**
 * Production-grade ZK Circuit Engine
 * Manages zero-knowledge proof circuits with cryptographic security
 */
export class ZKCircuitEngine {
  private poseidon: any;
  private initialized: boolean = false;
  private readonly BN128_FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

  async initialize(): Promise<void> {
    if (!this.initialized) {
      try {
        this.poseidon = await buildPoseidon();
        this.initialized = true;
      } catch (error) {
        throw new ConfigurationError(
          'Failed to initialize Poseidon hash function',
          { error: error instanceof Error ? error.message : String(error) }
        );
      }
    }
  }

  /**
   * Generate circuit inputs for a claim with comprehensive validation
   */
  async generateCircuitInputs(
    claim: ClaimStatement,
    privateData: Record<string, any>
  ): Promise<Record<string, any>> {
    await this.initialize();

    // Validate claim statement
    InputValidator.validateClaimStatement(claim);

    // Validate private data
    if (!privateData || typeof privateData !== 'object') {
      throw new ProofGenerationError('Invalid private data');
    }

    switch (claim.type) {
      case ClaimType.AGE_OVER:
        return this.generateAgeOverInputs(claim.parameters, privateData);
      case ClaimType.LICENSE_VALID:
        return this.generateLicenseValidInputs(claim.parameters, privateData);
      case ClaimType.CLEARANCE_LEVEL:
        return this.generateClearanceLevelInputs(claim.parameters, privateData);
      case ClaimType.ROLE_AUTHORIZATION:
        return this.generateRoleAuthorizationInputs(claim.parameters, privateData);
      default:
        throw new ProofGenerationError(`Unsupported claim type: ${claim.type}`);
    }
  }

  /**
   * Generate inputs for age verification (over threshold) with validation
   */
  private generateAgeOverInputs(
    parameters: Record<string, any>,
    privateData: Record<string, any>
  ): Record<string, any> {
    // Validate threshold
    const threshold = parameters.threshold || 18;
    if (typeof threshold !== 'number' || threshold < 0 || threshold > 150) {
      throw new ProofGenerationError('Invalid age threshold');
    }

    // Validate actual age
    const actualAge = privateData.age;
    if (typeof actualAge !== 'number' || actualAge < 0 || actualAge > 150) {
      throw new ProofGenerationError('Invalid age value');
    }

    // Generate cryptographically secure salt
    const salt = privateData.salt !== undefined
      ? this.validateAndConvertSalt(privateData.salt)
      : this.generateSecureSalt();

    // Hash the age with salt for privacy
    const ageHash = this.hash([actualAge, salt]);
    this.validateFieldElement(ageHash);

    return {
      ageHash: ageHash.toString(),
      threshold,
      age: actualAge,
      salt,
      isOver: actualAge >= threshold ? 1 : 0
    };
  }

  /**
   * Generate inputs for license verification with validation
   */
  private generateLicenseValidInputs(
    parameters: Record<string, any>,
    privateData: Record<string, any>
  ): Record<string, any> {
    // Validate required license type
    const requiredLicenseType = parameters.licenseType;
    if (!requiredLicenseType || typeof requiredLicenseType !== 'string') {
      throw new ProofGenerationError('Invalid required license type');
    }

    // Validate license type
    const licenseType = privateData.licenseType;
    if (!licenseType || typeof licenseType !== 'string') {
      throw new ProofGenerationError('Invalid license type');
    }

    // Validate expiration date
    const expirationDate = privateData.expirationDate;
    if (typeof expirationDate !== 'number' || expirationDate <= 0) {
      throw new ProofGenerationError('Invalid expiration date');
    }

    const currentDate = Date.now();

    // Generate cryptographically secure salt
    const salt = privateData.salt !== undefined
      ? this.validateAndConvertSalt(privateData.salt)
      : this.generateSecureSalt();

    // Convert string to numeric hash for circuit
    const licenseTypeHash = this.stringToNumber(licenseType);
    const licenseHash = this.hash([licenseTypeHash, expirationDate, salt]);
    this.validateFieldElement(licenseHash);

    return {
      licenseHash: licenseHash.toString(),
      requiredLicenseType,
      licenseType,
      expirationDate,
      currentDate,
      salt,
      isValid: (licenseType === requiredLicenseType && expirationDate > currentDate) ? 1 : 0
    };
  }

  /**
   * Generate inputs for clearance level verification with validation
   */
  private generateClearanceLevelInputs(
    parameters: Record<string, any>,
    privateData: Record<string, any>
  ): Record<string, any> {
    // Validate required level
    const requiredLevel = parameters.requiredLevel || 0;
    if (typeof requiredLevel !== 'number' || requiredLevel < 0 || requiredLevel > 10) {
      throw new ProofGenerationError('Invalid required clearance level');
    }

    // Validate actual level
    const actualLevel = privateData.clearanceLevel;
    if (typeof actualLevel !== 'number' || actualLevel < 0 || actualLevel > 10) {
      throw new ProofGenerationError('Invalid clearance level');
    }

    // Generate cryptographically secure salt
    const salt = privateData.salt !== undefined
      ? this.validateAndConvertSalt(privateData.salt)
      : this.generateSecureSalt();

    const clearanceHash = this.hash([actualLevel, salt]);
    this.validateFieldElement(clearanceHash);

    return {
      clearanceHash: clearanceHash.toString(),
      requiredLevel,
      actualLevel,
      salt,
      hasAccess: actualLevel >= requiredLevel ? 1 : 0
    };
  }

  /**
   * Generate inputs for role authorization with validation
   */
  private generateRoleAuthorizationInputs(
    parameters: Record<string, any>,
    privateData: Record<string, any>
  ): Record<string, any> {
    // Validate required role
    const requiredRole = parameters.role;
    if (!requiredRole || typeof requiredRole !== 'string') {
      throw new ProofGenerationError('Invalid required role');
    }

    // Validate user role
    const userRole = privateData.role;
    if (!userRole || typeof userRole !== 'string') {
      throw new ProofGenerationError('Invalid user role');
    }

    // Generate cryptographically secure salt
    const salt = privateData.salt !== undefined
      ? this.validateAndConvertSalt(privateData.salt)
      : this.generateSecureSalt();

    // Convert string to numeric hash for circuit
    const userRoleHash = this.stringToNumber(userRole);
    const roleHash = this.hash([userRoleHash, salt]);
    this.validateFieldElement(roleHash);

    return {
      roleHash: roleHash.toString(),
      requiredRole,
      userRole,
      salt,
      isAuthorized: userRole === requiredRole ? 1 : 0
    };
  }

  /**
   * Hash data using Poseidon hash function with error handling
   */
  private hash(data: any[]): bigint {
    if (!this.poseidon) {
      throw new ConfigurationError('Circuit engine not initialized');
    }

    // Validate input data
    if (!Array.isArray(data) || data.length === 0) {
      throw new ProofGenerationError('Invalid hash input data');
    }

    try {
      const hash = this.poseidon(data);
      return this.poseidon.F.toObject(hash);
    } catch (error) {
      throw new ProofGenerationError(
        'Hash computation failed',
        { error: error instanceof Error ? error.message : String(error) }
      );
    }
  }

  /**
   * Validate that a value is within the BN128 field
   */
  private validateFieldElement(value: bigint): void {
    if (value < 0n || value >= this.BN128_FIELD_PRIME) {
      throw new ProofGenerationError(
        'Value exceeds field modulus',
        { value: value.toString() }
      );
    }
  }

  /**
   * Convert string to number for hashing (deterministic)
   */
  private stringToNumber(str: string): number {
    // Validate input
    if (typeof str !== 'string' || str.length === 0) {
      throw new ProofGenerationError('Invalid string for hashing');
    }

    // Use deterministic string hashing (DJB2 algorithm)
    let hash = 5381;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) + hash) + char; // hash * 33 + char
      hash = hash >>> 0; // Convert to 32-bit unsigned integer
    }
    return hash;
  }

  /**
   * Generate cryptographically secure random salt
   */
  private generateSecureSalt(): number {
    // Generate 4 bytes (32 bits) of cryptographically secure randomness
    const randomBytes = CryptoUtils.generateSecureRandom(4);
    // Convert to unsigned 32-bit integer
    return randomBytes.readUInt32BE(0);
  }

  /**
   * Validate and convert salt to number
   */
  private validateAndConvertSalt(salt: any): number {
    if (typeof salt === 'number') {
      if (!Number.isInteger(salt) || salt < 0 || salt > 0xFFFFFFFF) {
        throw new ProofGenerationError('Salt must be a 32-bit unsigned integer');
      }
      return salt;
    }

    if (typeof salt === 'string') {
      const parsed = parseInt(salt, 10);
      if (isNaN(parsed) || parsed < 0 || parsed > 0xFFFFFFFF) {
        throw new ProofGenerationError('Invalid salt string value');
      }
      return parsed;
    }

    throw new ProofGenerationError('Salt must be a number or numeric string');
  }

  /**
   * Get circuit definition for a claim type
   */
  getCircuitDefinition(claimType: ClaimType): string {
    switch (claimType) {
      case ClaimType.AGE_OVER:
        return this.getAgeOverCircuit();
      case ClaimType.LICENSE_VALID:
        return this.getLicenseValidCircuit();
      case ClaimType.CLEARANCE_LEVEL:
        return this.getClearanceLevelCircuit();
      case ClaimType.ROLE_AUTHORIZATION:
        return this.getRoleAuthorizationCircuit();
      default:
        throw new ConfigurationError(`Unsupported claim type: ${claimType}`);
    }
  }

  /**
   * Get Circom circuit for age verification
   */
  private getAgeOverCircuit(): string {
    return `
pragma circom 2.0.0;

include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/poseidon.circom";

template AgeOver() {
    signal input age;
    signal input threshold;
    signal input salt;
    signal output ageHash;
    signal output isOver;

    // Hash the age with salt
    component hasher = Poseidon(2);
    hasher.inputs[0] <== age;
    hasher.inputs[1] <== salt;
    ageHash <== hasher.out;

    // Check if age >= threshold
    component gte = GreaterEqThan(8);
    gte.in[0] <== age;
    gte.in[1] <== threshold;
    isOver <== gte.out;
}

component main = AgeOver();
`;
  }

  /**
   * Get Circom circuit for license validation
   */
  private getLicenseValidCircuit(): string {
    return `
pragma circom 2.0.0;

include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/poseidon.circom";

template LicenseValid() {
    signal input licenseType;
    signal input requiredLicenseType;
    signal input expirationDate;
    signal input currentDate;
    signal input salt;
    signal output licenseHash;
    signal output isValid;

    // Hash the license data
    component hasher = Poseidon(3);
    hasher.inputs[0] <== licenseType;
    hasher.inputs[1] <== expirationDate;
    hasher.inputs[2] <== salt;
    licenseHash <== hasher.out;

    // Check type matches
    component typeEq = IsEqual();
    typeEq.in[0] <== licenseType;
    typeEq.in[1] <== requiredLicenseType;

    // Check not expired
    component notExpired = GreaterThan(32);
    notExpired.in[0] <== expirationDate;
    notExpired.in[1] <== currentDate;

    // Both conditions must be true
    isValid <== typeEq.out * notExpired.out;
}

component main = LicenseValid();
`;
  }

  /**
   * Get Circom circuit for clearance level
   */
  private getClearanceLevelCircuit(): string {
    return `
pragma circom 2.0.0;

include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/poseidon.circom";

template ClearanceLevel() {
    signal input actualLevel;
    signal input requiredLevel;
    signal input salt;
    signal output clearanceHash;
    signal output hasAccess;

    // Hash the clearance level
    component hasher = Poseidon(2);
    hasher.inputs[0] <== actualLevel;
    hasher.inputs[1] <== salt;
    clearanceHash <== hasher.out;

    // Check if actualLevel >= requiredLevel
    component gte = GreaterEqThan(8);
    gte.in[0] <== actualLevel;
    gte.in[1] <== requiredLevel;
    hasAccess <== gte.out;
}

component main = ClearanceLevel();
`;
  }

  /**
   * Get Circom circuit for role authorization
   */
  private getRoleAuthorizationCircuit(): string {
    return `
pragma circom 2.0.0;

include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/poseidon.circom";

template RoleAuthorization() {
    signal input userRole;
    signal input requiredRole;
    signal input salt;
    signal output roleHash;
    signal output isAuthorized;

    // Hash the role
    component hasher = Poseidon(2);
    hasher.inputs[0] <== userRole;
    hasher.inputs[1] <== salt;
    roleHash <== hasher.out;

    // Check if roles match
    component eq = IsEqual();
    eq.in[0] <== userRole;
    eq.in[1] <== requiredRole;
    isAuthorized <== eq.out;
}

component main = RoleAuthorization();
`;
  }
}
