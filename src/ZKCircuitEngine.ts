import { ClaimType, ClaimStatement } from './types';
import { buildPoseidon } from 'circomlibjs';

/**
 * ZK Circuit Engine
 * Manages zero-knowledge proof circuits for different claim types
 */
export class ZKCircuitEngine {
  private poseidon: any;
  private initialized: boolean = false;

  async initialize(): Promise<void> {
    if (!this.initialized) {
      this.poseidon = await buildPoseidon();
      this.initialized = true;
    }
  }

  /**
   * Generate circuit inputs for a claim
   */
  async generateCircuitInputs(
    claim: ClaimStatement,
    privateData: Record<string, any>
  ): Promise<Record<string, any>> {
    await this.initialize();

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
        throw new Error(`Unsupported claim type: ${claim.type}`);
    }
  }

  /**
   * Generate inputs for age verification (over threshold)
   */
  private generateAgeOverInputs(
    parameters: Record<string, any>,
    privateData: Record<string, any>
  ): Record<string, any> {
    const threshold = parameters.threshold || 18;
    const actualAge = privateData.age;
    const salt = privateData.salt || this.generateSalt();

    // Hash the age with salt for privacy
    const ageHash = this.hash([actualAge, salt]);

    return {
      ageHash: ageHash.toString(),
      threshold,
      age: actualAge,
      salt,
      isOver: actualAge >= threshold ? 1 : 0
    };
  }

  /**
   * Generate inputs for license verification
   */
  private generateLicenseValidInputs(
    parameters: Record<string, any>,
    privateData: Record<string, any>
  ): Record<string, any> {
    const requiredLicenseType = parameters.licenseType;
    const licenseType = privateData.licenseType;
    const expirationDate = privateData.expirationDate;
    const currentDate = Date.now();
    const salt = privateData.salt || this.generateSalt();

    // Convert string to numeric hash for circuit
    const licenseTypeHash = this.stringToNumber(licenseType);
    const licenseHash = this.hash([licenseTypeHash, expirationDate, salt]);

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
   * Generate inputs for clearance level verification
   */
  private generateClearanceLevelInputs(
    parameters: Record<string, any>,
    privateData: Record<string, any>
  ): Record<string, any> {
    const requiredLevel = parameters.requiredLevel || 0;
    const actualLevel = privateData.clearanceLevel;
    const salt = privateData.salt || this.generateSalt();

    const clearanceHash = this.hash([actualLevel, salt]);

    return {
      clearanceHash: clearanceHash.toString(),
      requiredLevel,
      actualLevel,
      salt,
      hasAccess: actualLevel >= requiredLevel ? 1 : 0
    };
  }

  /**
   * Generate inputs for role authorization
   */
  private generateRoleAuthorizationInputs(
    parameters: Record<string, any>,
    privateData: Record<string, any>
  ): Record<string, any> {
    const requiredRole = parameters.role;
    const userRole = privateData.role;
    const salt = privateData.salt || this.generateSalt();

    // Convert string to numeric hash for circuit
    const userRoleHash = this.stringToNumber(userRole);
    const roleHash = this.hash([userRoleHash, salt]);

    return {
      roleHash: roleHash.toString(),
      requiredRole,
      userRole,
      salt,
      isAuthorized: userRole === requiredRole ? 1 : 0
    };
  }

  /**
   * Hash data using Poseidon hash function
   */
  private hash(data: any[]): bigint {
    if (!this.poseidon) {
      throw new Error('Circuit engine not initialized');
    }
    const hash = this.poseidon(data);
    return this.poseidon.F.toObject(hash);
  }

  /**
   * Convert string to number for hashing
   */
  private stringToNumber(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash);
  }

  /**
   * Generate a random salt
   */
  private generateSalt(): number {
    return Math.floor(Math.random() * 1000000);
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
        throw new Error(`Unsupported claim type: ${claimType}`);
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
