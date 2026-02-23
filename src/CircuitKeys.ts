import * as fs from 'fs';
import * as path from 'path';
import { ClaimType } from './types';
import { ConfigurationError } from './errors/SystemErrors';

/**
 * Circuit Keys Manager
 * Manages access to compiled circuit artifacts (WASM, proving keys, verification keys)
 */
export class CircuitKeys {
  private static instance: CircuitKeys;
  private readonly circuitsDir: string;
  private readonly buildDir: string;
  private keysLoaded: Map<ClaimType, boolean> = new Map();

  private constructor(circuitsDir?: string) {
    this.circuitsDir = circuitsDir || path.join(__dirname, '../circuits');
    this.buildDir = path.join(this.circuitsDir, 'build');
  }

  /**
   * Get singleton instance
   */
  static getInstance(circuitsDir?: string): CircuitKeys {
    if (!CircuitKeys.instance) {
      CircuitKeys.instance = new CircuitKeys(circuitsDir);
    }
    return CircuitKeys.instance;
  }

  /**
   * Get the circuit name for a claim type
   */
  private getCircuitName(claimType: ClaimType): string {
    switch (claimType) {
      case ClaimType.AGE_OVER:
        return 'ageOver';
      case ClaimType.LICENSE_VALID:
        return 'licenseValid';
      case ClaimType.CLEARANCE_LEVEL:
        return 'clearanceLevel';
      case ClaimType.ROLE_AUTHORIZATION:
        return 'roleAuthorization';
      default:
        throw new ConfigurationError(`Unsupported claim type: ${claimType}`);
    }
  }

  /**
   * Get WASM file path for a circuit
   */
  getWasmPath(claimType: ClaimType): string {
    const circuitName = this.getCircuitName(claimType);
    const wasmPath = path.join(this.buildDir, `${circuitName}_js`, `${circuitName}.wasm`);

    if (!fs.existsSync(wasmPath)) {
      throw new ConfigurationError(
        `WASM file not found for ${claimType}. Run 'npm run prepare-circuits' to compile circuits.`,
        { expectedPath: wasmPath }
      );
    }

    return wasmPath;
  }

  /**
   * Get proving key (zkey) file path for a circuit
   */
  getZkeyPath(claimType: ClaimType): string {
    const circuitName = this.getCircuitName(claimType);
    const zkeyPath = path.join(this.buildDir, `${circuitName}.zkey`);

    if (!fs.existsSync(zkeyPath)) {
      throw new ConfigurationError(
        `Proving key not found for ${claimType}. Run 'npm run prepare-circuits' to compile circuits.`,
        { expectedPath: zkeyPath }
      );
    }

    return zkeyPath;
  }

  /**
   * Get verification key for a circuit
   */
  getVerificationKey(claimType: ClaimType): any {
    const circuitName = this.getCircuitName(claimType);
    const vkeyPath = path.join(this.buildDir, `${circuitName}_verification_key.json`);

    if (!fs.existsSync(vkeyPath)) {
      throw new ConfigurationError(
        `Verification key not found for ${claimType}. Run 'npm run prepare-circuits' to compile circuits.`,
        { expectedPath: vkeyPath }
      );
    }

    try {
      const vkeyData = fs.readFileSync(vkeyPath, 'utf8');
      return JSON.parse(vkeyData);
    } catch (error) {
      throw new ConfigurationError(
        `Failed to load verification key for ${claimType}`,
        {
          path: vkeyPath,
          error: error instanceof Error ? error.message : String(error)
        }
      );
    }
  }

  /**
   * Check if circuits are compiled and ready
   */
  areCircuitsReady(): boolean {
    try {
      // Check if build directory exists
      if (!fs.existsSync(this.buildDir)) {
        return false;
      }

      // Check if all circuits have their required files
      for (const claimType of Object.values(ClaimType)) {
        const circuitName = this.getCircuitName(claimType);

        // Check WASM
        const wasmPath = path.join(this.buildDir, `${circuitName}_js`, `${circuitName}.wasm`);
        if (!fs.existsSync(wasmPath)) {
          return false;
        }

        // Check zkey
        const zkeyPath = path.join(this.buildDir, `${circuitName}.zkey`);
        if (!fs.existsSync(zkeyPath)) {
          return false;
        }

        // Check verification key
        const vkeyPath = path.join(this.buildDir, `${circuitName}_verification_key.json`);
        if (!fs.existsSync(vkeyPath)) {
          return false;
        }
      }

      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get detailed status of circuit compilation
   */
  getCircuitStatus(): Record<string, any> {
    const status: Record<string, any> = {
      buildDirExists: fs.existsSync(this.buildDir),
      circuits: {}
    };

    for (const claimType of Object.values(ClaimType)) {
      const circuitName = this.getCircuitName(claimType);
      const wasmPath = path.join(this.buildDir, `${circuitName}_js`, `${circuitName}.wasm`);
      const zkeyPath = path.join(this.buildDir, `${circuitName}.zkey`);
      const vkeyPath = path.join(this.buildDir, `${circuitName}_verification_key.json`);

      status.circuits[claimType] = {
        name: circuitName,
        wasm: fs.existsSync(wasmPath),
        zkey: fs.existsSync(zkeyPath),
        vkey: fs.existsSync(vkeyPath),
        ready: fs.existsSync(wasmPath) && fs.existsSync(zkeyPath) && fs.existsSync(vkeyPath)
      };
    }

    status.allReady = Object.values(status.circuits).every((c: any) => c.ready);

    return status;
  }

  /**
   * Validate that all required circuit files exist
   * Throws detailed error if any files are missing
   */
  validateCircuits(): void {
    const status = this.getCircuitStatus();

    if (!status.buildDirExists) {
      throw new ConfigurationError(
        'Circuits build directory not found. Run \'npm run prepare-circuits\' to compile circuits.',
        { buildDir: this.buildDir }
      );
    }

    const missingCircuits = Object.entries(status.circuits)
      .filter(([_, info]: [string, any]) => !info.ready)
      .map(([type, info]: [string, any]) => ({ type, info }));

    if (missingCircuits.length > 0) {
      const details = missingCircuits.map(({ type, info }) => {
        const missing = [];
        if (!info.wasm) missing.push('WASM');
        if (!info.zkey) missing.push('proving key');
        if (!info.vkey) missing.push('verification key');
        return `${type}: missing ${missing.join(', ')}`;
      });

      throw new ConfigurationError(
        'Some circuits are not compiled. Run \'npm run prepare-circuits\' to compile circuits.',
        { missingCircuits: details }
      );
    }
  }
}
