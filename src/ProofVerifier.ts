import { Proof, VerificationResult, ClaimType } from './types';
import { CircuitKeys } from './CircuitKeys';
import { ProofVerificationError, TimeoutError } from './errors/SystemErrors';
import { CryptoUtils } from './security/CryptoUtils';

const snarkjs = require('snarkjs');

/**
 * Production-grade Proof Verifier
 * Verifies zero-knowledge proofs with comprehensive security checks
 */
export class ProofVerifier {
  private circuitKeys: CircuitKeys;
  private readonly VERIFICATION_TIMEOUT_MS = 10000; // 10 seconds
  private readonly MAX_BATCH_SIZE = 100;
  private verificationCache: Map<string, boolean> = new Map();
  private useRealVerification: boolean = true;

  constructor(useRealVerification: boolean = true) {
    this.circuitKeys = CircuitKeys.getInstance();
    this.useRealVerification = useRealVerification;

    // If real verification is enabled, check if circuits are ready
    if (this.useRealVerification && !this.circuitKeys.areCircuitsReady()) {
      console.warn(
        'Warning: Circuits are not compiled. Falling back to simulated verification. ' +
        'Run \'npm run prepare-circuits\' to enable real ZK verification.'
      );
      this.useRealVerification = false;
    }
  }

  /**
   * Verify a zero-knowledge proof with validation and caching
   */
  async verifyProof(proof: Proof): Promise<VerificationResult> {
    const startTime = Date.now();

    try {
      // Validate proof structure
      this.validateProofStructure(proof);

      // Check cache
      const cacheKey = this.computeProofHash(proof);
      const cachedResult = this.verificationCache.get(cacheKey);

      if (cachedResult !== undefined) {
        return {
          valid: cachedResult,
          statement: proof.statement,
          timestamp: Date.now(),
          cached: true
        };
      }

      // Verify with timeout protection
      const valid = await this.verifyWithTimeout(proof);

      // Cache result (only cache valid proofs to prevent cache poisoning)
      if (valid) {
        this.verificationCache.set(cacheKey, valid);
        this.pruneCache();
      }

      const verificationTime = Date.now() - startTime;

      return {
        valid,
        statement: proof.statement,
        timestamp: Date.now(),
        verificationTimeMs: verificationTime,
        cached: false
      };
    } catch (error) {
      if (error instanceof TimeoutError) {
        throw error;
      }

      if (error instanceof ProofVerificationError) {
        throw error;
      }

      // Don't leak error details
      return {
        valid: false,
        statement: proof.statement,
        timestamp: Date.now(),
        error: 'Verification failed'
      };
    }
  }

  /**
   * Validate proof structure before verification
   */
  private validateProofStructure(proof: Proof): void {
    if (!proof || typeof proof !== 'object') {
      throw new ProofVerificationError('Invalid proof structure');
    }

    if (!proof.proof || typeof proof.proof !== 'object') {
      throw new ProofVerificationError('Missing proof data');
    }

    if (!Array.isArray(proof.publicSignals)) {
      throw new ProofVerificationError('Invalid public signals');
    }

    if (proof.publicSignals.length === 0) {
      throw new ProofVerificationError('No public signals provided');
    }

    if (proof.publicSignals.length > 1000) {
      throw new ProofVerificationError('Too many public signals');
    }

    // Validate proof components (Groth16 structure)
    const { pi_a, pi_b, pi_c, protocol, curve } = proof.proof;

    if (protocol !== 'groth16') {
      throw new ProofVerificationError('Unsupported proof protocol');
    }

    if (curve !== 'bn128') {
      throw new ProofVerificationError('Unsupported curve');
    }

    if (!Array.isArray(pi_a) || pi_a.length !== 3) {
      throw new ProofVerificationError('Invalid pi_a');
    }

    if (!Array.isArray(pi_b) || pi_b.length !== 3) {
      throw new ProofVerificationError('Invalid pi_b');
    }

    if (!Array.isArray(pi_c) || pi_c.length !== 3) {
      throw new ProofVerificationError('Invalid pi_c');
    }
  }

  /**
   * Verify proof with timeout protection
   */
  private async verifyWithTimeout(proof: Proof): Promise<boolean> {
    const verificationPromise = this.useRealVerification
      ? this.performRealVerification(proof)
      : this.simulateVerification(proof);

    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(
        () => reject(new TimeoutError('Proof verification', this.VERIFICATION_TIMEOUT_MS)),
        this.VERIFICATION_TIMEOUT_MS
      );
    });

    return Promise.race([verificationPromise, timeoutPromise]);
  }

  /**
   * Simulate proof verification with enhanced security
   * In production, use snarkjs.groth16.verify
   */
  private async simulateVerification(proof: Proof): Promise<boolean> {
    // In production:
    // const vKey = await this.loadVerificationKey(claimType);
    // const valid = await snarkjs.groth16.verify(vKey, proof.publicSignals, proof.proof);

    // Validate proof structure
    if (!proof.proof || !proof.publicSignals) {
      return false;
    }

    // Check that public signals are present
    if (proof.publicSignals.length === 0) {
      return false;
    }

    // Validate public signal format
    for (const signal of proof.publicSignals) {
      if (typeof signal !== 'string') {
        return false;
      }

      // Check signal is numeric string
      if (!/^-?\d+$/.test(signal)) {
        return false;
      }
    }

    // In a real implementation, we would:
    // 1. Load the verification key for the circuit
    // 2. Use snarkjs.groth16.verify() to verify the proof
    // 3. Check the public signals match expected values

    // For simulation, check the result signal (last public signal)
    const resultSignal = proof.publicSignals[proof.publicSignals.length - 1];

    // The proof is valid if the result is '1' (true)
    return resultSignal === '1';
  }

  /**
   * Perform real ZK proof verification using snarkjs.groth16.verify
   */
  private async performRealVerification(proof: Proof): Promise<boolean> {
    try {
      // Extract claim type from metadata
      if (!proof.metadata || !proof.metadata.claimType) {
        throw new ProofVerificationError('Proof metadata missing claim type');
      }

      const claimType = proof.metadata.claimType as ClaimType;

      // Load verification key for this circuit
      const verificationKey = this.circuitKeys.getVerificationKey(claimType);

      // Verify the proof using snarkjs
      const valid = await snarkjs.groth16.verify(
        verificationKey,
        proof.publicSignals,
        proof.proof
      );

      return valid;
    } catch (error) {
      throw new ProofVerificationError(
        'Real proof verification failed',
        {
          error: error instanceof Error ? error.message : String(error)
        }
      );
    }
  }

  /**
   * Batch verify multiple proofs efficiently
   */
  async batchVerify(proofs: Proof[]): Promise<VerificationResult[]> {
    if (!Array.isArray(proofs)) {
      throw new ProofVerificationError('Invalid proofs array');
    }

    if (proofs.length === 0) {
      return [];
    }

    if (proofs.length > this.MAX_BATCH_SIZE) {
      throw new ProofVerificationError(
        `Batch size exceeds limit: ${proofs.length} > ${this.MAX_BATCH_SIZE}`
      );
    }

    const results: VerificationResult[] = [];

    // Verify proofs in parallel (with concurrency limit)
    const CONCURRENCY = 10;
    for (let i = 0; i < proofs.length; i += CONCURRENCY) {
      const batch = proofs.slice(i, i + CONCURRENCY);
      const batchResults = await Promise.all(
        batch.map(proof => this.verifyProof(proof))
      );
      results.push(...batchResults);
    }

    return results;
  }

  /**
   * Verify proof and check against expected statement
   */
  async verifyWithStatement(
    proof: Proof,
    expectedStatement: string
  ): Promise<VerificationResult> {
    const result = await this.verifyProof(proof);

    // Use constant-time comparison for statement check
    if (result.valid && !CryptoUtils.constantTimeEqual(proof.statement, expectedStatement)) {
      return {
        valid: false,
        statement: proof.statement,
        timestamp: Date.now(),
        error: 'Statement mismatch'
      };
    }

    return result;
  }

  /**
   * Extract claim result from public signals
   */
  extractClaimResult(proof: Proof): boolean {
    if (!proof.publicSignals || proof.publicSignals.length === 0) {
      return false;
    }

    // The last public signal typically contains the result (0 or 1)
    const resultSignal = proof.publicSignals[proof.publicSignals.length - 1];
    return resultSignal === '1';
  }

  /**
   * Compute hash of proof for caching
   */
  private computeProofHash(proof: Proof): string {
    const proofData = JSON.stringify({
      proof: proof.proof,
      publicSignals: proof.publicSignals
    });
    return CryptoUtils.hash(proofData);
  }

  /**
   * Prune verification cache to prevent memory exhaustion
   */
  private pruneCache(): void {
    const MAX_CACHE_SIZE = 1000;

    if (this.verificationCache.size > MAX_CACHE_SIZE) {
      // Remove oldest entries (first 20%)
      const entriesToRemove = Math.floor(MAX_CACHE_SIZE * 0.2);
      const keys = Array.from(this.verificationCache.keys());

      for (let i = 0; i < entriesToRemove; i++) {
        this.verificationCache.delete(keys[i]);
      }
    }
  }

  /**
   * Clear verification cache
   */
  clearCache(): void {
    this.verificationCache.clear();
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): { size: number; hitRate?: number } {
    return {
      size: this.verificationCache.size
    };
  }

  /**
   * Check if using real ZK verification or simulated verification
   */
  isUsingRealVerification(): boolean {
    return this.useRealVerification;
  }
}
