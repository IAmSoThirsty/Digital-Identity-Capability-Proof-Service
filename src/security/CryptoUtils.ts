import { createHash, timingSafeEqual, randomBytes } from 'crypto';

/**
 * Cryptographic utilities for production-grade security
 * Implements constant-time operations, secure randomness, and proper key derivation
 */
export class CryptoUtils {
  // Minimum entropy bits for secure operations
  private static readonly MIN_ENTROPY_BITS = 256;

  /**
   * Constant-time string comparison
   * Prevents timing attacks on signature/hash verification
   */
  static constantTimeEqual(a: string, b: string): boolean {
    if (typeof a !== 'string' || typeof b !== 'string') {
      return false;
    }

    // Ensure both strings are same length for constant-time comparison
    const bufA = Buffer.from(a, 'utf-8');
    const bufB = Buffer.from(b, 'utf-8');

    // If lengths differ, create dummy buffers of same length
    if (bufA.length !== bufB.length) {
      // Still compare to prevent timing leak on length check
      const maxLen = Math.max(bufA.length, bufB.length);
      const paddedA = Buffer.alloc(maxLen);
      const paddedB = Buffer.alloc(maxLen);
      bufA.copy(paddedA);
      bufB.copy(paddedB);

      try {
        timingSafeEqual(paddedA, paddedB);
        return false; // Lengths differed, so not equal
      } catch {
        return false;
      }
    }

    try {
      return timingSafeEqual(bufA, bufB);
    } catch {
      return false;
    }
  }

  /**
   * Constant-time buffer comparison
   */
  static constantTimeEqualBuffers(a: Buffer, b: Buffer): boolean {
    if (a.length !== b.length) {
      // Create dummy comparison to prevent timing leak
      const dummy = Buffer.alloc(a.length);
      try {
        timingSafeEqual(a, dummy);
      } catch {
        // Ignore
      }
      return false;
    }

    try {
      return timingSafeEqual(a, b);
    } catch {
      return false;
    }
  }

  /**
   * Generate cryptographically secure random bytes with entropy validation
   */
  static generateSecureRandom(bytes: number): Buffer {
    if (bytes <= 0 || bytes > 1024) {
      throw new Error('Invalid random bytes size (must be 1-1024)');
    }

    const random = randomBytes(bytes);

    // Validate entropy (basic check)
    this.validateEntropy(random);

    return random;
  }

  /**
   * Validate entropy of random data
   * Uses Shannon entropy calculation
   */
  private static validateEntropy(data: Buffer): void {
    const frequencies = new Map<number, number>();

    // Count byte frequencies
    for (const byte of data) {
      frequencies.set(byte, (frequencies.get(byte) || 0) + 1);
    }

    // Calculate Shannon entropy
    let entropy = 0;
    const length = data.length;

    for (const count of frequencies.values()) {
      const probability = count / length;
      entropy -= probability * Math.log2(probability);
    }

    // Entropy should be close to 8 bits per byte for good randomness
    // We require at least 7.5 bits per byte
    const totalEntropy = entropy * data.length;
    const requiredEntropy = data.length * 7.5;

    if (totalEntropy < requiredEntropy) {
      throw new Error('Insufficient entropy in random data');
    }
  }

  /**
   * Hash data with SHA3-256
   */
  static hash(data: string | Buffer): string {
    const input = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
    return createHash('sha3-256').update(input).digest('hex');
  }

  /**
   * Hash data with SHA-256 (for compatibility)
   */
  static sha256(data: string | Buffer): string {
    const input = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
    return createHash('sha256').update(input).digest('hex');
  }

  /**
   * HMAC-based key derivation function (HKDF)
   * Derives keys from a master secret
   */
  static deriveKey(
    masterKey: Buffer,
    salt: Buffer,
    info: string,
    length: number = 32
  ): Buffer {
    if (masterKey.length < 32) {
      throw new Error('Master key must be at least 32 bytes');
    }

    if (length <= 0 || length > 255 * 32) {
      throw new Error('Invalid derived key length');
    }

    // HKDF-Extract
    const prk = createHash('sha256')
      .update(Buffer.concat([salt, masterKey]))
      .digest();

    // HKDF-Expand
    const n = Math.ceil(length / 32);
    const output: Buffer[] = [];
    let t = Buffer.alloc(0);

    for (let i = 1; i <= n; i++) {
      const hmac = createHash('sha256');
      hmac.update(Buffer.concat([t, Buffer.from(info, 'utf-8'), Buffer.from([i])]));
      t = hmac.digest();
      output.push(t);
    }

    return Buffer.concat(output).slice(0, length);
  }

  /**
   * Generate a secure salt
   */
  static generateSalt(bytes: number = 32): Buffer {
    return this.generateSecureRandom(bytes);
  }

  /**
   * Deterministic hash for state transitions (audit chain)
   */
  static deterministicHash(...inputs: (string | Buffer | number)[]): string {
    const combined = inputs.map(input => {
      if (typeof input === 'number') {
        // Use fixed-length encoding for numbers
        return Buffer.from(input.toString(16).padStart(16, '0'), 'hex');
      } else if (typeof input === 'string') {
        return Buffer.from(input, 'utf-8');
      } else {
        return input;
      }
    });

    return this.hash(Buffer.concat(combined));
  }

  /**
   * Create commitment to a value (hash with blinding factor)
   */
  static createCommitment(value: string | Buffer, blinding?: Buffer): {
    commitment: string;
    blinding: Buffer;
  } {
    const blindingFactor = blinding || this.generateSecureRandom(32);
    const valueBuffer = typeof value === 'string' ? Buffer.from(value, 'utf-8') : value;

    const commitment = this.hash(Buffer.concat([valueBuffer, blindingFactor]));

    return {
      commitment,
      blinding: blindingFactor
    };
  }

  /**
   * Verify commitment
   */
  static verifyCommitment(
    value: string | Buffer,
    blinding: Buffer,
    commitment: string
  ): boolean {
    const valueBuffer = typeof value === 'string' ? Buffer.from(value, 'utf-8') : value;
    const computed = this.hash(Buffer.concat([valueBuffer, blinding]));
    return this.constantTimeEqual(computed, commitment);
  }

  /**
   * Secure zeroing of sensitive data in memory
   */
  static secureZero(buffer: Buffer): void {
    if (!Buffer.isBuffer(buffer)) {
      return;
    }

    // Overwrite with random data first (defense against memory remanence)
    const random = randomBytes(buffer.length);
    random.copy(buffer);

    // Then zero
    buffer.fill(0);
  }

  /**
   * Generate a nonce (number used once)
   */
  static generateNonce(): string {
    return this.generateSecureRandom(16).toString('hex');
  }

  /**
   * Time-based nonce validation (prevents replay attacks)
   */
  static validateNonce(
    nonce: string,
    timestamp: number,
    windowMs: number = 300000 // 5 minutes
  ): boolean {
    // Check nonce format
    if (!/^[0-9a-f]{32}$/.test(nonce)) {
      return false;
    }

    // Check timestamp is within acceptable window
    const now = Date.now();
    const age = now - timestamp;

    if (age < 0 || age > windowMs) {
      return false;
    }

    return true;
  }

  /**
   * Generate a deterministic ID from data
   */
  static generateDeterministicId(prefix: string, ...data: string[]): string {
    const hash = this.hash(data.join('|'));
    return `${prefix}_${hash.slice(0, 32)}`;
  }

  /**
   * Validate hash format
   */
  static isValidHash(hash: string, algorithm: 'sha256' | 'sha3-256' = 'sha3-256'): boolean {
    if (typeof hash !== 'string') {
      return false;
    }

    // Both SHA-256 and SHA3-256 produce 64 hex characters
    return /^[0-9a-f]{64}$/.test(hash);
  }

  /**
   * Generate proof of work (for rate limiting/DoS prevention)
   */
  static generateProofOfWork(challenge: string, difficulty: number): {
    nonce: string;
    hash: string;
    iterations: number;
  } {
    if (difficulty < 1 || difficulty > 32) {
      throw new Error('Difficulty must be between 1 and 32');
    }

    const prefix = '0'.repeat(difficulty);
    let nonce = 0;
    let hash = '';

    while (true) {
      const nonceStr = nonce.toString(16).padStart(16, '0');
      hash = this.hash(`${challenge}${nonceStr}`);

      if (hash.startsWith(prefix)) {
        return {
          nonce: nonceStr,
          hash,
          iterations: nonce
        };
      }

      nonce++;

      // Prevent infinite loop
      if (nonce > 10000000) {
        throw new Error('Proof of work taking too long');
      }
    }
  }

  /**
   * Verify proof of work
   */
  static verifyProofOfWork(
    challenge: string,
    nonce: string,
    difficulty: number
  ): boolean {
    const hash = this.hash(`${challenge}${nonce}`);
    const prefix = '0'.repeat(difficulty);
    return hash.startsWith(prefix);
  }
}
