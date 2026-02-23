import { RevocationRecord } from './types';

/**
 * Revocation Registry
 * Manages credential revocations
 */
export class RevocationRegistry {
  private revocations: Map<string, RevocationRecord>;

  constructor() {
    this.revocations = new Map();
  }

  /**
   * Revoke a credential
   */
  revokeCredential(credentialId: string, reason?: string): RevocationRecord {
    const record: RevocationRecord = {
      credentialId,
      revokedAt: Date.now(),
      reason
    };

    this.revocations.set(credentialId, record);
    return record;
  }

  /**
   * Check if a credential is revoked
   */
  isRevoked(credentialId: string): boolean {
    return this.revocations.has(credentialId);
  }

  /**
   * Get revocation record for a credential
   */
  getRevocationRecord(credentialId: string): RevocationRecord | undefined {
    return this.revocations.get(credentialId);
  }

  /**
   * Get all revoked credentials
   */
  getAllRevocations(): RevocationRecord[] {
    return Array.from(this.revocations.values());
  }

  /**
   * Restore a revoked credential (if needed)
   */
  restoreCredential(credentialId: string): boolean {
    return this.revocations.delete(credentialId);
  }

  /**
   * Get revocations within a time range
   */
  getRevocationsInRange(startTime: number, endTime: number): RevocationRecord[] {
    return Array.from(this.revocations.values()).filter(
      record => record.revokedAt >= startTime && record.revokedAt <= endTime
    );
  }

  /**
   * Generate a revocation proof (Merkle tree based)
   * In production, use a Merkle tree accumulator for efficient revocation checks
   */
  generateRevocationProof(credentialId: string): {
    revoked: boolean;
    proof: string[];
  } {
    const revoked = this.isRevoked(credentialId);

    // In production, this would return a Merkle proof
    // For now, we return a simple structure
    return {
      revoked,
      proof: revoked ? ['revocation_proof_placeholder'] : []
    };
  }

  /**
   * Batch check multiple credentials for revocation
   */
  batchCheckRevocation(credentialIds: string[]): Map<string, boolean> {
    const results = new Map<string, boolean>();

    for (const credentialId of credentialIds) {
      results.set(credentialId, this.isRevoked(credentialId));
    }

    return results;
  }

  /**
   * Get statistics about revocations
   */
  getStatistics(): {
    totalRevocations: number;
    recentRevocations: number;
    revocationsByReason: Map<string, number>;
  } {
    const total = this.revocations.size;
    const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;

    let recent = 0;
    const byReason = new Map<string, number>();

    for (const record of this.revocations.values()) {
      if (record.revokedAt >= oneDayAgo) {
        recent++;
      }

      const reason = record.reason || 'unspecified';
      byReason.set(reason, (byReason.get(reason) || 0) + 1);
    }

    return {
      totalRevocations: total,
      recentRevocations: recent,
      revocationsByReason: byReason
    };
  }
}
