import { RevocationRegistry } from '../RevocationRegistry';

describe('RevocationRegistry', () => {
  let registry: RevocationRegistry;

  // Valid credential ID format: cred_ followed by 32 hex characters
  const validCredId1 = 'cred_0123456789abcdef0123456789abcdef';
  const validCredId2 = 'cred_fedcba9876543210fedcba9876543210';
  const validCredId3 = 'cred_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const validCredId999 = 'cred_9999999999999999999999999999999';

  beforeEach(() => {
    registry = new RevocationRegistry();
  });

  describe('revokeCredential', () => {
    it('should revoke a credential', () => {
      const record = registry.revokeCredential(validCredId1, 'Expired');

      expect(record).toBeDefined();
      expect(record.credentialId).toBe(validCredId1);
      expect(record.reason).toBe('Expired');
      expect(record.revokedAt).toBeDefined();
    });

    it('should revoke credential without reason', () => {
      const record = registry.revokeCredential(validCredId1);

      expect(record.reason).toBeUndefined();
    });
  });

  describe('isRevoked', () => {
    it('should return true for revoked credential', () => {
      registry.revokeCredential(validCredId1);

      expect(registry.isRevoked(validCredId1)).toBe(true);
    });

    it('should return false for non-revoked credential', () => {
      expect(registry.isRevoked(validCredId1)).toBe(false);
    });
  });

  describe('getRevocationRecord', () => {
    it('should return revocation record', () => {
      const record = registry.revokeCredential(validCredId1, 'Test');
      const retrieved = registry.getRevocationRecord(validCredId1);

      expect(retrieved).toEqual(record);
    });

    it('should return undefined for non-revoked credential', () => {
      const retrieved = registry.getRevocationRecord(validCredId999);

      expect(retrieved).toBeUndefined();
    });
  });

  describe('getAllRevocations', () => {
    it('should return all revocations', () => {
      const record1 = registry.revokeCredential(validCredId1);
      const record2 = registry.revokeCredential(validCredId2);

      const all = registry.getAllRevocations();

      expect(all).toHaveLength(2);
      expect(all).toContainEqual(record1);
      expect(all).toContainEqual(record2);
    });
  });

  describe('restoreCredential', () => {
    it('should restore a revoked credential', () => {
      registry.revokeCredential(validCredId1);
      const success = registry.restoreCredential(validCredId1);

      expect(success).toBe(true);
      expect(registry.isRevoked(validCredId1)).toBe(false);
    });

    it('should return false for non-revoked credential', () => {
      const success = registry.restoreCredential(validCredId999);

      expect(success).toBe(false);
    });
  });

  describe('batchCheckRevocation', () => {
    it('should check multiple credentials', () => {
      registry.revokeCredential(validCredId1);
      registry.revokeCredential(validCredId2);

      const results = registry.batchCheckRevocation([validCredId1, validCredId2, validCredId3]);

      expect(results.get(validCredId1)).toBe(true);
      expect(results.get(validCredId2)).toBe(true);
      expect(results.get(validCredId3)).toBe(false);
    });
  });

  describe('getStatistics', () => {
    it('should return revocation statistics', () => {
      registry.revokeCredential(validCredId1, 'expired');
      registry.revokeCredential(validCredId2, 'expired');
      registry.revokeCredential(validCredId3, 'fraud');

      const stats = registry.getStatistics();

      expect(stats.totalRevocations).toBe(3);
      expect(stats.revocationsByReason.get('expired')).toBe(2);
      expect(stats.revocationsByReason.get('fraud')).toBe(1);
    });
  });
});
