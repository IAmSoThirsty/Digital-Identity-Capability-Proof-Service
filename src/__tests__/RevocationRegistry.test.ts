import { RevocationRegistry } from '../RevocationRegistry';

describe('RevocationRegistry', () => {
  let registry: RevocationRegistry;

  beforeEach(() => {
    registry = new RevocationRegistry();
  });

  describe('revokeCredential', () => {
    it('should revoke a credential', () => {
      const record = registry.revokeCredential('cred_123', 'Expired');

      expect(record).toBeDefined();
      expect(record.credentialId).toBe('cred_123');
      expect(record.reason).toBe('Expired');
      expect(record.revokedAt).toBeDefined();
    });

    it('should revoke credential without reason', () => {
      const record = registry.revokeCredential('cred_123');

      expect(record.reason).toBeUndefined();
    });
  });

  describe('isRevoked', () => {
    it('should return true for revoked credential', () => {
      registry.revokeCredential('cred_123');

      expect(registry.isRevoked('cred_123')).toBe(true);
    });

    it('should return false for non-revoked credential', () => {
      expect(registry.isRevoked('cred_123')).toBe(false);
    });
  });

  describe('getRevocationRecord', () => {
    it('should return revocation record', () => {
      const record = registry.revokeCredential('cred_123', 'Test');
      const retrieved = registry.getRevocationRecord('cred_123');

      expect(retrieved).toEqual(record);
    });

    it('should return undefined for non-revoked credential', () => {
      const retrieved = registry.getRevocationRecord('cred_999');

      expect(retrieved).toBeUndefined();
    });
  });

  describe('getAllRevocations', () => {
    it('should return all revocations', () => {
      const record1 = registry.revokeCredential('cred_1');
      const record2 = registry.revokeCredential('cred_2');

      const all = registry.getAllRevocations();

      expect(all).toHaveLength(2);
      expect(all).toContainEqual(record1);
      expect(all).toContainEqual(record2);
    });
  });

  describe('restoreCredential', () => {
    it('should restore a revoked credential', () => {
      registry.revokeCredential('cred_123');
      const success = registry.restoreCredential('cred_123');

      expect(success).toBe(true);
      expect(registry.isRevoked('cred_123')).toBe(false);
    });

    it('should return false for non-revoked credential', () => {
      const success = registry.restoreCredential('cred_999');

      expect(success).toBe(false);
    });
  });

  describe('batchCheckRevocation', () => {
    it('should check multiple credentials', () => {
      registry.revokeCredential('cred_1');
      registry.revokeCredential('cred_2');

      const results = registry.batchCheckRevocation(['cred_1', 'cred_2', 'cred_3']);

      expect(results.get('cred_1')).toBe(true);
      expect(results.get('cred_2')).toBe(true);
      expect(results.get('cred_3')).toBe(false);
    });
  });

  describe('getStatistics', () => {
    it('should return revocation statistics', () => {
      registry.revokeCredential('cred_1', 'expired');
      registry.revokeCredential('cred_2', 'expired');
      registry.revokeCredential('cred_3', 'fraud');

      const stats = registry.getStatistics();

      expect(stats.totalRevocations).toBe(3);
      expect(stats.revocationsByReason.get('expired')).toBe(2);
      expect(stats.revocationsByReason.get('fraud')).toBe(1);
    });
  });
});
