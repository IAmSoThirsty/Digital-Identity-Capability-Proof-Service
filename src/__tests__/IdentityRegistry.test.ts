import { IdentityRegistry } from '../IdentityRegistry';
import { Attribute } from '../types';

describe('IdentityRegistry', () => {
  let registry: IdentityRegistry;

  beforeEach(() => {
    registry = new IdentityRegistry();
  });

  describe('registerIdentity', () => {
    it('should register a new identity', () => {
      const attributes: Attribute[] = [
        { name: 'name', value: 'Alice', timestamp: Date.now() }
      ];

      const identity = registry.registerIdentity('public_key_123', attributes);

      expect(identity).toBeDefined();
      expect(identity.id).toMatch(/^id_/);
      expect(identity.publicKey).toBe('public_key_123');
      expect(identity.attributes).toEqual(attributes);
      expect(identity.createdAt).toBeDefined();
    });

    it('should generate unique identity IDs', () => {
      const identity1 = registry.registerIdentity('key1', []);
      const identity2 = registry.registerIdentity('key2', []);

      expect(identity1.id).not.toBe(identity2.id);
    });
  });

  describe('getIdentity', () => {
    it('should retrieve an existing identity', () => {
      const attributes: Attribute[] = [
        { name: 'age', value: 25, timestamp: Date.now() }
      ];
      const identity = registry.registerIdentity('public_key_123', attributes);

      const retrieved = registry.getIdentity(identity.id);

      expect(retrieved).toEqual(identity);
    });

    it('should return undefined for non-existent identity', () => {
      const retrieved = registry.getIdentity('non_existent_id');

      expect(retrieved).toBeUndefined();
    });
  });

  describe('updateAttributes', () => {
    it('should update identity attributes', () => {
      const identity = registry.registerIdentity('key', []);
      const newAttributes: Attribute[] = [
        { name: 'status', value: 'active', timestamp: Date.now() }
      ];

      const success = registry.updateAttributes(identity.id, newAttributes);
      const updated = registry.getIdentity(identity.id);

      expect(success).toBe(true);
      expect(updated?.attributes).toEqual(newAttributes);
    });

    it('should return false for non-existent identity', () => {
      const newAttributes: Attribute[] = [];
      const success = registry.updateAttributes('fake_id', newAttributes);

      expect(success).toBe(false);
    });
  });

  describe('hasIdentity', () => {
    it('should return true for existing identity', () => {
      const identity = registry.registerIdentity('key', []);

      expect(registry.hasIdentity(identity.id)).toBe(true);
    });

    it('should return false for non-existent identity', () => {
      expect(registry.hasIdentity('fake_id')).toBe(false);
    });
  });

  describe('getAllIdentities', () => {
    it('should return all registered identities', () => {
      const identity1 = registry.registerIdentity('key1', []);
      const identity2 = registry.registerIdentity('key2', []);

      const all = registry.getAllIdentities();

      expect(all).toHaveLength(2);
      expect(all).toContainEqual(identity1);
      expect(all).toContainEqual(identity2);
    });

    it('should return empty array when no identities', () => {
      const all = registry.getAllIdentities();

      expect(all).toEqual([]);
    });
  });
});
