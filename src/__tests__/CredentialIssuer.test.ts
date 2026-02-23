import { CredentialIssuer } from '../CredentialIssuer';
import { Attribute } from '../types';

describe('CredentialIssuer', () => {
  let issuer: CredentialIssuer;

  beforeEach(() => {
    issuer = new CredentialIssuer('Test Issuer');
  });

  describe('issueCredential', () => {
    it('should issue a credential', () => {
      const attributes: Attribute[] = [
        { name: 'age', value: 25, timestamp: Date.now() }
      ];

      const credential = issuer.issueCredential('identity_123', attributes);

      expect(credential).toBeDefined();
      expect(credential.id).toMatch(/^cred_/);
      expect(credential.identityId).toBe('identity_123');
      expect(credential.issuer).toBe('Test Issuer');
      expect(credential.attributes).toEqual(attributes);
      expect(credential.signature).toBeDefined();
      expect(credential.issuedAt).toBeDefined();
    });

    it('should issue credential with expiration', () => {
      const futureDate = Date.now() + 10000;
      const credential = issuer.issueCredential('identity_123', [], futureDate);

      expect(credential.expiresAt).toBe(futureDate);
    });
  });

  describe('getCredential', () => {
    it('should retrieve an issued credential', () => {
      const credential = issuer.issueCredential('identity_123', []);
      const retrieved = issuer.getCredential(credential.id);

      expect(retrieved).toEqual(credential);
    });

    it('should return undefined for non-existent credential', () => {
      const retrieved = issuer.getCredential('fake_id');

      expect(retrieved).toBeUndefined();
    });
  });

  describe('verifyCredential', () => {
    it('should verify a valid credential', () => {
      const attributes: Attribute[] = [
        { name: 'test', value: 'value', timestamp: Date.now() }
      ];
      const credential = issuer.issueCredential('identity_123', attributes);

      const isValid = issuer.verifyCredential(credential);

      expect(isValid).toBe(true);
    });

    it('should reject tampered credential', () => {
      const credential = issuer.issueCredential('identity_123', []);
      credential.signature = 'tampered_signature';

      const isValid = issuer.verifyCredential(credential);

      expect(isValid).toBe(false);
    });
  });

  describe('isExpired', () => {
    it('should return false for non-expiring credential', () => {
      const credential = issuer.issueCredential('identity_123', []);

      expect(issuer.isExpired(credential)).toBe(false);
    });

    it('should return false for future expiration', () => {
      const futureDate = Date.now() + 100000;
      const credential = issuer.issueCredential('identity_123', [], futureDate);

      expect(issuer.isExpired(credential)).toBe(false);
    });

    it('should return true for past expiration', () => {
      const pastDate = Date.now() - 10000;
      const credential = issuer.issueCredential('identity_123', [], pastDate);

      expect(issuer.isExpired(credential)).toBe(true);
    });
  });

  describe('getCredentialsForIdentity', () => {
    it('should return all credentials for an identity', () => {
      const cred1 = issuer.issueCredential('identity_123', []);
      const cred2 = issuer.issueCredential('identity_123', []);
      issuer.issueCredential('identity_456', []);

      const credentials = issuer.getCredentialsForIdentity('identity_123');

      expect(credentials).toHaveLength(2);
      expect(credentials).toContainEqual(cred1);
      expect(credentials).toContainEqual(cred2);
    });

    it('should return empty array for identity with no credentials', () => {
      const credentials = issuer.getCredentialsForIdentity('identity_999');

      expect(credentials).toEqual([]);
    });
  });
});
