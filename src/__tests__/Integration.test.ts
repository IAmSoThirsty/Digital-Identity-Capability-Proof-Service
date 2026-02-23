import { DigitalIdentityProofService } from '../index';
import { ClaimType } from '../types';

describe('DigitalIdentityProofService Integration', () => {
  let service: DigitalIdentityProofService;

  beforeEach(() => {
    service = new DigitalIdentityProofService('Test Authority');
  });

  it('should complete full identity lifecycle', async () => {
    // Register identity
    const identity = service.registerIdentity('pubkey_123', [
      { name: 'name', value: 'Alice', timestamp: Date.now() }
    ]);

    expect(identity.id).toBeDefined();

    // Issue credential
    const credential = service.issueCredential(identity.id, [
      { name: 'age', value: 25, timestamp: Date.now() }
    ]);

    expect(credential.identityId).toBe(identity.id);

    // Generate proof
    const proof = await service.generateProof(
      { type: ClaimType.AGE_OVER, parameters: { threshold: 18 } },
      { age: 25, salt: 123 }
    );

    expect(proof.statement).toContain('over 18');

    // Verify proof
    const result = await service.verifyProof(proof);

    expect(result.valid).toBe(true);

    // Revoke credential
    const revocation = service.revokeCredential(credential.id, 'Test revocation');

    expect(revocation.credentialId).toBe(credential.id);

    // Check revocation
    const isRevoked = service.isCredentialRevoked(credential.id);

    expect(isRevoked).toBe(true);
  });

  it('should reject credential issuance for non-existent identity', () => {
    expect(() => {
      service.issueCredential('fake_id', []);
    }).toThrow('Identity not found');
  });

  it('should provide access to all components', () => {
    expect(service.getIdentityRegistry()).toBeDefined();
    expect(service.getCredentialIssuer()).toBeDefined();
    expect(service.getProofGenerator()).toBeDefined();
    expect(service.getProofVerifier()).toBeDefined();
    expect(service.getRevocationRegistry()).toBeDefined();
  });
});
