import { ProofGenerator } from '../ProofGenerator';
import { ProofVerifier } from '../ProofVerifier';
import { ClaimType } from '../types';

describe('Proof Generation and Verification', () => {
  let generator: ProofGenerator;
  let verifier: ProofVerifier;

  beforeEach(() => {
    generator = new ProofGenerator();
    verifier = new ProofVerifier();
  });

  describe('Age Over Proof', () => {
    it('should generate and verify valid age proof', async () => {
      const claim = {
        type: ClaimType.AGE_OVER,
        parameters: { threshold: 18 }
      };

      const privateData = {
        age: 25,
        salt: 12345
      };

      const proof = await generator.generateProof(claim, privateData);

      expect(proof).toBeDefined();
      expect(proof.statement).toContain('over 18');
      expect(proof.publicSignals).toBeDefined();

      const result = await verifier.verifyProof(proof);

      expect(result.valid).toBe(true);
      expect(result.statement).toBe(proof.statement);
    });

    it('should fail verification for underage', async () => {
      const claim = {
        type: ClaimType.AGE_OVER,
        parameters: { threshold: 18 }
      };

      const privateData = {
        age: 15,
        salt: 12345
      };

      const proof = await generator.generateProof(claim, privateData);
      const result = await verifier.verifyProof(proof);

      expect(result.valid).toBe(false);
    });
  });

  describe('License Verification Proof', () => {
    it('should generate and verify valid license proof', async () => {
      const claim = {
        type: ClaimType.LICENSE_VALID,
        parameters: { licenseType: 'Professional Engineer' }
      };

      const futureDate = Date.now() + 100000;
      const privateData = {
        licenseType: 'Professional Engineer',
        expirationDate: futureDate,
        salt: 67890
      };

      const proof = await generator.generateProof(claim, privateData);

      expect(proof).toBeDefined();
      expect(proof.statement).toContain('Professional Engineer');

      const result = await verifier.verifyProof(proof);

      expect(result.valid).toBe(true);
    });
  });

  describe('Clearance Level Proof', () => {
    it('should generate and verify clearance proof', async () => {
      const claim = {
        type: ClaimType.CLEARANCE_LEVEL,
        parameters: { requiredLevel: 3 }
      };

      const privateData = {
        clearanceLevel: 4,
        salt: 11111
      };

      const proof = await generator.generateProof(claim, privateData);

      expect(proof).toBeDefined();
      expect(proof.statement).toContain('clearance level 3');

      const result = await verifier.verifyProof(proof);

      expect(result.valid).toBe(true);
    });

    it('should fail for insufficient clearance', async () => {
      const claim = {
        type: ClaimType.CLEARANCE_LEVEL,
        parameters: { requiredLevel: 5 }
      };

      const privateData = {
        clearanceLevel: 3,
        salt: 11111
      };

      const proof = await generator.generateProof(claim, privateData);
      const result = await verifier.verifyProof(proof);

      expect(result.valid).toBe(false);
    });
  });

  describe('Role Authorization Proof', () => {
    it('should generate and verify role proof', async () => {
      const claim = {
        type: ClaimType.ROLE_AUTHORIZATION,
        parameters: { role: 'election_official' }
      };

      const privateData = {
        role: 'election_official',
        salt: 22222
      };

      const proof = await generator.generateProof(claim, privateData);

      expect(proof).toBeDefined();
      expect(proof.statement).toContain('election_official');

      const result = await verifier.verifyProof(proof);

      expect(result.valid).toBe(true);
    });

    it('should fail for wrong role', async () => {
      const claim = {
        type: ClaimType.ROLE_AUTHORIZATION,
        parameters: { role: 'election_official' }
      };

      const privateData = {
        role: 'voter',
        salt: 22222
      };

      const proof = await generator.generateProof(claim, privateData);
      const result = await verifier.verifyProof(proof);

      expect(result.valid).toBe(false);
    });
  });

  describe('Batch Verification', () => {
    it('should verify multiple proofs', async () => {
      const proof1 = await generator.generateProof(
        { type: ClaimType.AGE_OVER, parameters: { threshold: 18 } },
        { age: 25, salt: 1 }
      );

      const proof2 = await generator.generateProof(
        { type: ClaimType.CLEARANCE_LEVEL, parameters: { requiredLevel: 2 } },
        { clearanceLevel: 3, salt: 2 }
      );

      const results = await verifier.batchVerify([proof1, proof2]);

      expect(results).toHaveLength(2);
      expect(results[0].valid).toBe(true);
      expect(results[1].valid).toBe(true);
    });
  });
});
