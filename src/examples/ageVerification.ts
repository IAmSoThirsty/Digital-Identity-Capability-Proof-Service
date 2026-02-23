/**
 * Example: Age Verification
 * Demonstrates how to prove someone is over 18 without revealing their actual age
 */

import { DigitalIdentityProofService, ClaimType } from '../index';

async function ageVerificationExample() {
  console.log('=== Age Verification Example ===\n');

  // Initialize the service
  const service = new DigitalIdentityProofService('Government ID Issuer');

  // Step 1: Register an identity
  const identity = service.registerIdentity('public_key_123', [
    { name: 'name', value: 'Alice', timestamp: Date.now() },
    { name: 'dateOfBirth', value: '1990-05-15', timestamp: Date.now() }
  ]);
  console.log('Identity registered:', identity.id);

  // Step 2: Issue a credential with age attribute
  const credential = service.issueCredential(identity.id, [
    { name: 'age', value: 25, timestamp: Date.now() }
  ]);
  console.log('Credential issued:', credential.id);

  // Step 3: Generate a proof that the person is over 18
  const claim = {
    type: ClaimType.AGE_OVER,
    parameters: { threshold: 18 }
  };

  const privateData = {
    age: 25,
    salt: 12345
  };

  console.log('\nGenerating proof...');
  const proof = await service.generateProof(claim, privateData);
  console.log('Proof generated!');
  console.log('Statement:', proof.statement);

  // Step 4: Verify the proof
  console.log('\nVerifying proof...');
  const result = await service.verifyProof(proof);
  console.log('Verification result:', result.valid ? 'VALID ✓' : 'INVALID ✗');
  console.log('Statement verified:', result.statement);

  // Note: The actual age (25) is never revealed, only the proof that age >= 18
  console.log('\n✓ Privacy preserved: Actual age not disclosed');
}

// Run the example
if (require.main === module) {
  ageVerificationExample().catch(console.error);
}

export { ageVerificationExample };
