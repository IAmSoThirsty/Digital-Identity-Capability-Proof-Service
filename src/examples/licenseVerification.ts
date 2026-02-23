/**
 * Example: License Verification
 * Demonstrates how to prove someone has a valid engineering license
 */

import { DigitalIdentityProofService, ClaimType } from '../index';

async function licenseVerificationExample() {
  console.log('=== License Verification Example ===\n');

  const service = new DigitalIdentityProofService('Professional Licensing Board');

  // Register identity
  const identity = service.registerIdentity('public_key_456', [
    { name: 'name', value: 'Bob', timestamp: Date.now() },
    { name: 'profession', value: 'Engineer', timestamp: Date.now() }
  ]);
  console.log('Identity registered:', identity.id);

  // Issue credential with license information
  const futureDate = Date.now() + (365 * 24 * 60 * 60 * 1000); // 1 year from now
  const credential = service.issueCredential(identity.id, [
    { name: 'licenseType', value: 'Professional Engineer', timestamp: Date.now() },
    { name: 'expirationDate', value: futureDate, timestamp: Date.now() }
  ], futureDate);
  console.log('License credential issued:', credential.id);

  // Generate proof of valid engineering license
  const claim = {
    type: ClaimType.LICENSE_VALID,
    parameters: { licenseType: 'Professional Engineer' }
  };

  const privateData = {
    licenseType: 'Professional Engineer',
    expirationDate: futureDate,
    salt: 67890
  };

  console.log('\nGenerating proof...');
  const proof = await service.generateProof(claim, privateData);
  console.log('Proof generated!');
  console.log('Statement:', proof.statement);

  // Verify the proof
  console.log('\nVerifying proof...');
  const result = await service.verifyProof(proof);
  console.log('Verification result:', result.valid ? 'VALID ✓' : 'INVALID ✗');
  console.log('Statement verified:', result.statement);

  console.log('\n✓ Privacy preserved: License details not disclosed');
}

// Run the example
if (require.main === module) {
  licenseVerificationExample().catch(console.error);
}

export { licenseVerificationExample };
