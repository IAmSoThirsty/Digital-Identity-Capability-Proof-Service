/**
 * Example: Clearance Level Verification
 * Demonstrates proving sufficient security clearance for access control
 */

import { DigitalIdentityProofService, ClaimType } from '../index';

async function clearanceVerificationExample() {
  console.log('=== Clearance Level Verification Example ===\n');

  const service = new DigitalIdentityProofService('Security Clearance Authority');

  // Register identity
  const identity = service.registerIdentity('public_key_789', [
    { name: 'name', value: 'Carol', timestamp: Date.now() },
    { name: 'department', value: 'Research', timestamp: Date.now() }
  ]);
  console.log('Identity registered:', identity.id);

  // Issue credential with clearance level (0-5 scale)
  const credential = service.issueCredential(identity.id, [
    { name: 'clearanceLevel', value: 4, timestamp: Date.now() }
  ]);
  console.log('Clearance credential issued:', credential.id);

  // Generate proof of sufficient clearance (level 3 required)
  const claim = {
    type: ClaimType.CLEARANCE_LEVEL,
    parameters: { requiredLevel: 3 }
  };

  const privateData = {
    clearanceLevel: 4,
    salt: 11111
  };

  console.log('\nGenerating proof for level 3 access...');
  const proof = await service.generateProof(claim, privateData);
  console.log('Proof generated!');
  console.log('Statement:', proof.statement);

  // Verify the proof
  console.log('\nVerifying proof...');
  const result = await service.verifyProof(proof);
  console.log('Verification result:', result.valid ? 'VALID ✓' : 'INVALID ✗');
  console.log('Access granted:', result.valid ? 'YES' : 'NO');

  console.log('\n✓ Privacy preserved: Exact clearance level not disclosed');
}

// Run the example
if (require.main === module) {
  clearanceVerificationExample().catch(console.error);
}

export { clearanceVerificationExample };
