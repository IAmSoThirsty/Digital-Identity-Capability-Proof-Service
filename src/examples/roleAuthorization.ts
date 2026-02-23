/**
 * Example: Role Authorization
 * Demonstrates proving authorized role for election official verification
 */

import { DigitalIdentityProofService, ClaimType } from '../index';

async function roleAuthorizationExample() {
  console.log('=== Role Authorization Example ===\n');

  const service = new DigitalIdentityProofService('Election Commission');

  // Register identity
  const identity = service.registerIdentity('public_key_012', [
    { name: 'name', value: 'David', timestamp: Date.now() },
    { name: 'state', value: 'California', timestamp: Date.now() }
  ]);
  console.log('Identity registered:', identity.id);

  // Issue credential with role
  const credential = service.issueCredential(identity.id, [
    { name: 'role', value: 'election_official', timestamp: Date.now() }
  ]);
  console.log('Role credential issued:', credential.id);

  // Generate proof of election official authorization
  const claim = {
    type: ClaimType.ROLE_AUTHORIZATION,
    parameters: { role: 'election_official' }
  };

  const privateData = {
    role: 'election_official',
    salt: 22222
  };

  console.log('\nGenerating proof of election official role...');
  const proof = await service.generateProof(claim, privateData);
  console.log('Proof generated!');
  console.log('Statement:', proof.statement);

  // Verify the proof
  console.log('\nVerifying proof...');
  const result = await service.verifyProof(proof);
  console.log('Verification result:', result.valid ? 'VALID ✓' : 'INVALID ✗');
  console.log('Authorization:', result.valid ? 'GRANTED' : 'DENIED');

  console.log('\n✓ Privacy preserved: Personal identity not disclosed');
}

// Run the example
if (require.main === module) {
  roleAuthorizationExample().catch(console.error);
}

export { roleAuthorizationExample };
