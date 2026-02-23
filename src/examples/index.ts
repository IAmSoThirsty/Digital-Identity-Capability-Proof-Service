/**
 * Run all examples
 */

import { ageVerificationExample } from './ageVerification';
import { licenseVerificationExample } from './licenseVerification';
import { clearanceVerificationExample } from './clearanceVerification';
import { roleAuthorizationExample } from './roleAuthorization';

async function runAllExamples() {
  console.log('╔════════════════════════════════════════════════════════╗');
  console.log('║  Digital Identity Capability Proof Service Examples   ║');
  console.log('╚════════════════════════════════════════════════════════╝\n');

  try {
    await ageVerificationExample();
    console.log('\n' + '─'.repeat(60) + '\n');

    await licenseVerificationExample();
    console.log('\n' + '─'.repeat(60) + '\n');

    await clearanceVerificationExample();
    console.log('\n' + '─'.repeat(60) + '\n');

    await roleAuthorizationExample();

    console.log('\n' + '═'.repeat(60));
    console.log('All examples completed successfully! ✓');
    console.log('═'.repeat(60));
  } catch (error) {
    console.error('Error running examples:', error);
  }
}

// Run all examples
if (require.main === module) {
  runAllExamples();
}

export { runAllExamples };
