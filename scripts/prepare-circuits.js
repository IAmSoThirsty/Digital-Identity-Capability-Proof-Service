#!/usr/bin/env node

/**
 * Circuit Compilation and Trusted Setup Script
 *
 * This script automates the following steps for each circuit:
 * 1. Compile Circom circuit to R1CS and WASM
 * 2. Generate witness calculator
 * 3. Perform trusted setup ceremony (Powers of Tau + circuit-specific)
 * 4. Generate proving and verification keys
 *
 * For production use, replace the automated trusted setup with a proper
 * multi-party computation ceremony.
 */

const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const util = require('util');

const execPromise = util.promisify(exec);

const CIRCUITS_DIR = path.join(__dirname, '../circuits');
const BUILD_DIR = path.join(CIRCUITS_DIR, 'build');
const PTAU_FILE = path.join(BUILD_DIR, 'pot12_final.ptau');

const CIRCUITS = [
  { name: 'ageOver', file: 'ageOver.circom' },
  { name: 'licenseValid', file: 'licenseValid.circom' },
  { name: 'clearanceLevel', file: 'clearanceLevel.circom' },
  { name: 'roleAuthorization', file: 'roleAuthorization.circom' }
];

// Circuit complexity - determines Powers of Tau size
// 12 = 2^12 = 4096 constraints (sufficient for our circuits)
const PTAU_POWER = 12;

async function runCommand(command, description) {
  console.log(`\n📦 ${description}...`);
  console.log(`   Command: ${command}`);

  try {
    const { stdout, stderr } = await execPromise(command, {
      maxBuffer: 10 * 1024 * 1024 // 10MB buffer
    });
    if (stdout) console.log(stdout);
    if (stderr) console.error(stderr);
    console.log(`✅ ${description} completed`);
    return true;
  } catch (error) {
    console.error(`❌ ${description} failed:`, error.message);
    if (error.stdout) console.log(error.stdout);
    if (error.stderr) console.error(error.stderr);
    throw error;
  }
}

async function checkCircomInstalled() {
  try {
    await execPromise('circom --version');
    console.log('✅ Circom compiler found');
    return true;
  } catch (error) {
    console.error('❌ Circom compiler not found!');
    console.error('\nPlease install Circom:');
    console.error('  npm install -g circom');
    console.error('  Or visit: https://docs.circom.io/getting-started/installation/');
    return false;
  }
}

async function ensureBuildDirectory() {
  if (!fs.existsSync(BUILD_DIR)) {
    fs.mkdirSync(BUILD_DIR, { recursive: true });
    console.log(`✅ Created build directory: ${BUILD_DIR}`);
  }
}

async function downloadOrGeneratePtau() {
  console.log('\n🔧 Setting up Powers of Tau...');

  if (fs.existsSync(PTAU_FILE)) {
    console.log(`✅ Powers of Tau file already exists: ${PTAU_FILE}`);
    return;
  }

  console.log(`\n⚠️  WARNING: This will generate a NEW Powers of Tau file.`);
  console.log(`   For production, use a trusted ceremony file or multi-party computation!`);
  console.log(`   See: https://github.com/iden3/snarkjs#7-prepare-phase-2\n`);

  // Start a new powers of tau ceremony
  await runCommand(
    `npx snarkjs powersoftau new bn128 ${PTAU_POWER} ${path.join(BUILD_DIR, 'pot12_0000.ptau')} -v`,
    'Initialize Powers of Tau ceremony'
  );

  // Contribute to the ceremony (in production, this would be done by multiple parties)
  await runCommand(
    `npx snarkjs powersoftau contribute ${path.join(BUILD_DIR, 'pot12_0000.ptau')} ${path.join(BUILD_DIR, 'pot12_0001.ptau')} --name="First contribution" -v -e="random entropy"`,
    'First contribution to Powers of Tau'
  );

  // Prepare phase 2
  await runCommand(
    `npx snarkjs powersoftau prepare phase2 ${path.join(BUILD_DIR, 'pot12_0001.ptau')} ${PTAU_FILE} -v`,
    'Prepare Powers of Tau for Phase 2'
  );

  // Clean up intermediate files
  fs.unlinkSync(path.join(BUILD_DIR, 'pot12_0000.ptau'));
  fs.unlinkSync(path.join(BUILD_DIR, 'pot12_0001.ptau'));

  console.log(`✅ Powers of Tau setup complete: ${PTAU_FILE}`);
}

async function compileCircuit(circuit) {
  const circuitPath = path.join(CIRCUITS_DIR, circuit.file);
  const outputDir = BUILD_DIR;

  console.log(`\n\n═══════════════════════════════════════════════════`);
  console.log(`   Compiling Circuit: ${circuit.name}`);
  console.log(`═══════════════════════════════════════════════════`);

  // 1. Compile circuit
  await runCommand(
    `circom ${circuitPath} --r1cs --wasm --sym -o ${outputDir}`,
    `Compile ${circuit.name} circuit`
  );

  // 2. Generate witness calculator info
  await runCommand(
    `npx snarkjs r1cs info ${path.join(BUILD_DIR, `${circuit.name}.r1cs`)}`,
    `Get ${circuit.name} circuit info`
  );

  // 3. Setup proving key (Phase 2 of trusted setup)
  await runCommand(
    `npx snarkjs groth16 setup ${path.join(BUILD_DIR, `${circuit.name}.r1cs`)} ${PTAU_FILE} ${path.join(BUILD_DIR, `${circuit.name}_0000.zkey`)}`,
    `Setup ${circuit.name} proving key`
  );

  // 4. Contribute to circuit-specific setup
  await runCommand(
    `npx snarkjs zkey contribute ${path.join(BUILD_DIR, `${circuit.name}_0000.zkey`)} ${path.join(BUILD_DIR, `${circuit.name}.zkey`)} --name="Circuit contribution" -v -e="random entropy"`,
    `Contribute to ${circuit.name} setup`
  );

  // 5. Export verification key
  await runCommand(
    `npx snarkjs zkey export verificationkey ${path.join(BUILD_DIR, `${circuit.name}.zkey`)} ${path.join(BUILD_DIR, `${circuit.name}_verification_key.json`)}`,
    `Export ${circuit.name} verification key`
  );

  // 6. Clean up intermediate file
  fs.unlinkSync(path.join(BUILD_DIR, `${circuit.name}_0000.zkey`));

  console.log(`\n✅ ${circuit.name} circuit compilation complete!`);
  console.log(`   - WASM: ${path.join(BUILD_DIR, circuit.name + '_js', circuit.name + '.wasm')}`);
  console.log(`   - Proving Key: ${path.join(BUILD_DIR, `${circuit.name}.zkey`)}`);
  console.log(`   - Verification Key: ${path.join(BUILD_DIR, `${circuit.name}_verification_key.json`)}`);
}

async function main() {
  console.log('\n╔═══════════════════════════════════════════════════╗');
  console.log('║   ZK Circuit Compilation & Trusted Setup         ║');
  console.log('║   Digital Identity Capability Proof Service      ║');
  console.log('╚═══════════════════════════════════════════════════╝\n');

  try {
    // Check if circom is installed
    const hasCircom = await checkCircomInstalled();
    if (!hasCircom) {
      process.exit(1);
    }

    // Ensure build directory exists
    await ensureBuildDirectory();

    // Setup or download Powers of Tau
    await downloadOrGeneratePtau();

    // Compile each circuit
    for (const circuit of CIRCUITS) {
      await compileCircuit(circuit);
    }

    console.log('\n\n╔═══════════════════════════════════════════════════╗');
    console.log('║   ✅ ALL CIRCUITS COMPILED SUCCESSFULLY           ║');
    console.log('╚═══════════════════════════════════════════════════╝\n');

    console.log('📝 Next Steps:');
    console.log('   1. Review the generated keys in circuits/build/');
    console.log('   2. For production, conduct a proper trusted setup ceremony');
    console.log('   3. The system will now use real ZK proofs instead of simulations');
    console.log('   4. Run tests: npm test\n');

  } catch (error) {
    console.error('\n\n❌ Circuit compilation failed:', error.message);
    process.exit(1);
  }
}

// Run if called directly
if (require.main === module) {
  main().catch(console.error);
}

module.exports = { main, compileCircuit, downloadOrGeneratePtau };
