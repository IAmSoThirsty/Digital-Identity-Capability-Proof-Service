# ZK Circuit Compilation and Trusted Setup

This guide explains how to compile the Circom circuits and generate the necessary cryptographic keys for production-grade zero-knowledge proofs.

## Overview

The Digital Identity Capability Proof Service uses **Groth16** zero-knowledge proofs implemented in **Circom**. The system includes four circuits for different claim types:

1. **ageOver.circom** - Age verification (prove age >= threshold)
2. **licenseValid.circom** - License validation (prove valid license of specific type)
3. **clearanceLevel.circom** - Clearance level verification (prove level >= required)
4. **roleAuthorization.circom** - Role authorization (prove specific role)

## Prerequisites

### Install Circom Compiler

The Circom compiler is required to compile the circuits. Install it globally:

```bash
npm install -g circom
```

Or follow the official installation guide: https://docs.circom.io/getting-started/installation/

### Verify Installation

```bash
circom --version
```

You should see output like `circom compiler 2.x.x`.

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

This installs:
- `snarkjs` - zkSNARK toolkit for proof generation/verification
- `circomlib` - Standard Circom circuit library
- `circomlibjs` - JavaScript utilities for Poseidon hashing

### 2. Compile Circuits

Run the automated compilation script:

```bash
npm run prepare-circuits
```

This script will:
1. ✅ Check that Circom is installed
2. 🔧 Generate Powers of Tau (universal trusted setup)
3. 📦 Compile each circuit to R1CS and WASM
4. 🔑 Generate proving keys (circuit-specific setup)
5. 🔐 Export verification keys

**Expected output:**
```
╔═══════════════════════════════════════════════════╗
║   ZK Circuit Compilation & Trusted Setup         ║
║   Digital Identity Capability Proof Service      ║
╚═══════════════════════════════════════════════════╝

✅ Circom compiler found
✅ Created build directory: circuits/build/

🔧 Setting up Powers of Tau...
...
✅ ALL CIRCUITS COMPILED SUCCESSFULLY
```

### 3. Verify Compilation

After successful compilation, you should have the following files in `circuits/build/`:

```
circuits/build/
├── pot12_final.ptau                      # Powers of Tau (universal setup)
├── ageOver.r1cs                          # Constraint system
├── ageOver_js/
│   └── ageOver.wasm                      # Witness calculator
├── ageOver.zkey                          # Proving key
├── ageOver_verification_key.json         # Verification key
├── licenseValid.r1cs
├── licenseValid_js/
│   └── licenseValid.wasm
├── licenseValid.zkey
├── licenseValid_verification_key.json
├── clearanceLevel.r1cs
├── clearanceLevel_js/
│   └── clearanceLevel.wasm
├── clearanceLevel.zkey
├── clearanceLevel_verification_key.json
├── roleAuthorization.r1cs
├── roleAuthorization_js/
│   └── roleAuthorization.wasm
├── roleAuthorization.zkey
└── roleAuthorization_verification_key.json
```

### 4. Test the Implementation

Run tests to verify the circuits work correctly:

```bash
npm test
```

The system will automatically:
- ✅ Use **real ZK proofs** if circuits are compiled
- ⚠️  Fall back to simulated proofs if circuits are not compiled

## Production Deployment

### ⚠️ SECURITY WARNING

The automated `npm run prepare-circuits` script generates a **NEW** Powers of Tau ceremony for convenience. This is **NOT SECURE** for production use.

### For Production: Conduct a Proper Trusted Setup

A trusted setup ceremony ensures that no single party can compromise the system. For production deployment:

#### Option 1: Use Existing Trusted Setup

Download a pre-computed Powers of Tau file from a trusted ceremony:

```bash
# Download from Perpetual Powers of Tau (recommended)
wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_12.ptau
mv powersOfTau28_hez_final_12.ptau circuits/build/pot12_final.ptau
```

Then run the circuit-specific setup:

```bash
# For each circuit (example for ageOver)
npx snarkjs groth16 setup circuits/build/ageOver.r1cs circuits/build/pot12_final.ptau circuits/build/ageOver_0000.zkey
npx snarkjs zkey contribute circuits/build/ageOver_0000.zkey circuits/build/ageOver.zkey --name="My contribution" -v
npx snarkjs zkey export verificationkey circuits/build/ageOver.zkey circuits/build/ageOver_verification_key.json
```

#### Option 2: Multi-Party Computation (MPC)

For maximum security, conduct a multi-party trusted setup ceremony:

1. **Phase 1 (Powers of Tau):**
   - Start ceremony: `npx snarkjs powersoftau new bn128 12 pot12_0000.ptau`
   - Multiple parties contribute: `npx snarkjs powersoftau contribute`
   - Prepare phase 2: `npx snarkjs powersoftau prepare phase2`

2. **Phase 2 (Circuit-specific):**
   - Setup: `npx snarkjs groth16 setup`
   - Multiple parties contribute: `npx snarkjs zkey contribute`
   - Export verification key: `npx snarkjs zkey export verificationkey`

See the [snarkjs documentation](https://github.com/iden3/snarkjs#7-prepare-phase-2) for detailed instructions.

### Security Checklist

Before deploying to production:

- [ ] Conducted proper trusted setup ceremony (MPC or trusted source)
- [ ] Verified all circuit compilations
- [ ] Backed up proving and verification keys securely
- [ ] Tested proof generation and verification
- [ ] Reviewed circuit logic for correctness
- [ ] Conducted security audit
- [ ] Implemented secure key storage
- [ ] Set up rate limiting and DoS protection
- [ ] Enabled audit logging
- [ ] Configured proper access controls

## Circuit Details

### Age Over Circuit

**File:** `circuits/ageOver.circom`

**Public Inputs:**
- `threshold` - Minimum age requirement

**Private Inputs:**
- `age` - User's actual age
- `salt` - Random value for privacy

**Public Outputs:**
- `ageHash` - Poseidon hash of (age, salt)
- `isOver` - 1 if age >= threshold, 0 otherwise

### License Valid Circuit

**File:** `circuits/licenseValid.circom`

**Public Inputs:**
- `requiredLicenseType` - Required license type (hashed)
- `currentDate` - Current timestamp

**Private Inputs:**
- `licenseType` - User's license type (hashed)
- `expirationDate` - License expiration timestamp
- `salt` - Random value for privacy

**Public Outputs:**
- `licenseHash` - Poseidon hash of (licenseType, expirationDate, salt)
- `isValid` - 1 if valid, 0 otherwise

### Clearance Level Circuit

**File:** `circuits/clearanceLevel.circom`

**Public Inputs:**
- `requiredLevel` - Minimum clearance level

**Private Inputs:**
- `actualLevel` - User's clearance level
- `salt` - Random value for privacy

**Public Outputs:**
- `clearanceHash` - Poseidon hash of (actualLevel, salt)
- `hasAccess` - 1 if actualLevel >= requiredLevel, 0 otherwise

### Role Authorization Circuit

**File:** `circuits/roleAuthorization.circom`

**Public Inputs:**
- `requiredRole` - Required role (hashed)

**Private Inputs:**
- `userRole` - User's role (hashed)
- `salt` - Random value for privacy

**Public Outputs:**
- `roleHash` - Poseidon hash of (userRole, salt)
- `isAuthorized` - 1 if roles match, 0 otherwise

## Troubleshooting

### "Circom not found"

Install Circom globally:
```bash
npm install -g circom
```

### "Powers of Tau file too small"

If you need larger circuits, increase the `PTAU_POWER` in `scripts/prepare-circuits.js`:
```javascript
const PTAU_POWER = 15; // 2^15 = 32768 constraints
```

### "Circuit compilation failed"

1. Check that circomlib is installed: `npm install`
2. Verify circuit syntax: `circom circuits/ageOver.circom --r1cs --wasm --sym`
3. Check for syntax errors in the circuit files

### "Proof generation is slow"

- First proof generation is slower due to WASM initialization
- Subsequent proofs are much faster
- Consider using batch verification for multiple proofs
- For production, use a dedicated proving server

## API Usage

### Check Circuit Status

```typescript
import { CircuitKeys } from './src/CircuitKeys';

const circuitKeys = CircuitKeys.getInstance();
const status = circuitKeys.getCircuitStatus();

console.log('Circuits ready:', status.allReady);
console.log('Individual circuits:', status.circuits);
```

### Generate Real ZK Proof

```typescript
import { ProofGenerator } from './src/ProofGenerator';
import { ClaimType } from './src/types';

const generator = new ProofGenerator(true); // true = use real proofs

const claim = {
  type: ClaimType.AGE_OVER,
  parameters: { threshold: 18 }
};

const privateData = {
  age: 25,
  salt: 12345
};

const proof = await generator.generateProof(claim, privateData);
console.log('Using real proofs:', generator.isUsingRealProofs());
```

### Verify Real ZK Proof

```typescript
import { ProofVerifier } from './src/ProofVerifier';

const verifier = new ProofVerifier(true); // true = use real verification

const result = await verifier.verifyProof(proof);
console.log('Proof valid:', result.valid);
console.log('Using real verification:', verifier.isUsingRealVerification());
```

## Resources

- [Circom Documentation](https://docs.circom.io/)
- [snarkjs Documentation](https://github.com/iden3/snarkjs)
- [Groth16 Paper](https://eprint.iacr.org/2016/260.pdf)
- [Trusted Setup Ceremonies](https://medium.com/qed-it/diving-into-the-snarks-setup-phase-b7660242a0d7)
- [PRODUCTION_SECURITY.md](./PRODUCTION_SECURITY.md) - Additional security considerations

## License

MIT
