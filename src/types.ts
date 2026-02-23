/**
 * Core types for the Digital Identity Capability Proof Service
 */

export interface Attribute {
  name: string;
  value: string | number | boolean;
  timestamp: number;
}

export interface Identity {
  id: string;
  publicKey: string;
  attributes: Attribute[];
  createdAt: number;
}

export interface Credential {
  id: string;
  identityId: string;
  issuer: string;
  attributes: Attribute[];
  signature: string;
  issuedAt: number;
  expiresAt?: number;
}

export interface Proof {
  proof: any;
  publicSignals: string[];
  statement: string;
}

export interface VerificationResult {
  valid: boolean;
  statement: string;
  timestamp: number;
}

export interface RevocationRecord {
  credentialId: string;
  revokedAt: number;
  reason?: string;
}

export enum ClaimType {
  AGE_OVER = 'AGE_OVER',
  LICENSE_VALID = 'LICENSE_VALID',
  CLEARANCE_LEVEL = 'CLEARANCE_LEVEL',
  ROLE_AUTHORIZATION = 'ROLE_AUTHORIZATION'
}

export interface ClaimStatement {
  type: ClaimType;
  parameters: Record<string, any>;
}
