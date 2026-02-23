/**
 * Interface Contracts for DICPS
 * Complete TypeScript interface definitions for all architectural layers
 */

// ============================================================================
// LAYER 1: PRESENTATION LAYER CONTRACTS
// ============================================================================

export interface PresentationLayerContract {
  handleRequest(request: Request): Promise<Response>;
  validateRequest(request: Request): ValidationResult;
  formatResponse(data: any): Response;
  handleError(error: Error): ErrorResponse;
  authenticate(credentials: Credentials): AuthToken;
  authorize(token: AuthToken, resource: Resource): boolean;
}

export interface Request {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: any;
  query: Record<string, string>;
  params: Record<string, string>;
}

export interface Response {
  statusCode: number;
  headers: Record<string, string>;
  body: any;
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
}

export interface ValidationError {
  field: string;
  message: string;
  code: string;
}

export interface Credentials {
  username?: string;
  password?: string;
  apiKey?: string;
  token?: string;
}

export interface AuthToken {
  token: string;
  type: string;
  expiresAt: number;
  scopes: string[];
}

export interface Resource {
  type: string;
  id: string;
  action: string;
}

export interface ErrorResponse {
  code: string;
  message: string;
  details?: any;
  timestamp: number;
  requestId: string;
}

// ============================================================================
// LAYER 2: APPLICATION LAYER CONTRACTS
// ============================================================================

export interface ApplicationServiceContract {
  // Identity operations
  registerIdentity(publicKey: string, attributes: Attribute[]): Identity;
  updateIdentity(id: string, attributes: Attribute[]): boolean;
  getIdentity(id: string): Identity | undefined;

  // Credential operations
  issueCredential(identityId: string, attributes: Attribute[], expiresAt?: number): Credential;
  validateCredential(credentialId: string): ValidationResult;
  getCredential(credentialId: string): Credential | undefined;

  // Proof operations
  generateProof(claim: ClaimStatement, privateData: Record<string, any>): Promise<Proof>;
  verifyProof(proof: Proof): Promise<VerificationResult>;
  batchVerifyProofs(proofs: Proof[]): Promise<VerificationResult[]>;

  // Revocation operations
  revokeCredential(credentialId: string, reason?: string): RevocationRecord;
  checkRevocation(credentialId: string): boolean;
  getRevocationRecord(credentialId: string): RevocationRecord | undefined;
}

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

export interface ClaimStatement {
  type: ClaimType;
  parameters: Record<string, any>;
}

export enum ClaimType {
  AGE_OVER = 'AGE_OVER',
  LICENSE_VALID = 'LICENSE_VALID',
  CLEARANCE_LEVEL = 'CLEARANCE_LEVEL',
  ROLE_AUTHORIZATION = 'ROLE_AUTHORIZATION'
}

export interface Proof {
  proof: ProofData;
  publicSignals: string[];
  statement: string;
}

export interface ProofData {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol: string;
  curve: string;
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

// ============================================================================
// LAYER 3: BUSINESS LOGIC LAYER CONTRACTS
// ============================================================================

export interface IdentityManagementDomainContract {
  registerIdentity(publicKey: string, attributes: Attribute[]): Identity;
  getIdentity(id: string): Identity | undefined;
  getAllIdentities(): Identity[];
  updateAttributes(id: string, attributes: Attribute[]): boolean;
  hasIdentity(id: string): boolean;
  validateIdentity(identity: Identity): ValidationResult;
  activateIdentity(id: string): boolean;
  deactivateIdentity(id: string): boolean;
}

export interface CredentialManagementDomainContract {
  issueCredential(identityId: string, attributes: Attribute[], expiresAt?: number): Credential;
  getCredential(id: string): Credential | undefined;
  getCredentialsForIdentity(identityId: string): Credential[];
  verifyCredential(credential: Credential): boolean;
  isExpired(credential: Credential): boolean;
  signCredential(identityId: string, attributes: Attribute[]): string;
  verifySignature(credential: Credential): boolean;
}

export interface ProofGenerationDomainContract {
  generateProof(claim: ClaimStatement, privateData: Record<string, any>): Promise<Proof>;
  prepareCircuitInputs(claim: ClaimStatement, privateData: Record<string, any>): CircuitInputs;
  computeWitness(inputs: CircuitInputs): Witness;
  constructProof(witness: Witness): ProofData;
  extractPublicSignals(witness: Witness): string[];
  formatStatement(claim: ClaimStatement): string;
}

export interface ProofVerificationDomainContract {
  verifyProof(proof: Proof): Promise<VerificationResult>;
  batchVerify(proofs: Proof[]): Promise<VerificationResult[]>;
  validateProofStructure(proof: Proof): boolean;
  validatePublicSignals(signals: string[]): boolean;
  extractClaimResult(proof: Proof): boolean;
  constructVerificationResult(valid: boolean, statement: string): VerificationResult;
}

export interface RevocationManagementDomainContract {
  revokeCredential(credentialId: string, reason?: string): RevocationRecord;
  restoreCredential(credentialId: string): boolean;
  isRevoked(credentialId: string): boolean;
  batchCheckRevocation(credentialIds: string[]): Map<string, boolean>;
  getRevocationRecord(credentialId: string): RevocationRecord | undefined;
  getAllRevocations(): RevocationRecord[];
  getRevocationsInRange(startTime: number, endTime: number): RevocationRecord[];
  generateRevocationProof(credentialId: string): RevocationProof;
  getStatistics(): RevocationStatistics;
}

export interface CircuitInputs {
  [key: string]: number | string | bigint;
}

export interface Witness {
  inputs: CircuitInputs;
  outputs: any[];
}

export interface RevocationProof {
  revoked: boolean;
  proof: string[];
}

export interface RevocationStatistics {
  totalRevocations: number;
  recentRevocations: number;
  revocationsByReason: Map<string, number>;
}

// ============================================================================
// LAYER 4: CRYPTOGRAPHIC LAYER CONTRACTS
// ============================================================================

export interface ZKCircuitEngineDomainContract {
  initialize(): Promise<void>;
  generateCircuitInputs(claim: ClaimStatement, privateData: Record<string, any>): Promise<CircuitInputs>;
  generateAgeOverInputs(parameters: any, privateData: any): CircuitInputs;
  generateLicenseValidInputs(parameters: any, privateData: any): CircuitInputs;
  generateClearanceLevelInputs(parameters: any, privateData: any): CircuitInputs;
  generateRoleAuthorizationInputs(parameters: any, privateData: any): CircuitInputs;
  getCircuitDefinition(claimType: ClaimType): string;
  hash(data: any[]): bigint;
  stringToNumber(str: string): number;
  generateSalt(): number;
}

export interface HashFunctionDomainContract {
  poseidonHash(inputs: bigint[]): bigint;
  poseidonMulti(inputs: bigint[][]): bigint[];
  mimcHash(inputs: bigint[]): bigint;
  stringToFieldElement(str: string): bigint;
  bytesToFieldElement(bytes: Uint8Array): bigint;
  merkleRoot(leaves: bigint[]): bigint;
  merkleProof(leaves: bigint[], index: number): bigint[];
  verifyMerkleProof(root: bigint, leaf: bigint, proof: bigint[]): boolean;
}

export interface SignatureSchemeDomainContract {
  ecdsaSign(message: Uint8Array, privateKey: Uint8Array): Signature;
  ecdsaVerify(message: Uint8Array, signature: Signature, publicKey: Uint8Array): boolean;
  eddsaSign(message: Uint8Array, privateKey: Uint8Array): Signature;
  eddsaVerify(message: Uint8Array, signature: Signature, publicKey: Uint8Array): boolean;
  blsSign(message: Uint8Array, privateKey: Uint8Array): Signature;
  blsVerify(message: Uint8Array, signature: Signature, publicKey: Uint8Array): boolean;
  blsAggregate(signatures: Signature[]): Signature;
  generateKeyPair(scheme: SignatureScheme): KeyPair;
}

export interface Signature {
  r: string;
  s: string;
  v?: number;
}

export enum SignatureScheme {
  ECDSA = 'ECDSA',
  EdDSA = 'EdDSA',
  BLS = 'BLS'
}

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

// ============================================================================
// LAYER 5: DATA ACCESS LAYER CONTRACTS
// ============================================================================

export interface IdentityRepositoryContract {
  create(identity: Identity): Promise<Identity>;
  findById(id: string): Promise<Identity | null>;
  findAll(): Promise<Identity[]>;
  findByPublicKey(publicKey: string): Promise<Identity | null>;
  findByAttribute(attributeName: string, attributeValue: any): Promise<Identity[]>;
  update(id: string, updates: Partial<Identity>): Promise<boolean>;
  updateAttributes(id: string, attributes: Attribute[]): Promise<boolean>;
  delete(id: string): Promise<boolean>;
  beginTransaction(): Promise<Transaction>;
  commit(transaction: Transaction): Promise<void>;
  rollback(transaction: Transaction): Promise<void>;
}

export interface CredentialRepositoryContract {
  create(credential: Credential): Promise<Credential>;
  findById(id: string): Promise<Credential | null>;
  findByIdentityId(identityId: string): Promise<Credential[]>;
  findByIssuer(issuer: string): Promise<Credential[]>;
  findExpired(): Promise<Credential[]>;
  findExpiringBefore(timestamp: number): Promise<Credential[]>;
  update(id: string, updates: Partial<Credential>): Promise<boolean>;
  delete(id: string): Promise<boolean>;
  createBatch(credentials: Credential[]): Promise<Credential[]>;
  deleteBatch(ids: string[]): Promise<number>;
}

export interface RevocationRepositoryContract {
  create(record: RevocationRecord): Promise<RevocationRecord>;
  findByCredentialId(credentialId: string): Promise<RevocationRecord | null>;
  findAll(): Promise<RevocationRecord[]>;
  findInRange(startTime: number, endTime: number): Promise<RevocationRecord[]>;
  findByReason(reason: string): Promise<RevocationRecord[]>;
  update(credentialId: string, updates: Partial<RevocationRecord>): Promise<boolean>;
  delete(credentialId: string): Promise<boolean>;
  getMerkleRoot(): Promise<bigint>;
  getMerkleProof(credentialId: string): Promise<bigint[]>;
  updateMerkleTree(): Promise<void>;
  count(): Promise<number>;
  countByReason(): Promise<Map<string, number>>;
  countInRange(startTime: number, endTime: number): Promise<number>;
}

export interface Transaction {
  id: string;
  startTime: number;
  status: 'active' | 'committed' | 'rolled_back';
}

// ============================================================================
// LAYER 6: PERSISTENCE LAYER CONTRACTS
// ============================================================================

export interface InMemoryStorageContract {
  get(key: string): any | undefined;
  set(key: string, value: any): void;
  delete(key: string): boolean;
  has(key: string): boolean;
  getAll(): Map<string, any>;
  setAll(entries: Map<string, any>): void;
  clear(): void;
  setWithTTL(key: string, value: any, ttl: number): void;
  size(): number;
  memoryUsage(): number;
}

export interface DatabaseStorageContract {
  connect(config: DatabaseConfig): Promise<void>;
  disconnect(): Promise<void>;
  insert(table: string, data: any): Promise<any>;
  select(table: string, query: Query): Promise<any[]>;
  update(table: string, query: Query, data: any): Promise<number>;
  delete(table: string, query: Query): Promise<number>;
  beginTransaction(): Promise<Transaction>;
  commit(transaction: Transaction): Promise<void>;
  rollback(transaction: Transaction): Promise<void>;
  createTable(definition: TableDefinition): Promise<void>;
  dropTable(table: string): Promise<void>;
  createIndex(table: string, columns: string[]): Promise<void>;
  backup(path: string): Promise<void>;
  restore(path: string): Promise<void>;
}

export interface DistributedLedgerContract {
  writeEntry(entry: LedgerEntry): Promise<TransactionHash>;
  readEntry(hash: TransactionHash): Promise<LedgerEntry | null>;
  queryEntries(filter: LedgerFilter): Promise<LedgerEntry[]>;
  getCurrentBlock(): Promise<Block>;
  getBlock(blockNumber: number): Promise<Block | null>;
  deployContract(bytecode: string): Promise<ContractAddress>;
  callContract(address: ContractAddress, method: string, params: any[]): Promise<any>;
  getConsensusState(): Promise<ConsensusState>;
  validateBlock(block: Block): Promise<boolean>;
  subscribeToEvents(filter: EventFilter, callback: (event: Event) => void): Subscription;
  unsubscribe(subscription: Subscription): void;
}

export interface DatabaseConfig {
  host: string;
  port: number;
  database: string;
  username: string;
  password: string;
  ssl?: boolean;
  poolSize?: number;
}

export interface Query {
  where?: Record<string, any>;
  orderBy?: string;
  limit?: number;
  offset?: number;
}

export interface TableDefinition {
  name: string;
  columns: ColumnDefinition[];
  primaryKey: string[];
  indexes?: IndexDefinition[];
}

export interface ColumnDefinition {
  name: string;
  type: string;
  nullable?: boolean;
  unique?: boolean;
  default?: any;
}

export interface IndexDefinition {
  name: string;
  columns: string[];
  unique?: boolean;
}

export interface LedgerEntry {
  id: string;
  data: any;
  timestamp: number;
  signature: string;
}

export interface TransactionHash {
  hash: string;
  blockNumber: number;
}

export interface LedgerFilter {
  fromBlock?: number;
  toBlock?: number;
  address?: string;
  topics?: string[];
}

export interface Block {
  number: number;
  hash: string;
  parentHash: string;
  timestamp: number;
  transactions: TransactionHash[];
}

export interface ContractAddress {
  address: string;
}

export interface ConsensusState {
  currentRound: number;
  validators: string[];
  status: string;
}

export interface EventFilter {
  topics: string[];
  fromBlock?: number;
  toBlock?: number;
}

export interface Event {
  type: string;
  data: any;
  blockNumber: number;
  transactionHash: string;
}

export interface Subscription {
  id: string;
  unsubscribe(): void;
}

// ============================================================================
// CROSS-CUTTING CONCERNS CONTRACTS
// ============================================================================

export interface MetricsCollectorContract {
  recordLatency(operation: string, duration: number): void;
  recordThroughput(operation: string, count: number): void;
  recordIdentityRegistration(): void;
  recordCredentialIssuance(): void;
  recordProofGeneration(): void;
  recordProofVerification(valid: boolean): void;
  recordRevocation(): void;
  recordError(component: string, error: Error): void;
  recordWarning(component: string, message: string): void;
  recordCPUUsage(percent: number): void;
  recordMemoryUsage(bytes: number): void;
  recordDiskUsage(bytes: number): void;
}

export interface LoggerContract {
  debug(message: string, context?: any): void;
  info(message: string, context?: any): void;
  warn(message: string, context?: any): void;
  error(message: string, error?: Error, context?: any): void;
  logWithContext(level: LogLevel, message: string, context: LogContext): void;
  auditLog(event: AuditEvent): void;
}

export enum LogLevel {
  DEBUG = 'DEBUG',
  INFO = 'INFO',
  WARN = 'WARN',
  ERROR = 'ERROR'
}

export interface LogContext {
  requestId?: string;
  userId?: string;
  operation?: string;
  duration?: number;
  [key: string]: any;
}

export interface AuditEvent {
  type: string;
  actor: string;
  action: string;
  resource: string;
  timestamp: number;
  outcome: 'success' | 'failure';
  details?: any;
}

export interface DistributedTracingContract {
  startTrace(operationName: string): TraceContext;
  endTrace(context: TraceContext): void;
  startSpan(name: string, parent?: TraceContext): Span;
  endSpan(span: Span): void;
  injectContext(context: TraceContext): Headers;
  extractContext(headers: Headers): TraceContext;
}

export interface TraceContext {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
}

export interface Span {
  name: string;
  startTime: number;
  endTime?: number;
  tags: Record<string, any>;
}

export interface Headers {
  [key: string]: string;
}

export interface HealthCheckContract {
  checkIdentityRegistry(): HealthStatus;
  checkCredentialIssuer(): HealthStatus;
  checkProofGenerator(): HealthStatus;
  checkProofVerifier(): HealthStatus;
  checkRevocationRegistry(): HealthStatus;
  checkDatabase(): HealthStatus;
  checkCache(): HealthStatus;
  checkCryptographicLibraries(): HealthStatus;
  getOverallHealth(): HealthStatus;
}

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: number;
  details?: string;
  metrics?: Record<string, number>;
}

// ============================================================================
// PLUGIN SYSTEM CONTRACTS
// ============================================================================

export interface ClaimTypePluginContract {
  getName(): string;
  getVersion(): string;
  generateCircuitInputs(parameters: any, privateData: any): CircuitInputs;
  getCircuitDefinition(): string;
  validateParameters(parameters: any): ValidationResult;
  validatePrivateData(privateData: any): ValidationResult;
}

export interface StoragePluginContract {
  connect(config: any): Promise<void>;
  disconnect(): Promise<void>;
  create(entity: any): Promise<any>;
  read(id: string): Promise<any>;
  update(id: string, data: any): Promise<boolean>;
  delete(id: string): Promise<boolean>;
}

export interface AuthenticationPluginContract {
  authenticate(credentials: any): Promise<AuthToken>;
  validateToken(token: AuthToken): Promise<boolean>;
  refreshToken(token: AuthToken): Promise<AuthToken>;
}

export interface EventBusContract {
  publish(event: Event): void;
  publishAsync(event: Event): Promise<void>;
  subscribe(eventType: string, handler: EventHandler): Subscription;
  unsubscribe(subscription: Subscription): void;
  on(eventType: string, handler: EventHandler): void;
  off(eventType: string, handler: EventHandler): void;
}

export type EventHandler = (event: Event) => void | Promise<void>;

export enum SystemEvent {
  IDENTITY_REGISTERED = 'identity.registered',
  CREDENTIAL_ISSUED = 'credential.issued',
  CREDENTIAL_REVOKED = 'credential.revoked',
  PROOF_GENERATED = 'proof.generated',
  PROOF_VERIFIED = 'proof.verified',
  ERROR_OCCURRED = 'error.occurred'
}
