/**
 * Comprehensive audit logger for compliance and security monitoring
 * Implements tamper-evident logging with structured events
 */
export class AuditLogger {
  private events: AuditEvent[] = [];
  private eventIndex: Map<string, number> = new Map();

  /**
   * Log a security-relevant event
   */
  log(event: AuditEventData): AuditEvent {
    const auditEvent: AuditEvent = {
      id: this.generateEventId(),
      timestamp: Date.now(),
      sequenceNumber: this.events.length,
      ...event,
      previousHash: this.getPreviousHash(),
      hash: '' // Will be computed
    };

    // Compute event hash
    auditEvent.hash = this.computeEventHash(auditEvent);

    this.events.push(auditEvent);
    this.eventIndex.set(auditEvent.id, this.events.length - 1);

    return auditEvent;
  }

  /**
   * Log identity registration
   */
  logIdentityRegistration(identityId: string, publicKey: string, actor: string): void {
    this.log({
      type: 'IDENTITY_REGISTERED',
      severity: 'INFO',
      actor,
      resource: identityId,
      action: 'REGISTER',
      details: {
        publicKey: this.maskSensitive(publicKey),
        timestamp: Date.now()
      },
      outcome: 'SUCCESS'
    });
  }

  /**
   * Log credential issuance
   */
  logCredentialIssuance(
    credentialId: string,
    identityId: string,
    issuer: string,
    attributeCount: number
  ): void {
    this.log({
      type: 'CREDENTIAL_ISSUED',
      severity: 'INFO',
      actor: issuer,
      resource: credentialId,
      action: 'ISSUE',
      details: {
        identityId,
        attributeCount,
        timestamp: Date.now()
      },
      outcome: 'SUCCESS'
    });
  }

  /**
   * Log proof generation
   */
  logProofGeneration(
    claimType: string,
    identityId: string,
    success: boolean,
    durationMs?: number
  ): void {
    this.log({
      type: 'PROOF_GENERATED',
      severity: success ? 'INFO' : 'WARNING',
      actor: identityId,
      resource: `proof_${claimType}`,
      action: 'GENERATE',
      details: {
        claimType,
        durationMs,
        timestamp: Date.now()
      },
      outcome: success ? 'SUCCESS' : 'FAILURE'
    });
  }

  /**
   * Log proof verification
   */
  logProofVerification(
    verifier: string,
    claimType: string,
    valid: boolean,
    durationMs?: number
  ): void {
    this.log({
      type: 'PROOF_VERIFIED',
      severity: valid ? 'INFO' : 'WARNING',
      actor: verifier,
      resource: `proof_${claimType}`,
      action: 'VERIFY',
      details: {
        claimType,
        valid,
        durationMs,
        timestamp: Date.now()
      },
      outcome: valid ? 'SUCCESS' : 'FAILURE'
    });
  }

  /**
   * Log credential revocation
   */
  logCredentialRevocation(
    credentialId: string,
    revokedBy: string,
    reason?: string
  ): void {
    this.log({
      type: 'CREDENTIAL_REVOKED',
      severity: 'WARNING',
      actor: revokedBy,
      resource: credentialId,
      action: 'REVOKE',
      details: {
        reason,
        timestamp: Date.now()
      },
      outcome: 'SUCCESS'
    });
  }

  /**
   * Log security violation
   */
  logSecurityViolation(
    violationType: string,
    actor: string,
    details: Record<string, any>
  ): void {
    this.log({
      type: 'SECURITY_VIOLATION',
      severity: 'CRITICAL',
      actor,
      resource: violationType,
      action: 'VIOLATION',
      details: {
        ...details,
        timestamp: Date.now()
      },
      outcome: 'BLOCKED'
    });
  }

  /**
   * Log authentication attempt
   */
  logAuthenticationAttempt(
    actor: string,
    success: boolean,
    method: string,
    ipAddress?: string
  ): void {
    this.log({
      type: 'AUTHENTICATION',
      severity: success ? 'INFO' : 'WARNING',
      actor,
      resource: 'auth',
      action: 'AUTHENTICATE',
      details: {
        method,
        ipAddress,
        timestamp: Date.now()
      },
      outcome: success ? 'SUCCESS' : 'FAILURE'
    });
  }

  /**
   * Log access control decision
   */
  logAccessControl(
    actor: string,
    resource: string,
    action: string,
    granted: boolean,
    reason?: string
  ): void {
    this.log({
      type: 'ACCESS_CONTROL',
      severity: granted ? 'INFO' : 'WARNING',
      actor,
      resource,
      action,
      details: {
        reason,
        timestamp: Date.now()
      },
      outcome: granted ? 'GRANTED' : 'DENIED'
    });
  }

  /**
   * Log data access
   */
  logDataAccess(
    actor: string,
    resourceType: string,
    resourceId: string,
    action: 'READ' | 'WRITE' | 'DELETE'
  ): void {
    this.log({
      type: 'DATA_ACCESS',
      severity: action === 'DELETE' ? 'WARNING' : 'INFO',
      actor,
      resource: `${resourceType}:${resourceId}`,
      action,
      details: {
        resourceType,
        timestamp: Date.now()
      },
      outcome: 'SUCCESS'
    });
  }

  /**
   * Log rate limit violation
   */
  logRateLimitViolation(actor: string, endpoint: string, limit: number): void {
    this.log({
      type: 'RATE_LIMIT_EXCEEDED',
      severity: 'WARNING',
      actor,
      resource: endpoint,
      action: 'REQUEST',
      details: {
        limit,
        timestamp: Date.now()
      },
      outcome: 'BLOCKED'
    });
  }

  /**
   * Get audit trail for a specific resource
   */
  getAuditTrail(resourceId: string): AuditEvent[] {
    return this.events.filter(e => e.resource === resourceId);
  }

  /**
   * Get audit trail for a specific actor
   */
  getActorAuditTrail(actor: string): AuditEvent[] {
    return this.events.filter(e => e.actor === actor);
  }

  /**
   * Get events by type
   */
  getEventsByType(type: string): AuditEvent[] {
    return this.events.filter(e => e.type === type);
  }

  /**
   * Get events by severity
   */
  getEventsBySeverity(severity: AuditSeverity): AuditEvent[] {
    return this.events.filter(e => e.severity === severity);
  }

  /**
   * Get events in time range
   */
  getEventsInRange(startTime: number, endTime: number): AuditEvent[] {
    return this.events.filter(e => e.timestamp >= startTime && e.timestamp <= endTime);
  }

  /**
   * Verify audit log integrity
   */
  verifyIntegrity(): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    for (let i = 0; i < this.events.length; i++) {
      const event = this.events[i];

      // Verify sequence number
      if (event.sequenceNumber !== i) {
        errors.push(`Event ${event.id}: invalid sequence number`);
      }

      // Verify hash chain
      const expectedPreviousHash = i > 0 ? this.events[i - 1].hash : '0'.repeat(64);
      if (event.previousHash !== expectedPreviousHash) {
        errors.push(`Event ${event.id}: broken hash chain`);
      }

      // Verify event hash
      const computedHash = this.computeEventHash(event);
      if (event.hash !== computedHash) {
        errors.push(`Event ${event.id}: invalid hash`);
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  /**
   * Export audit log for compliance
   */
  exportLog(format: 'JSON' | 'CSV' = 'JSON'): string {
    if (format === 'JSON') {
      return JSON.stringify(this.events, null, 2);
    } else {
      // CSV export
      const headers = ['ID', 'Timestamp', 'Type', 'Severity', 'Actor', 'Resource', 'Action', 'Outcome'];
      const rows = this.events.map(e => [
        e.id,
        new Date(e.timestamp).toISOString(),
        e.type,
        e.severity,
        e.actor,
        e.resource,
        e.action,
        e.outcome
      ]);

      return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    }
  }

  /**
   * Get audit statistics
   */
  getStatistics(): AuditStatistics {
    const stats: AuditStatistics = {
      totalEvents: this.events.length,
      eventsByType: {},
      eventsBySeverity: {},
      eventsByOutcome: {},
      timeRange: {
        start: this.events[0]?.timestamp || 0,
        end: this.events[this.events.length - 1]?.timestamp || 0
      }
    };

    for (const event of this.events) {
      // Count by type
      stats.eventsByType[event.type] = (stats.eventsByType[event.type] || 0) + 1;

      // Count by severity
      stats.eventsBySeverity[event.severity] = (stats.eventsBySeverity[event.severity] || 0) + 1;

      // Count by outcome
      stats.eventsByOutcome[event.outcome] = (stats.eventsByOutcome[event.outcome] || 0) + 1;
    }

    return stats;
  }

  /**
   * Detect anomalies in audit log
   */
  detectAnomalies(): AuditAnomaly[] {
    const anomalies: AuditAnomaly[] = [];

    // Detect rapid authentication failures
    const authFailures = this.getEventsByType('AUTHENTICATION').filter(e => e.outcome === 'FAILURE');
    const actorFailures = new Map<string, number>();

    for (const failure of authFailures) {
      actorFailures.set(failure.actor, (actorFailures.get(failure.actor) || 0) + 1);
    }

    for (const [actor, count] of actorFailures.entries()) {
      if (count >= 5) {
        anomalies.push({
          type: 'REPEATED_AUTH_FAILURES',
          severity: 'HIGH',
          actor,
          count,
          description: `${count} authentication failures for actor ${actor}`
        });
      }
    }

    // Detect unusual access patterns
    const accessEvents = this.getEventsByType('DATA_ACCESS');
    const actorAccess = new Map<string, number>();

    for (const access of accessEvents) {
      actorAccess.set(access.actor, (actorAccess.get(access.actor) || 0) + 1);
    }

    for (const [actor, count] of actorAccess.entries()) {
      if (count > 100) {
        anomalies.push({
          type: 'EXCESSIVE_DATA_ACCESS',
          severity: 'MEDIUM',
          actor,
          count,
          description: `${count} data access events for actor ${actor}`
        });
      }
    }

    return anomalies;
  }

  /**
   * Compute hash of audit event
   */
  private computeEventHash(event: AuditEvent): string {
    const data = JSON.stringify({
      id: event.id,
      timestamp: event.timestamp,
      sequenceNumber: event.sequenceNumber,
      type: event.type,
      severity: event.severity,
      actor: event.actor,
      resource: event.resource,
      action: event.action,
      details: event.details,
      outcome: event.outcome,
      previousHash: event.previousHash
    });

    return require('crypto').createHash('sha3-256').update(data).digest('hex');
  }

  /**
   * Get hash of previous event
   */
  private getPreviousHash(): string {
    if (this.events.length === 0) {
      return '0'.repeat(64);
    }
    return this.events[this.events.length - 1].hash;
  }

  /**
   * Generate unique event ID
   */
  private generateEventId(): string {
    return `evt_${require('crypto').randomBytes(16).toString('hex')}`;
  }

  /**
   * Mask sensitive data in logs
   */
  private maskSensitive(data: string): string {
    if (data.length <= 8) {
      return '***';
    }
    return `${data.slice(0, 4)}...${data.slice(-4)}`;
  }
}

/**
 * Audit event structure
 */
export interface AuditEvent {
  id: string;
  timestamp: number;
  sequenceNumber: number;
  type: string;
  severity: AuditSeverity;
  actor: string;
  resource: string;
  action: string;
  details: Record<string, any>;
  outcome: string;
  previousHash: string;
  hash: string;
}

/**
 * Audit event data (before hashing)
 */
export interface AuditEventData {
  type: string;
  severity: AuditSeverity;
  actor: string;
  resource: string;
  action: string;
  details: Record<string, any>;
  outcome: string;
}

/**
 * Audit severity levels
 */
export type AuditSeverity = 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL';

/**
 * Audit statistics
 */
export interface AuditStatistics {
  totalEvents: number;
  eventsByType: Record<string, number>;
  eventsBySeverity: Record<string, number>;
  eventsByOutcome: Record<string, number>;
  timeRange: {
    start: number;
    end: number;
  };
}

/**
 * Audit anomaly detection result
 */
export interface AuditAnomaly {
  type: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  actor: string;
  count: number;
  description: string;
}
