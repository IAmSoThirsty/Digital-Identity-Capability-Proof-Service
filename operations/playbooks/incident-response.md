# INCIDENT RESPONSE PLAYBOOK
## Digital Identity Capability Proof Service

**Version:** 2.0
**Last Updated:** 2026-02-23
**Owner:** Security Operations Team

---

## 1. INCIDENT CLASSIFICATION

### Severity Levels

#### P0 - CRITICAL
**Impact:** Complete service outage or active security breach
**Response Time:** Immediate (< 15 minutes)
**Escalation:** Page on-call engineer + security team + exec team
**Examples:**
- Complete API outage
- Active data breach
- Cryptographic key compromise
- ZK circuit compromise
- Database ransomware

#### P1 - HIGH
**Impact:** Significant degradation or potential security issue
**Response Time:** < 1 hour
**Escalation:** Page on-call engineer + security team
**Examples:**
- Partial service degradation (> 50% error rate)
- Suspicious access patterns
- DDoS attack in progress
- Failed security audit
- Backup system failure

#### P2 - MEDIUM
**Impact:** Minor degradation, no immediate security risk
**Response Time:** < 4 hours
**Escalation:** On-call engineer
**Examples:**
- Performance degradation (20-50% increase in latency)
- Non-critical component failure
- Certificate expiring in < 7 days
- Compliance check failure

#### P3 - LOW
**Impact:** Minimal or no user impact
**Response Time:** Next business day
**Escalation:** Regular ticket queue
**Examples:**
- Minor bugs
- Documentation issues
- Non-critical monitoring alerts

---

## 2. INCIDENT RESPONSE TEAM (IRT)

### Roles and Responsibilities

#### Incident Commander (IC)
- **Primary:** On-call SRE Lead
- **Backup:** Engineering Manager
- **Responsibilities:**
  - Declare incident and severity
  - Coordinate response efforts
  - Manage communications
  - Make critical decisions
  - Lead post-incident review

#### Technical Lead
- **Primary:** On-call Backend Engineer
- **Backup:** Senior Backend Engineer
- **Responsibilities:**
  - Technical investigation
  - Implement fixes
  - Verify resolution
  - Document technical details

#### Communications Lead
- **Primary:** Customer Success Manager
- **Backup:** Product Manager
- **Responsibilities:**
  - Update status page
  - Customer communications
  - Internal stakeholder updates
  - Social media monitoring

#### Security Lead (for security incidents)
- **Primary:** CISO
- **Backup:** Security Engineer
- **Responsibilities:**
  - Security assessment
  - Containment strategy
  - Evidence preservation
  - Regulatory notification

### Contact Information
```yaml
Incident Commander:
  Primary: +1-XXX-XXX-XXXX (PagerDuty)
  Backup: +1-XXX-XXX-XXXX

Technical Lead:
  Primary: +1-XXX-XXX-XXXX (PagerDuty)
  Backup: +1-XXX-XXX-XXXX

Security Lead:
  Email: security@dicps.example.com
  Phone: +1-XXX-XXX-XXXX (24/7)

Executive Escalation:
  CEO: +1-XXX-XXX-XXXX
  CTO: +1-XXX-XXX-XXXX
```

---

## 3. RESPONSE PROCEDURES

### 3.1 API Outage (P0)

**Detection:**
- Alertmanager fires `APIDown` alert
- Health check failures > 3 consecutive checks
- Customer reports

**Immediate Actions (0-15 min):**
```bash
# 1. Verify the outage
curl https://api.dicps.example.com/v1/health/live

# 2. Check pod status
kubectl get pods -n identity-platform -l app=dicps-api

# 3. Check recent deployments
kubectl rollout history deployment/dicps-api -n identity-platform

# 4. View pod logs
kubectl logs -n identity-platform -l app=dicps-api --tail=100

# 5. Check resource usage
kubectl top pods -n identity-platform -l app=dicps-api
```

**Investigation (15-30 min):**
1. Check Grafana dashboards
2. Review recent changes (last 24h)
3. Examine database connections
4. Check circuit compilation status
5. Review error logs in ELK

**Resolution Steps:**
```bash
# If deployment issue - rollback
kubectl rollout undo deployment/dicps-api -n identity-platform
kubectl rollout status deployment/dicps-api -n identity-platform

# If pod crashes - restart
kubectl delete pod -n identity-platform -l app=dicps-api

# If database issue - check connections
kubectl exec -n identity-platform dicps-api-xxx -- env | grep DB_

# If circuit issue - verify mounted configmap
kubectl describe configmap zk-circuits -n identity-platform
```

**Communications:**
```markdown
# Status Page Update Template
Title: API Service Disruption
Status: Investigating | Identified | Monitoring | Resolved
Impact: All API endpoints unavailable

We are investigating reports of API unavailability. We will provide updates every 15 minutes.

Last Updated: [timestamp]
```

**Post-Incident:**
- File incident report in `incidents/YYYY-MM-DD-api-outage.md`
- Schedule post-mortem within 48 hours
- Update runbooks based on learnings

### 3.2 Data Breach (P0)

**Detection:**
- IDS/IPS alert
- Anomalous data access patterns
- Security scan findings
- Third-party notification

**IMMEDIATE ACTIONS (0-5 min):**
```bash
# 1. ISOLATE AFFECTED SYSTEMS
# Deny all traffic to compromised pods
kubectl label pod <compromised-pod> quarantine=true
kubectl annotate networkpolicy dicps-api-network-policy \
  override="deny-all"

# 2. PRESERVE EVIDENCE
# Snapshot affected pods for forensics
kubectl debug <compromised-pod> --image=busybox \
  --copy-to=forensics-snapshot

# 3. REVOKE CREDENTIALS
aws iam update-service-specific-credential \
  --service-specific-credential-id <id> --status Inactive

# 4. ROTATE SECRETS
kubectl delete secret dicps-database
kubectl create secret generic dicps-database \
  --from-literal=password=$(openssl rand -base64 32)
```

**CONTAINMENT (5-30 min):**
1. Identify scope of breach
2. Preserve forensic evidence
3. Block attacker access
4. Isolate affected systems
5. Enable enhanced logging

**INVESTIGATION (30 min - 4 hours):**
```bash
# Analyze audit logs
cat /var/log/dicps/audit.log | grep -A 10 "UNAUTHORIZED"

# Check database access logs
psql -c "SELECT * FROM pg_stat_statements WHERE query LIKE '%identity%'"

# Review network flows
tcpdump -i any -w /tmp/capture.pcap port 5432

# Examine Kubernetes audit logs
kubectl get events --all-namespaces --sort-by='.lastTimestamp'
```

**ERADICATION:**
1. Remove attacker access
2. Patch vulnerabilities
3. Reset all credentials
4. Rebuild compromised systems

**RECOVERY:**
```bash
# Restore from known-good backup
pg_restore -h $DB_HOST -U dicps -d dicps /backups/latest.dump

# Verify data integrity
npm run test:integrity

# Gradually restore service
kubectl scale deployment dicps-api --replicas=1
# Monitor, then scale up
kubectl scale deployment dicps-api --replicas=3
```

**REGULATORY NOTIFICATION:**

**GDPR (72 hours):**
```markdown
To: supervisory-authority@gdpr.eu
Subject: Personal Data Breach Notification

Nature of breach: [Unauthorized access to user attributes]
Categories affected: [Identity attributes, credentials]
Number of affected: [XXX data subjects]
Consequences: [Potential privacy impact]
Measures taken: [Containment, notification, remediation]
Contact: dpo@dicps.example.com
```

**HIPAA (60 days for < 500 individuals):**
- Notify affected individuals
- Notify HHS if > 500 individuals
- Document in breach log

**Customer Notification (< 72 hours):**
```markdown
Subject: Important Security Notice

We are writing to inform you of a security incident affecting our service.

What happened: [Brief description]
What information was involved: [Specific data types]
What we are doing: [Response actions]
What you should do: [Recommendations]

For questions: security@dicps.example.com
```

### 3.3 ZK Circuit Compromise (P0)

**Detection:**
- Verification failures spike
- Invalid proofs accepted
- Circuit tampering detected

**IMMEDIATE ACTIONS:**
```bash
# 1. DISABLE PROOF GENERATION
kubectl set env deployment/dicps-api -n identity-platform \
  ENABLE_PROOF_GENERATION=false

# 2. VERIFY CIRCUIT INTEGRITY
cd circuits/build
sha256sum -c checksums.txt

# 3. CHECK CIRCUIT SOURCES
git log --all --full-history -- circuits/

# 4. AUDIT RECENT PROOFS
psql -c "SELECT * FROM proofs WHERE generated_at > NOW() - INTERVAL '24 hours'"
```

**RECOVERY:**
```bash
# 1. REGENERATE CIRCUITS FROM KNOWN-GOOD SOURCE
git checkout <known-good-commit> circuits/
npm run prepare-circuits

# 2. PERFORM NEW TRUSTED SETUP
# Coordinate multi-party ceremony
npx snarkjs powersoftau new bn128 12 pot12_0000.ptau
# [Multiple contributions from different parties]

# 3. VERIFY NEW CIRCUITS
npm run test:circuits

# 4. UPDATE VERIFICATION KEYS
kubectl delete configmap zk-circuits
kubectl create configmap zk-circuits \
  --from-file=circuits/build/

# 5. RE-ENABLE PROOF GENERATION
kubectl set env deployment/dicps-api -n identity-platform \
  ENABLE_PROOF_GENERATION=true
```

**INVALIDATION:**
- Revoke all proofs generated with compromised circuit
- Notify verifiers of compromise
- Re-issue credentials if necessary

### 3.4 DDoS Attack (P1)

**Detection:**
- Request rate > 10x normal
- WAF blocking rules triggered
- Latency degradation

**MITIGATION:**
```bash
# 1. ENABLE DDoS PROTECTION
aws wafv2 update-web-acl \
  --scope REGIONAL \
  --id <acl-id> \
  --default-action Block={}

# 2. ACTIVATE RATE LIMITING
kubectl annotate ingress dicps-api -n identity-platform \
  nginx.ingress.kubernetes.io/limit-rps=10

# 3. SCALE UP INFRASTRUCTURE
kubectl scale deployment dicps-api --replicas=50 -n identity-platform

# 4. ENABLE CLOUDFLARE / AKAMAI
# Update DNS to route through DDoS mitigation service
```

**ANALYSIS:**
```bash
# Identify attack patterns
cat /var/log/nginx/access.log | \
  awk '{print $1}' | sort | uniq -c | sort -rn | head -20

# Block top offenders
for ip in $(cat attacker_ips.txt); do
  kubectl exec -n identity-platform nginx-ingress-controller-xxx -- \
    nginx -s reload -c /etc/nginx/nginx.conf \
    -g "deny $ip;"
done
```

### 3.5 Database Failure (P0)

**Detection:**
- Database connection errors
- Replica lag alert
- Backup failure

**IMMEDIATE ACTIONS:**
```bash
# 1. CHECK RDS STATUS
aws rds describe-db-instances \
  --db-instance-identifier dicps-production

# 2. CHECK CONNECTIONS
psql -h $DB_HOST -U dicps -c "SELECT count(*) FROM pg_stat_activity"

# 3. FAILOVER TO REPLICA (if master down)
aws rds failover-db-cluster \
  --db-cluster-identifier dicps-production

# 4. VERIFY REPLICATION
psql -c "SELECT * FROM pg_stat_replication"
```

**RECOVERY:**
```bash
# If corruption - restore from backup
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier dicps-production-restored \
  --db-snapshot-identifier dicps-production-snapshot-latest

# Update connection string
kubectl set env deployment/dicps-api -n identity-platform \
  DB_HOST=dicps-production-restored.xxx.rds.amazonaws.com
```

---

## 4. COMMUNICATION TEMPLATES

### Internal Notification (Slack)
```markdown
@here INCIDENT DECLARED - P0

Severity: P0
Title: [Brief description]
Status: Investigating
IC: @name
Slack Channel: #incident-YYYY-MM-DD
Bridge: zoom.us/j/XXX
Status Page: https://status.dicps.example.com

Do not discuss in other channels. Join #incident-YYYY-MM-DD for updates.
```

### Customer Email
```markdown
Subject: [RESOLVED] Service Disruption - [DATE]

Dear DICPS Customer,

We experienced a service disruption on [DATE] from [TIME] to [TIME] UTC affecting [SCOPE].

Impact: [What was affected]
Root Cause: [Technical explanation]
Resolution: [What we did]
Prevention: [How we'll prevent recurrence]

We apologize for any inconvenience. For questions, contact support@dicps.example.com.

Reference: INC-YYYY-MM-DD-XXX
```

### Post-Mortem Template
```markdown
# Post-Incident Review: [INCIDENT TITLE]

Date: YYYY-MM-DD
Incident ID: INC-YYYY-MM-DD-XXX
Severity: PX
Duration: [HH:MM]
Affected Users: [Count]

## Summary
[2-3 sentence summary]

## Timeline
- [HH:MM] - Detection
- [HH:MM] - Page sent
- [HH:MM] - Incident declared
- [HH:MM] - Root cause identified
- [HH:MM] - Fix implemented
- [HH:MM] - Incident resolved

## Root Cause
[Technical details]

## Impact
- Affected Services: [List]
- User Impact: [Description]
- Revenue Impact: $[Amount]
- SLA Impact: [%]

## What Went Well
1. [Item]
2. [Item]

## What Went Wrong
1. [Item]
2. [Item]

## Action Items
| Action | Owner | Deadline | Priority |
|--------|-------|----------|----------|
| [Fix] | @name | YYYY-MM-DD | P0 |

## Lessons Learned
[Key takeaways]
```

---

## 5. ESCALATION MATRIX

### Escalation Triggers
| Condition | Action |
|-----------|--------|
| P0 not resolved in 1 hour | Escalate to VP Engineering |
| P0 not resolved in 4 hours | Escalate to CTO |
| Data breach confirmed | Notify CEO, Legal, PR |
| Revenue impact > $10k | Notify CFO |
| Customer impact > 1000 users | Notify Customer Success |
| SLA breach imminent | Notify Account Managers |

### Escalation Contacts
```yaml
Engineering:
  VP Engineering: vp-eng@dicps.example.com
  CTO: cto@dicps.example.com

Legal & Compliance:
  General Counsel: legal@dicps.example.com
  DPO: dpo@dicps.example.com

Executive:
  CEO: ceo@dicps.example.com
  Board Chair: (emergency only)

External:
  Legal Firm: external-legal@lawfirm.com
  PR Firm: pr@agency.com
  Cyber Insurance: claims@insurer.com
```

---

## 6. TOOLS AND ACCESS

### Required Tools
- PagerDuty (alerting)
- Zoom (incident bridge)
- Slack (#incident-response)
- StatusPage (customer comms)
- kubectl (Kubernetes access)
- AWS Console (infrastructure)
- Grafana (monitoring)
- Splunk/ELK (logs)

### Access Verification
```bash
# Verify on-call engineer has access
kubectl auth can-i '*' '*' -n identity-platform
aws sts get-caller-identity
psql -h $DB_HOST -U dicps -c "SELECT 1"
```

---

## 7. POST-INCIDENT PROCEDURES

### Within 24 Hours
- [ ] File incident report
- [ ] Update status page to resolved
- [ ] Send customer notification (if P0/P1)
- [ ] Collect metrics (MTTD, MTTR, impact)
- [ ] Schedule post-mortem

### Within 48 Hours
- [ ] Conduct post-mortem meeting
- [ ] Document root cause
- [ ] Identify action items
- [ ] Assign owners and deadlines

### Within 1 Week
- [ ] Implement quick fixes
- [ ] Update runbooks
- [ ] Update monitoring/alerts
- [ ] Share learnings with team

### Within 1 Month
- [ ] Complete all action items
- [ ] Conduct incident review
- [ ] Update incident response procedures
- [ ] Test improvements

---

## 8. TESTING AND DRILLS

### Quarterly DR Drills
- Simulate P0 incidents
- Test communication channels
- Verify backup/restore procedures
- Update procedures based on findings

### Monthly Tabletop Exercises
- Walk through incident scenarios
- Verify contact information
- Test decision-making process
- Train new team members

---

## APPENDICES

### Appendix A: Alert Thresholds
[See observability/prometheus/alert-rules.yaml]

### Appendix B: Runbook Links
- API Outage: operations/runbooks/api-outage.md
- Database Failure: operations/runbooks/database-failure.md
- Security Breach: operations/runbooks/security-breach.md

### Appendix C: Compliance Requirements
- GDPR breach notification: 72 hours
- HIPAA breach notification: 60 days
- SOC 2 incident logging: All P0/P1

---

**Document Owner:** Security Operations Team
**Review Frequency:** Quarterly
**Last Tested:** 2026-02-15
**Next Test:** 2026-05-15
