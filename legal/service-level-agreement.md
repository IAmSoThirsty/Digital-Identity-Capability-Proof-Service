# Service Level Agreement (SLA)

## Digital Identity Capability Proof Service
**Version:** 1.0
**Effective Date:** January 1, 2026
**Contract Period:** 12 months

---

## 1. SERVICE LEVEL OBJECTIVES (SLOs)

### 1.1 API Availability SLO

**Target:** 99.95% monthly uptime

**Measurement:**
```
Availability = (Total Minutes - Downtime Minutes) / Total Minutes × 100
```

**Exclusions:**
- Scheduled maintenance (< 4 hours/month, announced 7 days prior)
- Force majeure events
- Customer-caused incidents
- Third-party service failures beyond our control

**Error Budget:** 0.05% = 21.6 minutes/month

**Monitoring:**
- Health check endpoint: `/health/ready`
- Check frequency: Every 60 seconds
- From 3 geographic locations

### 1.2 Latency SLOs

**API Response Time:**
- P50: < 100ms
- P95: < 200ms
- P99: < 500ms

**Proof Generation Time:**
- P50: < 5 seconds
- P95: < 15 seconds
- P99: < 25 seconds
- Timeout: 30 seconds

**Measurement Period:** 5-minute rolling windows

### 1.3 Proof Generation Success Rate SLO

**Target:** 99.9% success rate

**Measurement:**
```
Success Rate = Successful Proofs / Total Proof Attempts × 100
```

**Exclusions:**
- Invalid input data (user error)
- Timeout due to circuit complexity
- Rate limit rejections

### 1.4 Data Durability SLO

**Target:** 99.999999999% (11 nines) annual durability

**Implementation:**
- Database: Multi-AZ RDS with automated backups
- Backups: Every 4 hours, 30-day retention
- Point-in-time recovery: 5-minute granularity
- Cross-region replication: Enabled

---

## 2. SUPPORT TIERS

### 2.1 Enterprise Support (Included)

**Response Times:**
| Severity | Description | First Response | Resolution Target |
|----------|-------------|----------------|-------------------|
| P0 - Critical | Service down, data breach | 15 minutes | 1 hour |
| P1 - High | Major degradation | 1 hour | 4 hours |
| P2 - Medium | Minor issues | 4 hours | 1 business day |
| P3 - Low | Questions, enhancements | 1 business day | 5 business days |

**Channels:**
- Email: support@dicps.example.com
- Phone: 1-XXX-XXX-XXXX (24/7 for P0/P1)
- Slack: Enterprise customers
- Status Page: https://status.dicps.example.com

**Coverage:**
- 24/7/365 for P0/P1
- Business hours (9 AM - 6 PM EST) for P2/P3

### 2.2 Premium Support (Optional)

**Additional Benefits:**
- Dedicated Technical Account Manager
- Quarterly business reviews
- Architecture consultation (4 hours/month)
- Priority feature requests
- Custom SLA terms

---

## 3. SERVICE CREDITS

### 3.1 Credit Calculation

**Monthly Uptime Percentage:**
```
Uptime % = (Total Minutes - Downtime) / Total Minutes × 100
```

**Credit Schedule:**

| Monthly Uptime % | Service Credit |
|-----------------|----------------|
| < 99.95% to ≥ 99.0% | 10% |
| < 99.0% to ≥ 95.0% | 25% |
| < 95.0% | 50% |

**Example:**
- Monthly fee: $10,000
- Uptime: 99.2%
- Credit: 10% = $1,000

### 3.2 Claiming Credits

**Process:**
1. Submit claim within 30 days of incident
2. Provide incident details and impact
3. Include monitoring data if available

**Contact:** sla-credits@dicps.example.com

**Processing:**
- Claim reviewed within 15 business days
- Credits applied to next invoice
- Credits expire after 12 months if unused

### 3.3 Maximum Credits

**Cap:** 50% of monthly fee per incident

**Annual Cap:** 3 months of fees

**Sole Remedy:** Service credits are the exclusive remedy for SLA breaches

---

## 4. MAINTENANCE WINDOWS

### 4.1 Scheduled Maintenance

**Frequency:** Once per month (if needed)

**Duration:** < 4 hours

**Timing:**
- Primary window: Sunday 2 AM - 6 AM EST
- Backup window: Wednesday 2 AM - 6 AM EST

**Notice:** 7 calendar days advance notice

**Excluded from Uptime:** Yes

### 4.2 Emergency Maintenance

**Conditions:**
- Critical security patches
- Data integrity issues
- Infrastructure failures

**Notice:** Best effort (minimum 1 hour if possible)

**Excluded from Uptime:** Only if < 1 hour total/month

---

## 5. SECURITY COMMITMENTS

### 5.1 Compliance Certifications

**Current:**
- ✅ SOC 2 Type II (annual audit)
- ✅ ISO 27001:2013
- ✅ PCI DSS Level 1
- ✅ HIPAA compliant (BAA required)
- ✅ GDPR compliant
- ✅ CCPA compliant

**Audit Reports:** Available under NDA

### 5.2 Data Protection

**Encryption:**
- In transit: TLS 1.3 minimum
- At rest: AES-256-GCM
- Key management: AWS KMS with rotation

**Access Controls:**
- Role-based access control (RBAC)
- Multi-factor authentication (MFA)
- Least privilege principle
- Quarterly access reviews

**Monitoring:**
- 24/7 SOC monitoring
- SIEM (Security Information and Event Management)
- Intrusion detection/prevention
- Automated vulnerability scanning

### 5.3 Incident Response

**Breach Notification:**
- Customer notification: < 24 hours
- GDPR notification: < 72 hours
- Regulatory notification: Per applicable laws

**Incident Management:**
- Dedicated incident response team
- Post-incident reports provided
- Root cause analysis
- Remediation plans

---

## 6. DATA MANAGEMENT

### 6.1 Backup and Recovery

**Backup Frequency:**
- Database: Every 4 hours
- Application state: Hourly
- Configuration: On change

**Retention:**
- Operational backups: 30 days
- Compliance backups: 7 years
- Deleted data: 30-day recovery period

**Recovery Objectives:**
- RTO (Recovery Time Objective): 1 hour
- RPO (Recovery Point Objective): 5 minutes

### 6.2 Data Portability

**Export Format:** JSON, CSV, or Protocol Buffers

**Export Scope:**
- Identities and attributes
- Credentials (including revoked)
- Proofs (last 90 days)
- Audit logs (if requested)

**Delivery:** Secure download link or API

**Turnaround:** < 7 business days

### 6.3 Data Deletion

**On-Demand Deletion:**
- Request via privacy@dicps.example.com
- Verification required
- Grace period: 30 days

**Deletion Scope:**
- Active data: Immediate
- Backups: Next backup cycle
- Logs: Per retention policy (7 years for compliance)

**Certification:** Deletion certificate provided upon request

---

## 7. CAPACITY AND PERFORMANCE

### 7.1 Rate Limits

**Standard Tier:**
- Requests: 100/minute per IP
- Proof generation: 10/minute per identity
- Batch operations: 100 items max

**Enterprise Tier:**
- Requests: 1,000/minute per IP
- Proof generation: 100/minute per identity
- Batch operations: 1,000 items max
- Custom limits available

### 7.2 Resource Limits

**Per Identity:**
- Attributes: 100 maximum
- Attribute size: 1 KB maximum
- Credentials: 1,000 active

**Per Credential:**
- Attributes: 100 maximum

**Proof Constraints:**
- Generation timeout: 30 seconds
- Proof size: 10 KB maximum
- Verification cache: 1,000 proofs

### 7.3 Scalability Guarantees

**Auto-Scaling:**
- Horizontal: 3 to 50 pods
- Trigger: CPU > 70% or Memory > 80%
- Scale-up time: < 2 minutes
- Scale-down: Gradual (10% per minute)

**Load Handling:**
- Normal load: 5,000 requests/second
- Peak load: 25,000 requests/second (5x)
- Proof generation: 500 concurrent

---

## 8. MONITORING AND REPORTING

### 8.1 Status Page

**URL:** https://status.dicps.example.com

**Updates:**
- Real-time service status
- Incident notifications
- Maintenance schedules
- Historical uptime data

**Subscriptions:**
- Email notifications
- SMS alerts (P0/P1)
- Webhook integrations
- RSS feed

### 8.2 SLA Reports

**Frequency:** Monthly

**Contents:**
- Uptime percentage
- Latency percentiles
- Incident summary
- Error budget consumption
- Capacity metrics

**Delivery:**
- Email to account contacts
- Dashboard: https://portal.dicps.example.com

### 8.3 Custom Metrics

**Enterprise Customers:**
- Custom dashboards (Grafana)
- API metrics endpoint
- Log streaming (Splunk, Datadog)
- Webhook alerts

---

## 9. CHANGE MANAGEMENT

### 9.1 API Versioning

**Policy:**
- Semantic versioning (v1, v2, etc.)
- Backward compatibility: 12 months minimum
- Deprecation notice: 6 months

**Breaking Changes:**
- Major version increment (v1 → v2)
- Migration guide provided
- Dual-running period: 6 months

### 9.2 Feature Updates

**Non-Breaking:**
- Deployed during maintenance windows
- Release notes published
- No customer action required

**Breaking Changes:**
- Customer notification: 30 days
- Opt-in beta period
- Migration assistance available

---

## 10. DISASTER RECOVERY

### 10.1 Business Continuity

**Multi-Region Architecture:**
- Primary: us-east-1
- Secondary: eu-west-1
- Tertiary: ap-southeast-1

**Failover:**
- Automatic: Database and cache
- Manual: Application (4-hour RTO)
- Testing: Quarterly DR drills

### 10.2 Recovery Procedures

**Disaster Scenarios:**
- Regional AWS outage
- Data center failure
- Cyber attack
- Data corruption

**Recovery Steps:**
1. Declare disaster (IC decision)
2. Activate DR team
3. Failover to secondary region
4. Restore from backup if needed
5. Verify data integrity
6. Resume operations
7. Post-incident review

---

## 11. CUSTOMER RESPONSIBILITIES

### 11.1 Required Actions

**Account Security:**
- Protect API keys and credentials
- Enable MFA on accounts
- Regular key rotation (90 days)
- Monitor access logs

**Input Validation:**
- Validate data before submission
- Handle error responses appropriately
- Respect rate limits
- Implement retry logic with backoff

**Capacity Planning:**
- Notify of significant load increases (> 50%)
- Plan for traffic spikes
- Use batch operations efficiently

### 11.2 Prohibited Actions

**Do Not:**
- Attempt to breach security controls
- Reverse engineer cryptographic implementations
- Share credentials or API keys
- Violate usage limits
- Store private ZK inputs on our servers

---

## 12. LEGAL AND COMPLIANCE

### 12.1 Definitions

**"Downtime":** Unavailability of API endpoints as measured by health checks

**"Incident":** Unplanned service disruption or degradation

**"Scheduled Maintenance":** Pre-announced service window for updates

**"Force Majeure":** Events beyond reasonable control (natural disasters, war, etc.)

### 12.2 Liability

**Service Credits:** Exclusive remedy for SLA breaches

**Liability Cap:** Total liability limited to fees paid in prior 12 months

**Exclusions:** Indirect, consequential, or punitive damages

### 12.3 Amendments

**Modification:**
- 30 days written notice for material changes
- Continued use constitutes acceptance
- Customer may terminate if changes unacceptable

---

## 13. CONTACT INFORMATION

**SLA Questions:**
- Email: sla@dicps.example.com
- Phone: 1-XXX-XXX-XXXX

**Service Credits:**
- Email: sla-credits@dicps.example.com

**Technical Support:**
- Email: support@dicps.example.com
- Phone: 1-XXX-XXX-XXXX (24/7)

**Account Management:**
- Email: accounts@dicps.example.com

---

## 14. APPENDIX: SLA MONITORING

### A.1 Measurement Methodology

**Uptime Calculation:**
```python
total_checks = checks_per_hour * 24 * days_in_month
failed_checks = count(health_check == "failed")
downtime_minutes = (failed_checks / checks_per_hour) * 60
uptime_percentage = (1 - (downtime_minutes / total_minutes)) * 100
```

**Latency Measurement:**
```python
# Using Prometheus
p95 = histogram_quantile(0.95,
    sum(rate(http_request_duration_seconds_bucket[5m])) by (le)
)
```

### A.2 Third-Party Monitoring

**Providers:**
- Pingdom (uptime monitoring)
- StatusCake (global checks)
- Datadog (APM and metrics)

**Check Points:**
- North America (3 locations)
- Europe (2 locations)
- Asia-Pacific (2 locations)

---

**Executed By:**

**Digital Identity Capability Proof Service**
Signature: ___________________________
Name: [Authorized Representative]
Title: [Title]
Date: ___________________________

**Customer**
Signature: ___________________________
Name: [Customer Representative]
Title: [Title]
Date: ___________________________

---

**Effective Date:** January 1, 2026
**Version:** 1.0
**Review Date:** Quarterly
