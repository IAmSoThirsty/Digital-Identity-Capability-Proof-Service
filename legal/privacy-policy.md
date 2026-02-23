# PRIVACY POLICY

**Digital Identity Capability Proof Service (DICPS)**
**Effective Date:** January 1, 2026
**Last Updated:** February 23, 2026

---

## 1. INTRODUCTION

This Privacy Policy describes how Digital Identity Capability Proof Service ("DICPS," "we," "us," or "our") collects, uses, discloses, and safeguards your personal information when you use our zero-knowledge proof-based identity verification service.

**Our Commitment:** We are committed to protecting your privacy through privacy-preserving cryptographic techniques that allow verification without revealing unnecessary personal information.

**Compliance:** This policy complies with:
- General Data Protection Regulation (GDPR)
- California Consumer Privacy Act (CCPA)
- Health Insurance Portability and Accountability Act (HIPAA)
- Payment Card Industry Data Security Standard (PCI DSS)

---

## 2. INFORMATION WE COLLECT

### 2.1 Information You Provide

**Identity Registration:**
- Public cryptographic key (Ethereum-style address)
- Identity attributes (name, age, license type, clearance level, roles)
- Timestamp of attribute assertions

**Credential Issuance:**
- Credential attributes
- Credential expiration dates
- Issuer information

**Zero-Knowledge Proofs:**
- Proof data (cryptographic proof, public signals)
- Claim statements
- Proof generation metadata

### 2.2 Information Automatically Collected

**Technical Information:**
- IP addresses
- Browser type and version
- Device information
- Operating system
- Access timestamps
- API request logs

**Usage Information:**
- Proof generation requests
- Verification requests
- Error logs
- Performance metrics

### 2.3 Information from Third Parties

**Identity Issuers:**
- Verified attributes from trusted issuers
- Credential signatures
- Issuance timestamps

---

## 3. HOW WE USE YOUR INFORMATION

### 3.1 Primary Purposes

**Identity Verification:**
- Register and manage digital identities
- Issue verifiable credentials
- Generate zero-knowledge proofs
- Verify proof validity

**Service Operation:**
- Maintain service availability (99.95% SLO)
- Monitor performance and detect issues
- Prevent fraud and abuse
- Enforce rate limits and security controls

**Compliance:**
- Maintain audit logs (SOC 2, ISO 27001)
- Respond to legal obligations
- Protect against security threats
- Fulfill regulatory requirements

### 3.2 Legal Basis (GDPR)

We process personal data based on:
- **Consent:** You explicitly consent to data processing
- **Contract:** Processing necessary to provide services
- **Legal Obligation:** Compliance with laws and regulations
- **Legitimate Interest:** Fraud prevention, security, service improvement

---

## 4. DATA MINIMIZATION & PRIVACY-PRESERVING TECHNIQUES

### 4.1 Zero-Knowledge Proofs

**Privacy by Design:**
- Proofs reveal ONLY the validity of a claim
- Private data never leaves your control
- Cryptographic guarantees prevent information leakage

**Example:** Age verification proof proves age > 18 without revealing exact age.

### 4.2 Selective Disclosure

- You control which attributes to include in credentials
- Only necessary attributes shared with verifiers
- Attribute revocation without full identity deletion

### 4.3 Pseudonymization

- Public keys serve as pseudonymous identifiers
- No direct linkage between keys and real identity (unless you provide)
- Multiple identities supported for different contexts

---

## 5. DATA SHARING AND DISCLOSURE

### 5.1 We Share Information With

**Service Providers:**
- Cloud infrastructure (AWS, GCP, Azure)
- Monitoring and analytics (Prometheus, Grafana)
- Security services (penetration testing, audits)

**Legal Requirements:**
- Law enforcement (with valid legal process)
- Regulatory authorities
- Court orders and subpoenas

**Business Transfers:**
- Mergers, acquisitions, or asset sales
- Bankruptcy proceedings

### 5.2 We DO NOT Share

- Private inputs to zero-knowledge proofs
- Unencrypted credential data with third parties
- Personal data for advertising or marketing
- Data with data brokers

---

## 6. DATA SECURITY

### 6.1 Encryption

**In Transit:**
- TLS 1.3 for all connections
- Perfect Forward Secrecy (PFS)
- Certificate pinning for critical services

**At Rest:**
- AES-256-GCM encryption
- AWS KMS for key management
- Automatic key rotation (90 days)

### 6.2 Access Controls

- Role-Based Access Control (RBAC)
- Multi-Factor Authentication (MFA)
- Principle of Least Privilege
- Quarterly access reviews

### 6.3 Monitoring & Incident Response

- 24/7 security monitoring
- Intrusion detection systems
- Incident response team
- Breach notification < 72 hours (GDPR)

---

## 7. DATA RETENTION

### 7.1 Retention Periods

| Data Type | Retention Period | Reason |
|-----------|-----------------|---------|
| Active Identities | Until deletion request | Service provision |
| Revoked Credentials | 7 years | Compliance (SOC 2) |
| Audit Logs | 7 years | Regulatory requirements |
| Access Logs | 90 days | Security monitoring |
| Backup Data | 30 days | Disaster recovery |

### 7.2 Deletion

Upon account deletion:
- Immediate: Active credentials revoked
- 30 days: Grace period for recovery
- 90 days: Complete data deletion from active systems
- 7 years: Audit logs retained (compliance)

---

## 8. YOUR PRIVACY RIGHTS

### 8.1 GDPR Rights (EU/EEA)

**Right to Access:**
- Request copy of your personal data
- Export in machine-readable format (JSON)

**Right to Rectification:**
- Correct inaccurate data
- Update attributes

**Right to Erasure ("Right to be Forgotten"):**
- Delete your account and associated data
- Exceptions: Legal obligations, audit logs

**Right to Restrict Processing:**
- Limit how we use your data
- Object to certain processing activities

**Right to Data Portability:**
- Transfer data to another service
- Structured, machine-readable format

**Right to Object:**
- Object to processing based on legitimate interest
- Object to automated decision-making

**How to Exercise:**
- Email: privacy@dicps.example.com
- Web Portal: https://dicps.example.com/privacy
- Response Time: < 30 days

### 8.2 CCPA Rights (California)

**Right to Know:**
- Categories of personal information collected
- Purposes for collection
- Third parties data is shared with

**Right to Delete:**
- Request deletion of personal information

**Right to Opt-Out:**
- Opt-out of sale of personal information
- **Note:** We DO NOT sell personal information

**Right to Non-Discrimination:**
- Equal service regardless of privacy choices

**How to Exercise:**
- Email: ccpa@dicps.example.com
- Phone: 1-XXX-XXX-XXXX
- Response Time: < 45 days

### 8.3 HIPAA Rights (US Healthcare)

If you are a covered entity or business associate:
- Access Protected Health Information (PHI)
- Request amendments to PHI
- Accounting of disclosures
- Request confidential communications

---

## 9. CHILDREN'S PRIVACY

**Age Restriction:** Our service is NOT directed to children under 13 (or 16 in EU).

We do not knowingly collect personal information from children. If we discover such collection, we will delete the data immediately.

**Parents:** If you believe your child provided information, contact privacy@dicps.example.com.

---

## 10. INTERNATIONAL DATA TRANSFERS

### 10.1 Data Location

Primary data centers:
- United States (AWS us-east-1)
- European Union (AWS eu-west-1)
- Asia-Pacific (AWS ap-southeast-1)

### 10.2 Transfer Mechanisms

**GDPR Compliance:**
- Standard Contractual Clauses (SCCs)
- Adequacy decisions where available
- Data Processing Agreements (DPAs)

**Data Residency Options:**
- EU customers: Data stored in EU regions
- Regional isolation available upon request

---

## 11. COOKIES AND TRACKING

### 11.1 Cookies We Use

**Essential Cookies:**
- Session management
- Authentication tokens
- CSRF protection

**Performance Cookies:**
- Service monitoring
- Error tracking
- Usage analytics (anonymized)

**Preference Cookies:**
- Language settings
- UI customization

### 11.2 Your Choices

- Cookie consent banner at first visit
- Opt-out of non-essential cookies
- Browser settings to block cookies

---

## 12. UPDATES TO THIS POLICY

**Version Control:** We maintain version history of this policy.

**Notification:** Material changes communicated via:
- Email to registered users
- Notice on website (30 days advance)
- In-app notification

**Review:** Policy reviewed quarterly and updated as needed.

---

## 13. CONTACT US

### 13.1 Privacy Team

**General Privacy Inquiries:**
- Email: privacy@dicps.example.com
- Response Time: 5 business days

**Data Protection Officer (DPO):**
- Email: dpo@dicps.example.com
- Phone: +1-XXX-XXX-XXXX
- Address: [Physical Address]

**EU Representative:**
- [EU Rep Name]
- Email: eu-rep@dicps.example.com
- Address: [EU Address]

### 13.2 Supervisory Authority

**EU/EEA Users:**
- Right to lodge complaint with supervisory authority
- List: https://edpb.europa.eu/about-edpb/board/members_en

**California Users:**
- California Attorney General
- Privacy Enforcement: https://oag.ca.gov/privacy

---

## 14. DEFINITIONS

**Personal Data:** Information relating to an identified or identifiable natural person.

**Processing:** Any operation performed on personal data (collection, storage, use, disclosure, deletion).

**Data Controller:** Entity determining purposes and means of processing (DICPS for most operations).

**Data Processor:** Entity processing data on behalf of controller (our service providers).

**Zero-Knowledge Proof:** Cryptographic method to prove statement truth without revealing underlying data.

---

## 15. APPENDIX: DATA INVENTORY

### Personal Data We Collect

| Category | Examples | Purpose | Legal Basis | Retention |
|----------|----------|---------|-------------|-----------|
| Identity Data | Public key, attributes | Service provision | Contract | Until deletion |
| Credentials | Issued credentials | Verification | Contract | 7 years after revocation |
| Proofs | ZK proofs | Claim verification | Contract | 90 days |
| Technical Data | IP, browser | Security | Legitimate interest | 90 days |
| Audit Logs | Access logs | Compliance | Legal obligation | 7 years |

---

**Effective Date:** January 1, 2026
**Version:** 3.2
**Last Review:** February 23, 2026
**Next Review:** May 23, 2026
