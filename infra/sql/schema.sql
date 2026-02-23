-- Digital Identity Capability Proof Service
-- PostgreSQL Database Schema
-- Version: 1.0
-- Date: 2026-02-23

-- ============================================================================
-- EXTENSIONS
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- ============================================================================
-- SCHEMAS
-- ============================================================================

CREATE SCHEMA IF NOT EXISTS identity;
CREATE SCHEMA IF NOT EXISTS audit;

-- ============================================================================
-- IDENTITY SCHEMA
-- ============================================================================

-- Identities table
CREATE TABLE identity.identities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    public_key VARCHAR(66) NOT NULL UNIQUE, -- 0x + 64 hex chars
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE,
    version INTEGER NOT NULL DEFAULT 1,

    -- Audit fields
    created_by VARCHAR(255),
    updated_by VARCHAR(255),

    -- Constraints
    CONSTRAINT valid_public_key CHECK (public_key ~ '^0x[a-fA-F0-9]{64}$'),
    CONSTRAINT valid_version CHECK (version > 0)
);

CREATE INDEX idx_identities_public_key ON identity.identities(public_key) WHERE deleted_at IS NULL;
CREATE INDEX idx_identities_created_at ON identity.identities(created_at DESC);

COMMENT ON TABLE identity.identities IS 'Registered digital identities';
COMMENT ON COLUMN identity.identities.public_key IS 'Ethereum-style public key (0x + 64 hex chars)';
COMMENT ON COLUMN identity.identities.version IS 'Optimistic locking version';

-- Attributes table
CREATE TABLE identity.attributes (
    id BIGSERIAL PRIMARY KEY,
    identity_id UUID NOT NULL REFERENCES identity.identities(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    value JSONB NOT NULL, -- Supports string, number, boolean
    timestamp BIGINT NOT NULL, -- Unix timestamp in milliseconds
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT fk_identity FOREIGN KEY (identity_id) REFERENCES identity.identities(id),
    CONSTRAINT valid_timestamp CHECK (timestamp > 0),
    CONSTRAINT max_value_size CHECK (pg_column_size(value) <= 1024) -- 1KB max per attribute
);

CREATE INDEX idx_attributes_identity_id ON identity.attributes(identity_id);
CREATE INDEX idx_attributes_name ON identity.attributes(name);
CREATE INDEX idx_attributes_created_at ON identity.attributes(created_at DESC);

COMMENT ON TABLE identity.attributes IS 'Identity attributes with versioning';
COMMENT ON COLUMN identity.attributes.value IS 'JSONB value supporting string/number/boolean';

-- Enforce max 100 attributes per identity
CREATE OR REPLACE FUNCTION identity.check_attribute_limit()
RETURNS TRIGGER AS $$
BEGIN
    IF (SELECT COUNT(*) FROM identity.attributes WHERE identity_id = NEW.identity_id) >= 100 THEN
        RAISE EXCEPTION 'Maximum 100 attributes per identity exceeded';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_attribute_limit
    BEFORE INSERT ON identity.attributes
    FOR EACH ROW
    EXECUTE FUNCTION identity.check_attribute_limit();

-- Credentials table
CREATE TABLE identity.credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id UUID NOT NULL REFERENCES identity.identities(id) ON DELETE CASCADE,
    issuer VARCHAR(100) NOT NULL,
    signature TEXT NOT NULL,
    issued_at BIGINT NOT NULL,
    expires_at BIGINT, -- NULL means no expiration
    revoked_at TIMESTAMP WITH TIME ZONE,
    revocation_reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT fk_identity FOREIGN KEY (identity_id) REFERENCES identity.identities(id),
    CONSTRAINT valid_issued_at CHECK (issued_at > 0),
    CONSTRAINT valid_expires_at CHECK (expires_at IS NULL OR expires_at > issued_at),
    CONSTRAINT valid_issuer CHECK (LENGTH(issuer) > 0 AND LENGTH(issuer) <= 100),
    CONSTRAINT valid_revocation CHECK (
        (revoked_at IS NULL AND revocation_reason IS NULL) OR
        (revoked_at IS NOT NULL)
    )
);

CREATE INDEX idx_credentials_identity_id ON identity.credentials(identity_id);
CREATE INDEX idx_credentials_issuer ON identity.credentials(issuer);
CREATE INDEX idx_credentials_issued_at ON identity.credentials(issued_at DESC);
CREATE INDEX idx_credentials_revoked ON identity.credentials(revoked_at) WHERE revoked_at IS NOT NULL;

COMMENT ON TABLE identity.credentials IS 'Verifiable credentials issued to identities';

-- Credential attributes (many-to-many)
CREATE TABLE identity.credential_attributes (
    id BIGSERIAL PRIMARY KEY,
    credential_id UUID NOT NULL REFERENCES identity.credentials(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    value JSONB NOT NULL,
    timestamp BIGINT NOT NULL,

    CONSTRAINT fk_credential FOREIGN KEY (credential_id) REFERENCES identity.credentials(id),
    CONSTRAINT valid_timestamp CHECK (timestamp > 0)
);

CREATE INDEX idx_credential_attributes_credential_id ON identity.credential_attributes(credential_id);

-- Proofs table
CREATE TABLE identity.proofs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    claim_type VARCHAR(50) NOT NULL,
    proof JSONB NOT NULL, -- Groth16 proof structure
    public_signals JSONB NOT NULL, -- Array of public signals
    statement TEXT NOT NULL,
    generated_at BIGINT NOT NULL,
    generation_time_ms INTEGER NOT NULL,
    verified BOOLEAN,
    verified_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT valid_claim_type CHECK (claim_type IN ('AGE_OVER', 'LICENSE_VALID', 'CLEARANCE_LEVEL', 'ROLE_AUTHORIZATION')),
    CONSTRAINT valid_generated_at CHECK (generated_at > 0),
    CONSTRAINT valid_generation_time CHECK (generation_time_ms > 0 AND generation_time_ms <= 30000), -- Max 30s
    CONSTRAINT valid_proof_size CHECK (pg_column_size(proof) <= 10240), -- Max 10KB
    CONSTRAINT valid_verification CHECK (
        (verified IS NULL AND verified_at IS NULL) OR
        (verified IS NOT NULL AND verified_at IS NOT NULL)
    )
);

CREATE INDEX idx_proofs_claim_type ON identity.proofs(claim_type);
CREATE INDEX idx_proofs_generated_at ON identity.proofs(generated_at DESC);
CREATE INDEX idx_proofs_verified ON identity.proofs(verified) WHERE verified IS NOT NULL;

COMMENT ON TABLE identity.proofs IS 'Zero-knowledge proofs generated and verified';

-- Revocations table (Merkle tree based)
CREATE TABLE identity.revocations (
    id BIGSERIAL PRIMARY KEY,
    credential_id UUID NOT NULL UNIQUE REFERENCES identity.credentials(id) ON DELETE CASCADE,
    merkle_root VARCHAR(66) NOT NULL, -- Current root after this revocation
    merkle_proof JSONB NOT NULL, -- Proof of inclusion in tree
    revoked_at BIGINT NOT NULL,
    reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_credential FOREIGN KEY (credential_id) REFERENCES identity.credentials(id),
    CONSTRAINT valid_revoked_at CHECK (revoked_at > 0),
    CONSTRAINT valid_merkle_root CHECK (merkle_root ~ '^0x[a-fA-F0-9]{64}$')
);

CREATE INDEX idx_revocations_credential_id ON identity.revocations(credential_id);
CREATE INDEX idx_revocations_revoked_at ON identity.revocations(revoked_at DESC);
CREATE INDEX idx_revocations_merkle_root ON identity.revocations(merkle_root);

COMMENT ON TABLE identity.revocations IS 'Credential revocations with Merkle tree proofs';

-- ============================================================================
-- AUDIT SCHEMA
-- ============================================================================

-- Audit log table
CREATE TABLE audit.logs (
    id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    actor VARCHAR(255),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    request_id VARCHAR(255),
    correlation_id VARCHAR(255),
    metadata JSONB,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT valid_severity CHECK (severity IN ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')),
    CONSTRAINT valid_event_type CHECK (LENGTH(event_type) > 0)
);

CREATE INDEX idx_audit_timestamp ON audit.logs(timestamp DESC);
CREATE INDEX idx_audit_event_type ON audit.logs(event_type);
CREATE INDEX idx_audit_actor ON audit.logs(actor);
CREATE INDEX idx_audit_resource ON audit.logs(resource_type, resource_id);
CREATE INDEX idx_audit_request_id ON audit.logs(request_id);
CREATE INDEX idx_audit_success ON audit.logs(success) WHERE success = false;

COMMENT ON TABLE audit.logs IS 'Comprehensive audit trail for compliance (SOC2, ISO27001)';

-- Partition audit logs by month for performance
CREATE TABLE audit.logs_y2026m02 PARTITION OF audit.logs
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');

-- Rate limit tracking table
CREATE TABLE audit.rate_limits (
    id BIGSERIAL PRIMARY KEY,
    identifier VARCHAR(255) NOT NULL, -- IP or user ID
    window_start TIMESTAMP WITH TIME ZONE NOT NULL,
    window_end TIMESTAMP WITH TIME ZONE NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 1,
    blocked_count INTEGER NOT NULL DEFAULT 0,
    last_request TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_window CHECK (window_end > window_start),
    CONSTRAINT valid_counts CHECK (request_count > 0)
);

CREATE INDEX idx_rate_limits_identifier ON audit.rate_limits(identifier);
CREATE INDEX idx_rate_limits_window ON audit.rate_limits(window_start, window_end);

COMMENT ON TABLE audit.rate_limits IS 'Rate limiting counters for DoS protection';

-- Access log table (for compliance)
CREATE TABLE audit.access_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(255),
    ip_address INET NOT NULL,
    endpoint VARCHAR(500) NOT NULL,
    method VARCHAR(10) NOT NULL,
    status_code INTEGER NOT NULL,
    response_time_ms INTEGER NOT NULL,
    user_agent TEXT,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_method CHECK (method IN ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS')),
    CONSTRAINT valid_status_code CHECK (status_code >= 100 AND status_code < 600),
    CONSTRAINT valid_response_time CHECK (response_time_ms >= 0)
);

CREATE INDEX idx_access_logs_timestamp ON audit.access_logs(timestamp DESC);
CREATE INDEX idx_access_logs_user_id ON audit.access_logs(user_id);
CREATE INDEX idx_access_logs_ip_address ON audit.access_logs(ip_address);
CREATE INDEX idx_access_logs_endpoint ON audit.access_logs(endpoint);

COMMENT ON TABLE audit.access_logs IS 'HTTP access logs for security monitoring';

-- ============================================================================
-- FUNCTIONS
-- ============================================================================

-- Update timestamp trigger function
CREATE OR REPLACE FUNCTION identity.update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply to identities table
CREATE TRIGGER update_identities_timestamp
    BEFORE UPDATE ON identity.identities
    FOR EACH ROW
    EXECUTE FUNCTION identity.update_timestamp();

-- Audit trigger function
CREATE OR REPLACE FUNCTION audit.log_data_change()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit.logs (
        event_type,
        severity,
        action,
        resource_type,
        resource_id,
        metadata,
        success
    ) VALUES (
        TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME || '.' || TG_OP,
        'INFO',
        TG_OP,
        TG_TABLE_NAME,
        CASE
            WHEN TG_OP = 'DELETE' THEN OLD.id::TEXT
            ELSE NEW.id::TEXT
        END,
        jsonb_build_object(
            'old', CASE WHEN TG_OP != 'INSERT' THEN row_to_json(OLD) END,
            'new', CASE WHEN TG_OP != 'DELETE' THEN row_to_json(NEW) END
        ),
        true
    );

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply audit triggers to critical tables
CREATE TRIGGER audit_identities
    AFTER INSERT OR UPDATE OR DELETE ON identity.identities
    FOR EACH ROW
    EXECUTE FUNCTION audit.log_data_change();

CREATE TRIGGER audit_credentials
    AFTER INSERT OR UPDATE OR DELETE ON identity.credentials
    FOR EACH ROW
    EXECUTE FUNCTION audit.log_data_change();

CREATE TRIGGER audit_revocations
    AFTER INSERT OR UPDATE OR DELETE ON identity.revocations
    FOR EACH ROW
    EXECUTE FUNCTION audit.log_data_change();

-- Function to get active credentials
CREATE OR REPLACE FUNCTION identity.get_active_credentials(p_identity_id UUID)
RETURNS TABLE (
    id UUID,
    issuer VARCHAR(100),
    issued_at BIGINT,
    expires_at BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT c.id, c.issuer, c.issued_at, c.expires_at
    FROM identity.credentials c
    WHERE c.identity_id = p_identity_id
      AND c.revoked_at IS NULL
      AND (c.expires_at IS NULL OR c.expires_at > EXTRACT(EPOCH FROM NOW()) * 1000);
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION identity.get_active_credentials IS 'Get all non-revoked, non-expired credentials for an identity';

-- Function to batch revoke credentials
CREATE OR REPLACE FUNCTION identity.batch_revoke_credentials(
    p_credential_ids UUID[],
    p_reason TEXT DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    v_count INTEGER;
    v_credential_id UUID;
BEGIN
    v_count := 0;

    FOREACH v_credential_id IN ARRAY p_credential_ids
    LOOP
        UPDATE identity.credentials
        SET revoked_at = NOW(),
            revocation_reason = p_reason
        WHERE id = v_credential_id
          AND revoked_at IS NULL;

        IF FOUND THEN
            v_count := v_count + 1;
        END IF;
    END LOOP;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION identity.batch_revoke_credentials IS 'Batch revoke up to 1000 credentials';

-- ============================================================================
-- VIEWS
-- ============================================================================

-- Active identities view
CREATE OR REPLACE VIEW identity.active_identities AS
SELECT
    i.id,
    i.public_key,
    i.created_at,
    i.updated_at,
    COUNT(a.id) as attribute_count,
    COUNT(c.id) FILTER (WHERE c.revoked_at IS NULL) as active_credential_count
FROM identity.identities i
LEFT JOIN identity.attributes a ON i.id = a.identity_id
LEFT JOIN identity.credentials c ON i.id = c.identity_id
WHERE i.deleted_at IS NULL
GROUP BY i.id, i.public_key, i.created_at, i.updated_at;

COMMENT ON VIEW identity.active_identities IS 'Active identities with counts';

-- Credential status view
CREATE OR REPLACE VIEW identity.credential_status AS
SELECT
    c.id,
    c.identity_id,
    c.issuer,
    c.issued_at,
    c.expires_at,
    c.revoked_at,
    CASE
        WHEN c.revoked_at IS NOT NULL THEN 'REVOKED'
        WHEN c.expires_at IS NOT NULL AND c.expires_at < EXTRACT(EPOCH FROM NOW()) * 1000 THEN 'EXPIRED'
        ELSE 'ACTIVE'
    END as status
FROM identity.credentials c;

COMMENT ON VIEW identity.credential_status IS 'Credential status with categorization';

-- ============================================================================
-- SECURITY
-- ============================================================================

-- Create application role
CREATE ROLE dicps_app;

-- Grant permissions
GRANT USAGE ON SCHEMA identity TO dicps_app;
GRANT USAGE ON SCHEMA audit TO dicps_app;

GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA identity TO dicps_app;
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA audit TO dicps_app;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA identity TO dicps_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA audit TO dicps_app;

-- Create read-only audit role
CREATE ROLE dicps_audit_viewer;
GRANT USAGE ON SCHEMA audit TO dicps_audit_viewer;
GRANT SELECT ON ALL TABLES IN SCHEMA audit TO dicps_audit_viewer;

-- Row-level security (example)
ALTER TABLE identity.identities ENABLE ROW LEVEL SECURITY;

CREATE POLICY identity_isolation ON identity.identities
    FOR ALL
    TO dicps_app
    USING (deleted_at IS NULL);

-- ============================================================================
-- MAINTENANCE
-- ============================================================================

-- Vacuum and analyze schedule (run daily)
-- Automated via pg_cron or external scheduler

-- Archive old audit logs (> 7 years)
CREATE OR REPLACE FUNCTION audit.archive_old_logs()
RETURNS INTEGER AS $$
DECLARE
    v_cutoff TIMESTAMP WITH TIME ZONE;
    v_count INTEGER;
BEGIN
    v_cutoff := NOW() - INTERVAL '7 years';

    -- Move to archive table or external storage
    WITH deleted AS (
        DELETE FROM audit.logs
        WHERE timestamp < v_cutoff
        RETURNING *
    )
    SELECT COUNT(*) INTO v_count FROM deleted;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION audit.archive_old_logs IS 'Archive audit logs older than 7 years (compliance retention)';

-- ============================================================================
-- PERFORMANCE TUNING
-- ============================================================================

-- Set appropriate autovacuum settings
ALTER TABLE identity.identities SET (
    autovacuum_vacuum_scale_factor = 0.05,
    autovacuum_analyze_scale_factor = 0.02
);

ALTER TABLE audit.logs SET (
    autovacuum_vacuum_scale_factor = 0.1,
    autovacuum_analyze_scale_factor = 0.05
);

-- ============================================================================
-- INITIAL DATA
-- ============================================================================

-- Insert default system user for automated operations
INSERT INTO audit.logs (event_type, severity, action, resource_type, success, metadata)
VALUES ('system.initialized', 'INFO', 'CREATE', 'database', true,
        jsonb_build_object('version', '1.0', 'date', NOW()));

-- ============================================================================
-- GRANTS FOR MIGRATIONS
-- ============================================================================

GRANT CREATE ON DATABASE dicps TO dicps_app;
GRANT CREATE ON SCHEMA identity TO dicps_app;
GRANT CREATE ON SCHEMA audit TO dicps_app;

-- ============================================================================
-- COMPLETION
-- ============================================================================

-- Verify schema
SELECT schemaname, tablename, tableowner
FROM pg_tables
WHERE schemaname IN ('identity', 'audit')
ORDER BY schemaname, tablename;

COMMENT ON DATABASE dicps IS 'Digital Identity Capability Proof Service - Production Database v1.0';
