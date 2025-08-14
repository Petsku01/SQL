-- Cybersecurity Event Monitoring Database 
-- PostgreSQL schema for  security monitoring
-- Author: -pk
-- Version: 2.0


-- Required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "btree_gin";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create dedicated schema
DROP SCHEMA IF EXISTS security_monitor CASCADE;
CREATE SCHEMA security_monitor;
SET search_path TO security_monitor, public;

-- Custom types for better data integrity
CREATE TYPE severity_enum AS ENUM ('low', 'medium', 'high', 'critical', 'emergency');
CREATE TYPE event_status_enum AS ENUM ('new', 'investigating', 'confirmed', 'false_positive', 'resolved');
CREATE TYPE vuln_status_enum AS ENUM ('new', 'confirmed', 'in_progress', 'resolved', 'risk_accepted', 'duplicate');
CREATE TYPE access_result_enum AS ENUM ('success', 'failed', 'blocked', 'timeout');
CREATE TYPE ioc_type_enum AS ENUM ('ip', 'domain', 'url', 'file_hash', 'email', 'registry_key', 'process_name');
CREATE TYPE incident_status_enum AS ENUM ('new', 'assigned', 'investigating', 'contained', 'eradicating', 'recovering', 'closed');

-- Core security events table with improved structure
CREATE TABLE security_events (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    severity severity_enum NOT NULL DEFAULT 'medium',
    status event_status_enum NOT NULL DEFAULT 'new',
    source_ip INET,
    source_port INTEGER CHECK (source_port BETWEEN 1 AND 65535),
    destination_ip INET,
    destination_port INTEGER CHECK (destination_port BETWEEN 1 AND 65535),
    protocol VARCHAR(10),
    username VARCHAR(255),
    user_agent TEXT,
    event_title VARCHAR(500) NOT NULL,
    event_description TEXT NOT NULL,
    raw_log_data JSONB,
    event_hash VARCHAR(64) UNIQUE, -- For deduplication
    rule_id VARCHAR(100), -- Detection rule identifier
    false_positive_reason TEXT,
    analyst_assigned VARCHAR(100),
    analyst_notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    processed_at TIMESTAMP WITH TIME ZONE,
    ttl_expires_at TIMESTAMP WITH TIME ZONE, -- For data retention
    
    -- Constraints
    CONSTRAINT valid_port_range CHECK (
        (source_port IS NULL OR source_port BETWEEN 1 AND 65535) AND
        (destination_port IS NULL OR destination_port BETWEEN 1 AND 65535)
    ),
    CONSTRAINT event_hash_format CHECK (
        event_hash IS NULL OR event_hash ~ '^[a-fA-F0-9]{64}$'
    )
) PARTITION BY RANGE (created_at);

-- Vulnerability management with enhanced tracking
CREATE TABLE vulnerability_assessments (
    vuln_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    cve_id VARCHAR(20) UNIQUE,
    cwe_id VARCHAR(20),
    vulnerability_name VARCHAR(500) NOT NULL,
    vulnerability_description TEXT,
    cvss_version VARCHAR(5) DEFAULT '3.1',
    cvss_score DECIMAL(3,1) CHECK (cvss_score BETWEEN 0.0 AND 10.0),
    cvss_vector TEXT,
    cvss_exploitability_score DECIMAL(3,1),
    cvss_impact_score DECIMAL(3,1),
    epss_score DECIMAL(5,4), -- Exploit Prediction Scoring System
    affected_systems TEXT[] NOT NULL,
    affected_versions TEXT[],
    discovery_method VARCHAR(100),
    discovery_date DATE NOT NULL,
    disclosure_date DATE,
    patch_available_date DATE,
    status vuln_status_enum NOT NULL DEFAULT 'new',
    remediation_priority INTEGER CHECK (remediation_priority BETWEEN 1 AND 5) DEFAULT 3,
    business_impact_score INTEGER CHECK (business_impact_score BETWEEN 1 AND 10),
    remediation_effort_estimate INTERVAL,
    remediation_notes TEXT,
    workaround_available BOOLEAN DEFAULT FALSE,
    workaround_description TEXT,
    exploit_available BOOLEAN DEFAULT FALSE,
    exploit_maturity VARCHAR(50),
    vendor_advisory_url TEXT,
    internal_ticket_id VARCHAR(100),
    assigned_to VARCHAR(100),
    verified_by VARCHAR(100),
    resolved_date DATE,
    resolution_notes TEXT,
    retest_required BOOLEAN DEFAULT TRUE,
    retest_date DATE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    
    -- Constraints
    CONSTRAINT valid_cvss_format CHECK (
        cvss_vector IS NULL OR 
        cvss_vector ~ '^CVSS:[0-9]\.[0-9]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]'
    ),
    CONSTRAINT valid_cve_format CHECK (
        cve_id IS NULL OR cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
    ),
    CONSTRAINT logical_dates CHECK (
        (disclosure_date IS NULL OR discovery_date <= disclosure_date) AND
        (resolved_date IS NULL OR discovery_date <= resolved_date) AND
        (patch_available_date IS NULL OR discovery_date <= patch_available_date)
    )
);

-- Enhanced access logging with behavioral analytics
CREATE TABLE access_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id VARCHAR(255),
    username VARCHAR(255),
    user_id VARCHAR(100),
    source_ip INET NOT NULL,
    source_port INTEGER CHECK (source_port BETWEEN 1 AND 65535),
    destination_ip INET,
    destination_port INTEGER CHECK (destination_port BETWEEN 1 AND 65535),
    access_type VARCHAR(50) NOT NULL,
    resource_accessed TEXT,
    resource_type VARCHAR(100),
    http_method VARCHAR(10),
    http_status_code INTEGER,
    access_result access_result_enum NOT NULL,
    authentication_method VARCHAR(100),
    multi_factor_used BOOLEAN DEFAULT FALSE,
    user_agent TEXT,
    referer TEXT,
    request_size BIGINT CHECK (request_size >= 0),
    response_size BIGINT CHECK (response_size >= 0),
    processing_time_ms INTEGER CHECK (processing_time_ms >= 0),
    geolocation JSONB,
    device_fingerprint VARCHAR(64),
    risk_score INTEGER DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    anomaly_flags TEXT[],
    access_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    logout_timestamp TIMESTAMP WITH TIME ZONE,
    session_duration INTERVAL,
    
    -- Behavioral tracking
    is_first_time_location BOOLEAN DEFAULT FALSE,
    is_unusual_time BOOLEAN DEFAULT FALSE,
    is_tor_exit_node BOOLEAN DEFAULT FALSE,
    is_vpn_detected BOOLEAN DEFAULT FALSE,
    
    CONSTRAINT valid_http_status CHECK (
        http_status_code IS NULL OR http_status_code BETWEEN 100 AND 599
    ),
    CONSTRAINT valid_session_duration CHECK (
        session_duration IS NULL OR session_duration >= INTERVAL '0'
    )
) PARTITION BY RANGE (access_timestamp);

-- Comprehensive threat intelligence platform
CREATE TABLE threat_intelligence (
    threat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ioc_type ioc_type_enum NOT NULL,
    ioc_value TEXT NOT NULL,
    ioc_normalized TEXT GENERATED ALWAYS AS (LOWER(TRIM(ioc_value))) STORED,
    threat_type VARCHAR(100) NOT NULL,
    threat_family VARCHAR(100),
    confidence_level INTEGER CHECK (confidence_level BETWEEN 0 AND 100) NOT NULL,
    tlp_marking VARCHAR(10) DEFAULT 'WHITE' CHECK (tlp_marking IN ('WHITE', 'GREEN', 'AMBER', 'RED')),
    source VARCHAR(200) NOT NULL,
    feed_name VARCHAR(100),
    original_source TEXT,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    expiration_date TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    is_whitelisted BOOLEAN DEFAULT FALSE,
    whitelist_reason TEXT,
    tags TEXT[],
    mitre_tactics TEXT[],
    mitre_techniques TEXT[],
    kill_chain_phases TEXT[],
    description TEXT,
    context JSONB,
    related_campaigns TEXT[],
    attribution TEXT,
    severity severity_enum DEFAULT 'medium',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    
    -- Unique constraint on IOC type and normalized value
    UNIQUE(ioc_type, ioc_normalized),
    
    -- Validation constraints
    CONSTRAINT valid_ip_format CHECK (
        ioc_type != 'ip' OR ioc_value ~ '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    ),
    CONSTRAINT valid_domain_format CHECK (
        ioc_type != 'domain' OR ioc_value ~ '^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.([a-zA-Z]{2,}\.?)+$'
    ),
    CONSTRAINT valid_hash_format CHECK (
        ioc_type != 'file_hash' OR ioc_value ~ '^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$'
    ),
    CONSTRAINT expiration_after_creation CHECK (
        expiration_date IS NULL OR expiration_date > created_at
    )
);

-- Advanced incident management system
CREATE TABLE security_incidents (
    incident_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_number SERIAL UNIQUE, -- Human-readable incident number
    incident_title VARCHAR(500) NOT NULL,
    incident_type VARCHAR(100) NOT NULL,
    incident_category VARCHAR(100) NOT NULL,
    severity severity_enum NOT NULL DEFAULT 'medium',
    priority INTEGER CHECK (priority BETWEEN 1 AND 5) DEFAULT 3,
    status incident_status_enum NOT NULL DEFAULT 'new',
    confidentiality_level VARCHAR(20) DEFAULT 'internal' CHECK (
        confidentiality_level IN ('public', 'internal', 'confidential', 'restricted')
    ),
    
    -- Timeline tracking
    detected_at TIMESTAMP WITH TIME ZONE NOT NULL,
    reported_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    contained_at TIMESTAMP WITH TIME ZONE,
    eradicated_at TIMESTAMP WITH TIME ZONE,
    recovered_at TIMESTAMP WITH TIME ZONE,
    closed_at TIMESTAMP WITH TIME ZONE,
    
    -- Assignment and ownership
    reporter VARCHAR(100),
    assigned_analyst VARCHAR(100),
    incident_commander VARCHAR(100),
    escalated_to VARCHAR(100),
    
    -- Impact assessment
    affected_systems TEXT[],
    affected_users INTEGER DEFAULT 0 CHECK (affected_users >= 0),
    affected_customers INTEGER DEFAULT 0 CHECK (affected_customers >= 0),
    data_compromised BOOLEAN DEFAULT FALSE,
    service_disruption BOOLEAN DEFAULT FALSE,
    estimated_financial_impact DECIMAL(15,2) DEFAULT 0,
    actual_financial_impact DECIMAL(15,2),
    reputation_impact VARCHAR(20) CHECK (
        reputation_impact IN ('none', 'low', 'medium', 'high', 'critical')
    ),
    
    -- Documentation
    incident_summary TEXT,
    technical_details TEXT,
    business_impact_description TEXT,
    root_cause_analysis TEXT,
    timeline_of_events TEXT,
    remediation_steps TEXT,
    preventive_measures TEXT,
    lessons_learned TEXT,
    communication_log TEXT,
    external_parties_notified TEXT[],
    regulatory_reporting_required BOOLEAN DEFAULT FALSE,
    regulatory_bodies_notified TEXT[],
    
    -- Metrics
    time_to_detect INTERVAL,
    time_to_respond INTERVAL,
    time_to_contain INTERVAL,
    time_to_resolve INTERVAL,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    
    -- Constraints
    CONSTRAINT logical_timeline CHECK (
        detected_at <= reported_at AND
        (acknowledged_at IS NULL OR reported_at <= acknowledged_at) AND
        (contained_at IS NULL OR acknowledged_at IS NULL OR acknowledged_at <= contained_at) AND
        (eradicated_at IS NULL OR contained_at IS NULL OR contained_at <= eradicated_at) AND
        (recovered_at IS NULL OR eradicated_at IS NULL OR eradicated_at <= recovered_at) AND
        (closed_at IS NULL OR recovered_at IS NULL OR recovered_at <= closed_at)
    )
);

-- Link table for incident-event correlation
CREATE TABLE incident_events (
    incident_id UUID REFERENCES security_incidents(incident_id) ON DELETE CASCADE,
    event_id UUID REFERENCES security_events(event_id) ON DELETE CASCADE,
    correlation_confidence INTEGER CHECK (correlation_confidence BETWEEN 0 AND 100) DEFAULT 50,
    correlation_method VARCHAR(100),
    added_by VARCHAR(100),
    added_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    notes TEXT,
    PRIMARY KEY (incident_id, event_id)
);

-- Security metrics and KPIs tracking
CREATE TABLE security_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    metric_category VARCHAR(100) NOT NULL,
    metric_name VARCHAR(200) NOT NULL,
    metric_value DECIMAL(20,6) NOT NULL,
    metric_unit VARCHAR(50),
    metric_target DECIMAL(20,6),
    metric_threshold_warning DECIMAL(20,6),
    metric_threshold_critical DECIMAL(20,6),
    calculation_method TEXT,
    calculation_period INTERVAL,
    period_start TIMESTAMP WITH TIME ZONE NOT NULL,
    period_end TIMESTAMP WITH TIME ZONE NOT NULL,
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    calculated_by VARCHAR(100),
    metadata JSONB,
    is_kpi BOOLEAN DEFAULT FALSE,
    
    UNIQUE(metric_category, metric_name, period_start, period_end),
    CONSTRAINT valid_period CHECK (period_start < period_end)
);

-- Advanced indexing strategy
-- Security Events indexes
CREATE INDEX CONCURRENTLY idx_security_events_created_at ON security_events(created_at DESC);
CREATE INDEX CONCURRENTLY idx_security_events_severity_status ON security_events(severity, status);
CREATE INDEX CONCURRENTLY idx_security_events_source_ip ON security_events USING hash(source_ip);
CREATE INDEX CONCURRENTLY idx_security_events_event_type ON security_events(event_type);
CREATE INDEX CONCURRENTLY idx_security_events_username ON security_events(username) WHERE username IS NOT NULL;
CREATE INDEX CONCURRENTLY idx_security_events_raw_data ON security_events USING gin(raw_log_data);
CREATE INDEX CONCURRENTLY idx_security_events_event_hash ON security_events(event_hash) WHERE event_hash IS NOT NULL;
CREATE INDEX CONCURRENTLY idx_security_events_ttl ON security_events(ttl_expires_at) WHERE ttl_expires_at IS NOT NULL;

-- Vulnerability Assessment indexes
CREATE INDEX CONCURRENTLY idx_vuln_status_priority ON vulnerability_assessments(status, remediation_priority);
CREATE INDEX CONCURRENTLY idx_vuln_cvss_score ON vulnerability_assessments(cvss_score DESC NULLS LAST);
CREATE INDEX CONCURRENTLY idx_vuln_discovery_date ON vulnerability_assessments(discovery_date DESC);
CREATE INDEX CONCURRENTLY idx_vuln_cve_id ON vulnerability_assessments(cve_id) WHERE cve_id IS NOT NULL;
CREATE INDEX CONCURRENTLY idx_vuln_affected_systems ON vulnerability_assessments USING gin(affected_systems);
CREATE INDEX CONCURRENTLY idx_vuln_assigned_to ON vulnerability_assessments(assigned_to) WHERE assigned_to IS NOT NULL;

-- Access Logs indexes
CREATE INDEX CONCURRENTLY idx_access_logs_timestamp ON access_logs(access_timestamp DESC);
CREATE INDEX CONCURRENTLY idx_access_logs_username ON access_logs(username) WHERE username IS NOT NULL;
CREATE INDEX CONCURRENTLY idx_access_logs_source_ip ON access_logs(source_ip);
CREATE INDEX CONCURRENTLY idx_access_logs_result ON access_logs(access_result);
CREATE INDEX CONCURRENTLY idx_access_logs_risk_score ON access_logs(risk_score DESC) WHERE risk_score > 0;
CREATE INDEX CONCURRENTLY idx_access_logs_session_id ON access_logs(session_id) WHERE session_id IS NOT NULL;
CREATE INDEX CONCURRENTLY idx_access_logs_anomaly ON access_logs USING gin(anomaly_flags) WHERE anomaly_flags IS NOT NULL;

-- Threat Intelligence indexes
CREATE INDEX CONCURRENTLY idx_threat_intel_ioc_type_value ON threat_intelligence(ioc_type, ioc_normalized);
CREATE INDEX CONCURRENTLY idx_threat_intel_active ON threat_intelligence(is_active) WHERE is_active = TRUE;
CREATE INDEX CONCURRENTLY idx_threat_intel_confidence ON threat_intelligence(confidence_level DESC);
CREATE INDEX CONCURRENTLY idx_threat_intel_tags ON threat_intelligence USING gin(tags);
CREATE INDEX CONCURRENTLY idx_threat_intel_threat_type ON threat_intelligence(threat_type);
CREATE INDEX CONCURRENTLY idx_threat_intel_expiration ON threat_intelligence(expiration_date) WHERE expiration_date IS NOT NULL;
CREATE INDEX CONCURRENTLY idx_threat_intel_mitre ON threat_intelligence USING gin(mitre_techniques) WHERE mitre_techniques IS NOT NULL;

-- Security Incidents indexes
CREATE INDEX CONCURRENTLY idx_incidents_status_priority ON security_incidents(status, priority);
CREATE INDEX CONCURRENTLY idx_incidents_detected_at ON security_incidents(detected_at DESC);
CREATE INDEX CONCURRENTLY idx_incidents_severity ON security_incidents(severity);
CREATE INDEX CONCURRENTLY idx_incidents_assigned ON security_incidents(assigned_analyst) WHERE assigned_analyst IS NOT NULL;
CREATE INDEX CONCURRENTLY idx_incidents_type_category ON security_incidents(incident_type, incident_category);

-- Security Metrics indexes
CREATE INDEX CONCURRENTLY idx_metrics_category_name ON security_metrics(metric_category, metric_name);
CREATE INDEX CONCURRENTLY idx_metrics_period ON security_metrics(period_start DESC, period_end DESC);
CREATE INDEX CONCURRENTLY idx_metrics_kpi ON security_metrics(is_kpi) WHERE is_kpi = TRUE;

-- Advanced stored procedures and functions

-- Function: Generate event hash for deduplication
CREATE OR REPLACE FUNCTION generate_event_hash(
    p_event_type TEXT,
    p_source_ip INET,
    p_destination_ip INET,
    p_event_description TEXT,
    p_username TEXT DEFAULT NULL
) RETURNS TEXT AS $$
BEGIN
    RETURN encode(
        digest(
            COALESCE(p_event_type, '') || '|' ||
            COALESCE(p_source_ip::TEXT, '') || '|' ||
            COALESCE(p_destination_ip::TEXT, '') || '|' ||
            COALESCE(p_event_description, '') || '|' ||
            COALESCE(p_username, ''),
            'sha256'
        ),
        'hex'
    );
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function: Calculate comprehensive risk score
CREATE OR REPLACE FUNCTION calculate_comprehensive_risk_score(
    p_cvss_score DECIMAL DEFAULT NULL,
    p_exploit_available BOOLEAN DEFAULT FALSE,
    p_patch_available BOOLEAN DEFAULT TRUE,
    p_business_impact INTEGER DEFAULT 5,
    p_affected_systems_count INTEGER DEFAULT 1,
    p_days_since_discovery INTEGER DEFAULT 0
) RETURNS INTEGER AS $$
DECLARE
    risk_score INTEGER := 0;
    cvss_component INTEGER := 0;
    exploit_component INTEGER := 0;
    patch_component INTEGER := 0;
    business_component INTEGER := 0;
    exposure_component INTEGER := 0;
    systems_component INTEGER := 0;
BEGIN
    -- CVSS component (40% of total score)
    IF p_cvss_score IS NOT NULL THEN
        cvss_component := (p_cvss_score * 4)::INTEGER;
    END IF;
    
    -- Exploit availability (20% weight)
    IF p_exploit_available THEN
        exploit_component := 20;
    END IF;
    
    -- Patch availability (10% weight)
    IF NOT p_patch_available THEN
        patch_component := 10;
    END IF;
    
    -- Business impact (15% weight)
    business_component := (p_business_impact * 1.5)::INTEGER;
    
    -- Number of affected systems (10% weight)
    systems_component := LEAST(10, (p_affected_systems_count * 2));
    
    -- Time exposure (5% weight)
    exposure_component := LEAST(5, (p_days_since_discovery / 10));
    
    risk_score := cvss_component + exploit_component + patch_component + 
                  business_component + systems_component + exposure_component;
    
    RETURN LEAST(100, risk_score);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function: Advanced threat detection
CREATE OR REPLACE FUNCTION detect_advanced_threats(
    p_time_window INTERVAL DEFAULT '24 hours',
    p_min_confidence INTEGER DEFAULT 70
) RETURNS TABLE(
    threat_type TEXT,
    source_ip INET,
    username TEXT,
    event_count BIGINT,
    max_severity severity_enum,
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    confidence_score INTEGER
) AS $$
BEGIN
    RETURN QUERY
    WITH threat_patterns AS (
        SELECT 
            se.source_ip,
            se.username,
            se.event_type,
            se.severity,
            COUNT(*) as event_count,
            MIN(se.created_at) as first_occurrence,
            MAX(se.created_at) as last_occurrence,
            -- Calculate confidence based on event frequency and severity
            CASE 
                WHEN COUNT(*) >= 10 AND se.severity IN ('critical', 'emergency') THEN 95
                WHEN COUNT(*) >= 5 AND se.severity = 'high' THEN 85
                WHEN COUNT(*) >= 3 AND se.severity = 'medium' THEN 75
                ELSE 50
            END as confidence
        FROM security_events
WHERE created_at >= NOW() - INTERVAL '24 hours'
UNION ALL
SELECT 
    'Last 7 Days' as time_period,
    COUNT(*) as total_events,
    COUNT(*) FILTER (WHERE severity IN ('critical', 'emergency')) as critical_events,
    COUNT(*) FILTER (WHERE event_type LIKE '%authentication%') as auth_events,
    COUNT(*) FILTER (WHERE event_type LIKE '%malware%') as malware_events,
    COUNT(*) FILTER (WHERE status = 'new') as unprocessed_events,
    AVG(CASE WHEN processed_at IS NOT NULL THEN 
        EXTRACT(EPOCH FROM (processed_at - created_at))/60 
        ELSE NULL END) as avg_processing_time_minutes
FROM security_events
WHERE created_at >= NOW() - INTERVAL '7 days'
UNION ALL
SELECT 
    'Last 30 Days' as time_period,
    COUNT(*) as total_events,
    COUNT(*) FILTER (WHERE severity IN ('critical', 'emergency')) as critical_events,
    COUNT(*) FILTER (WHERE event_type LIKE '%authentication%') as auth_events,
    COUNT(*) FILTER (WHERE event_type LIKE '%malware%') as malware_events,
    COUNT(*) FILTER (WHERE status = 'new') as unprocessed_events,
    AVG(CASE WHEN processed_at IS NOT NULL THEN 
        EXTRACT(EPOCH FROM (processed_at - created_at))/60 
        ELSE NULL END) as avg_processing_time_minutes
FROM security_events
WHERE created_at >= NOW() - INTERVAL '30 days';

CREATE UNIQUE INDEX ON mv_security_dashboard (time_period);

-- Critical vulnerabilities view
CREATE MATERIALIZED VIEW mv_critical_vulnerabilities AS
SELECT 
    va.*,
    calculate_comprehensive_risk_score(
        va.cvss_score,
        va.exploit_available,
        va.patch_available_date IS NOT NULL,
        va.business_impact_score,
        array_length(va.affected_systems, 1),
        EXTRACT(DAYS FROM (CURRENT_DATE - va.discovery_date))::INTEGER
    ) as calculated_risk_score,
    CASE 
        WHEN va.cvss_score >= 9.0 THEN 'Critical'
        WHEN va.cvss_score >= 7.0 THEN 'High'
        WHEN va.cvss_score >= 4.0 THEN 'Medium'
        ELSE 'Low'
    END as risk_category,
    CURRENT_DATE - va.discovery_date as days_open,
    CASE 
        WHEN va.patch_available_date IS NOT NULL THEN 'Available'
        ELSE 'Not Available'
    END as patch_status
FROM vulnerability_assessments va
WHERE va.status IN ('new', 'confirmed', 'in_progress')
ORDER BY va.cvss_score DESC NULLS LAST, va.discovery_date ASC;

CREATE UNIQUE INDEX ON mv_critical_vulnerabilities (vuln_id);

-- Threat landscape view
CREATE MATERIALIZED VIEW mv_threat_landscape AS
SELECT 
    ti.threat_type,
    ti.ioc_type,
    COUNT(*) as total_indicators,
    COUNT(*) FILTER (WHERE ti.confidence_level >= 80) as high_confidence_indicators,
    COUNT(*) FILTER (WHERE ti.is_active = TRUE) as active_indicators,
    AVG(ti.confidence_level) as avg_confidence,
    MAX(ti.last_seen) as most_recent_sighting,
    array_agg(DISTINCT ti.source) as sources,
    array_agg(DISTINCT unnest(ti.tags)) as all_tags
FROM threat_intelligence ti
WHERE ti.created_at >= NOW() - INTERVAL '90 days'
GROUP BY ti.threat_type, ti.ioc_type
ORDER BY total_indicators DESC;

CREATE UNIQUE INDEX ON mv_threat_landscape (threat_type, ioc_type);

-- Incident response metrics view
CREATE MATERIALIZED VIEW mv_incident_metrics AS
SELECT 
    DATE_TRUNC('week', detected_at) as week_start,
    COUNT(*) as total_incidents,
    COUNT(*) FILTER (WHERE severity IN ('critical', 'emergency')) as critical_incidents,
    COUNT(*) FILTER (WHERE status = 'closed') as resolved_incidents,
    AVG(EXTRACT(EPOCH FROM time_to_detect)/3600) as avg_detection_time_hours,
    AVG(EXTRACT(EPOCH FROM time_to_respond)/3600) as avg_response_time_hours,
    AVG(EXTRACT(EPOCH FROM time_to_contain)/3600) as avg_containment_time_hours,
    AVG(EXTRACT(EPOCH FROM time_to_resolve)/3600) as avg_resolution_time_hours,
    AVG(estimated_financial_impact) as avg_estimated_impact
FROM security_incidents
WHERE detected_at >= NOW() - INTERVAL '6 months'
GROUP BY DATE_TRUNC('week', detected_at)
ORDER BY week_start DESC;

CREATE UNIQUE INDEX ON mv_incident_metrics (week_start);

-- Partitioning setup for time-series tables
-- Security Events partitions (monthly)
DO $
DECLARE
    start_date DATE;
    end_date DATE;
    table_name TEXT;
BEGIN
    -- Create partitions for the last 6 months and next 6 months
    FOR i IN -6..6 LOOP
        start_date := DATE_TRUNC('month', CURRENT_DATE) + (i || ' months')::INTERVAL;
        end_date := start_date + INTERVAL '1 month';
        table_name := 'security_events_' || TO_CHAR(start_date, 'YYYY_MM');
        
        EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF security_events 
                       FOR VALUES FROM (%L) TO (%L)', 
                       table_name, start_date, end_date);
    END LOOP;
END $;

-- Access Logs partitions (weekly for better performance)
DO $
DECLARE
    start_date DATE;
    end_date DATE;
    table_name TEXT;
BEGIN
    -- Create partitions for the last 12 weeks and next 12 weeks
    FOR i IN -12..12 LOOP
        start_date := DATE_TRUNC('week', CURRENT_DATE) + (i || ' weeks')::INTERVAL;
        end_date := start_date + INTERVAL '1 week';
        table_name := 'access_logs_' || TO_CHAR(start_date, 'YYYY_WW');
        
        EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF access_logs 
                       FOR VALUES FROM (%L) TO (%L)', 
                       table_name, start_date, end_date);
    END LOOP;
END $;

-- Data retention and cleanup procedures
CREATE OR REPLACE FUNCTION cleanup_expired_data() RETURNS INTEGER AS $
DECLARE
    deleted_count INTEGER := 0;
    total_deleted INTEGER := 0;
BEGIN
    -- Clean up expired security events (based on TTL)
    DELETE FROM security_events 
    WHERE ttl_expires_at IS NOT NULL AND ttl_expires_at < NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;
    
    -- Clean up old resolved incidents (older than 2 years)
    DELETE FROM security_incidents 
    WHERE status = 'closed' 
    AND closed_at < NOW() - INTERVAL '2 years';
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;
    
    -- Clean up old access logs (older than 1 year for successful logins)
    DELETE FROM access_logs 
    WHERE access_result = 'success' 
    AND access_timestamp < NOW() - INTERVAL '1 year';
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;
    
    -- Clean up expired threat intelligence
    UPDATE threat_intelligence 
    SET is_active = FALSE 
    WHERE expiration_date IS NOT NULL 
    AND expiration_date < NOW() 
    AND is_active = TRUE;
    
    RETURN total_deleted;
END;
$ LANGUAGE plpgsql;

-- Automated maintenance procedure
CREATE OR REPLACE FUNCTION perform_maintenance() RETURNS TEXT AS $
DECLARE
    result_text TEXT := '';
    deleted_records INTEGER;
BEGIN
    -- Refresh materialized views
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_security_dashboard;
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_critical_vulnerabilities;
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_threat_landscape;
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_incident_metrics;
    
    result_text := result_text || 'Materialized views refreshed. ';
    
    -- Clean up expired data
    SELECT cleanup_expired_data() INTO deleted_records;
    result_text := result_text || 'Deleted ' || deleted_records || ' expired records. ';
    
    -- Update security metrics for yesterday
    PERFORM calculate_security_metrics(
        DATE_TRUNC('day', NOW() - INTERVAL '1 day'),
        DATE_TRUNC('day', NOW())
    );
    result_text := result_text || 'Security metrics updated. ';
    
    -- Analyze tables for query optimization
    ANALYZE security_events;
    ANALYZE vulnerability_assessments;
    ANALYZE access_logs;
    ANALYZE threat_intelligence;
    ANALYZE security_incidents;
    
    result_text := result_text || 'Table statistics updated.';
    
    RETURN result_text;
END;
$ LANGUAGE plpgsql;

-- Role-based security model
CREATE ROLE security_analyst_ro;
CREATE ROLE security_analyst_rw;
CREATE ROLE security_admin;
CREATE ROLE incident_responder;
CREATE ROLE threat_hunter;
CREATE ROLE compliance_auditor;

-- Permissions for read-only analyst
GRANT USAGE ON SCHEMA security_monitor TO security_analyst_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA security_monitor TO security_analyst_ro;
GRANT SELECT ON ALL MATERIALIZED VIEWS IN SCHEMA security_monitor TO security_analyst_ro;

-- Permissions for read-write analyst
GRANT USAGE ON SCHEMA security_monitor TO security_analyst_rw;
GRANT SELECT, INSERT, UPDATE ON security_events TO security_analyst_rw;
GRANT SELECT, INSERT, UPDATE ON vulnerability_assessments TO security_analyst_rw;
GRANT SELECT ON access_logs TO security_analyst_rw;
GRANT SELECT, INSERT, UPDATE ON threat_intelligence TO security_analyst_rw;
GRANT SELECT ON security_incidents TO security_analyst_rw;
GRANT SELECT ON ALL MATERIALIZED VIEWS IN SCHEMA security_monitor TO security_analyst_rw;

-- Permissions for incident responder
GRANT USAGE ON SCHEMA security_monitor TO incident_responder;
GRANT SELECT, INSERT, UPDATE ON security_incidents TO incident_responder;
GRANT SELECT, INSERT, UPDATE ON incident_events TO incident_responder;
GRANT SELECT, UPDATE ON security_events TO incident_responder;
GRANT SELECT ON ALL TABLES IN SCHEMA security_monitor TO incident_responder;

-- Permissions for threat hunter
GRANT USAGE ON SCHEMA security_monitor TO threat_hunter;
GRANT SELECT ON ALL TABLES IN SCHEMA security_monitor TO threat_hunter;
GRANT SELECT, INSERT, UPDATE, DELETE ON threat_intelligence TO threat_hunter;
GRANT EXECUTE ON FUNCTION detect_advanced_threats TO threat_hunter;
GRANT EXECUTE ON FUNCTION enrich_with_threat_intel TO threat_hunter;

-- Permissions for security admin
GRANT ALL PRIVILEGES ON SCHEMA security_monitor TO security_admin;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA security_monitor TO security_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA security_monitor TO security_admin;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA security_monitor TO security_admin;

-- Row Level Security (RLS) for multi-tenant environments
ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_incidents ENABLE ROW LEVEL SECURITY;

-- Sample RLS policy (customize based on your organization structure)
CREATE POLICY security_events_tenant_isolation ON security_events
    FOR ALL TO security_analyst_rw, security_analyst_ro
    USING (
        -- Allow access based on user's assigned systems or departments
        raw_log_data->>'tenant_id' = current_setting('app.current_tenant_id', true)
        OR current_setting('app.current_tenant_id', true) IS NULL
    );

-- Sample realistic data for testing and demonstration
INSERT INTO security_events (
    event_type, severity, source_ip, destination_ip, username, event_title, event_description, raw_log_data, rule_id
) VALUES 
('failed_authentication', 'medium', '192.168.1.100', '10.0.0.10', 'jdoe', 
 'Multiple failed SSH login attempts', 
 'User jdoe failed to authenticate via SSH 5 times in 2 minutes',
 '{"attempts": 5, "protocol": "SSH", "port": 22, "user_agent": "OpenSSH_8.0"}', 'AUTH_001'),

('malware_detection', 'critical', '10.0.0.50', NULL, 'system', 
 'Trojan detected in email attachment', 
 'Sophisticated banking trojan detected in PDF attachment via email',
 '{"file_hash": "a1b2c3d4e5f6789012345678901234567890abcdef", "scanner": "ClamAV", "quarantined": true}', 'MAL_002'),

('network_intrusion', 'high', '203.0.113.42', '10.0.0.100', NULL, 
 'Suspicious network scanning activity', 
 'Port scanning detected from external IP targeting internal servers',
 '{"ports_scanned": [22, 80, 443, 3389], "scan_duration": 120, "packets": 1500}', 'NET_003'),

('data_exfiltration', 'emergency', '10.0.0.25', '198.51.100.10', 'asmith', 
 'Large data transfer to external destination', 
 'Unusual large data transfer detected to suspicious external IP',
 '{"bytes_transferred": 5368709120, "duration": 1800, "encrypted": false}', 'DLP_001');

INSERT INTO vulnerability_assessments (
    cve_id, vulnerability_name, cvss_score, cvss_vector, affected_systems, discovery_date, 
    status, remediation_priority, business_impact_score, exploit_available
) VALUES 
('CVE-2024-1234', 'Apache HTTP Server Remote Code Execution', 9.8, 
 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
 ARRAY['web-server-01', 'web-server-02', 'web-server-03'], 
 CURRENT_DATE - INTERVAL '5 days', 'confirmed', 1, 9, true),

('CVE-2024-5678', 'PostgreSQL Privilege Escalation', 8.1,
 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
 ARRAY['db-server-01', 'db-server-02'], 
 CURRENT_DATE - INTERVAL '10 days', 'in_progress', 1, 8, false),

('CVE-2024-9012', 'Windows SMB Information Disclosure', 6.1,
 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
 ARRAY['file-server-01', 'file-server-02', 'workstation-*'], 
 CURRENT_DATE - INTERVAL '3 days', 'new', 2, 5, false);

INSERT INTO threat_intelligence (
    ioc_type, ioc_value, threat_type, confidence_level, source, tags, mitre_techniques
) VALUES 
('ip', '198.51.100.42', 'c2_server', 95, 'ThreatIntel_Premium', 
 ARRAY['apt', 'c2', 'persistent'], ARRAY['T1071.001', 'T1090']),

('domain', 'malicious-banking-site.example', 'phishing', 87, 'PhishTank_API', 
 ARRAY['phishing', 'banking', 'credential_theft'], ARRAY['T1566.002']),

('file_hash', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 
 'banking_trojan', 92, 'VirusTotal_API', 
 ARRAY['trojan', 'banking', 'keylogger'], ARRAY['T1056.001', 'T1055']);

INSERT INTO security_incidents (
    incident_title, incident_type, incident_category, severity, detected_at, affected_systems,
    incident_summary, assigned_analyst
) VALUES 
('Suspected APT Activity on Network Perimeter', 'intrusion', 'advanced_persistent_threat', 
 'critical', NOW() - INTERVAL '2 hours', 
 ARRAY['firewall-01', 'ids-01', 'web-server-01'],
 'Multiple indicators suggest coordinated attack attempt targeting web infrastructure',
 'senior_analyst_1'),

('Email-based Malware Campaign', 'malware', 'email_security', 
 'high', NOW() - INTERVAL '6 hours',
 ARRAY['email-server-01', 'workstation-finance-*'],
 'Banking trojan distributed via phishing emails targeting finance department',
 'malware_analyst_2');

-- Create monitoring and alerting functions
CREATE OR REPLACE FUNCTION check_critical_events() RETURNS TABLE(
    alert_type TEXT,
    alert_message TEXT,
    event_count BIGINT,
    severity severity_enum
) AS $
BEGIN
    -- Check for critical events in last hour
    RETURN QUERY
    SELECT 
        'critical_events'::TEXT as alert_type,
        'Critical security events detected in last hour'::TEXT as alert_message,
        COUNT(*) as event_count,
        'critical'::severity_enum as severity
    FROM security_events
    WHERE created_at >= NOW() - INTERVAL '1 hour'
    AND severity IN ('critical', 'emergency')
    AND status = 'new'
    HAVING COUNT(*) > 0;
    
    -- Check for brute force attempts
    RETURN QUERY
    SELECT 
        'brute_force'::TEXT as alert_type,
        'Potential brute force attacks detected'::TEXT as alert_message,
        COUNT(*) as event_count,
        'high'::severity_enum as severity
    FROM detect_brute_force_attempts('1 hour', 5)
    HAVING COUNT(*) > 0;
    
    -- Check for unprocessed high priority vulnerabilities
    RETURN QUERY
    SELECT 
        'critical_vulnerabilities'::TEXT as alert_type,
        'Unaddressed critical vulnerabilities found'::TEXT as alert_message,
        COUNT(*) as event_count,
        'high'::severity_enum as severity
    FROM vulnerability_assessments
    WHERE status IN ('new', 'confirmed')
    AND cvss_score >= 9.0
    AND discovery_date < CURRENT_DATE - INTERVAL '7 days'
    HAVING COUNT(*) > 0;
END;
$ LANGUAGE plpgsql;

-- Performance monitoring query
CREATE OR REPLACE VIEW v_performance_stats AS
SELECT 
    schemaname,
    tablename,
    n_tup_ins as inserts,
    n_tup_upd as updates,
    n_tup_del as deletes,
    n_live_tup as live_tuples,
    n_dead_tup as dead_tuples,
    last_vacuum,
    last_autovacuum,
    last_analyze,
    last_autoanalyze
FROM pg_stat_user_tables 
WHERE schemaname = 'security_monitor'
ORDER BY n_live_tup DESC;

-- Final setup and optimization
-- Set appropriate work_mem for complex queries
SET work_mem = '256MB';

-- Create scheduled job framework (requires pg_cron extension)
-- SELECT cron.schedule('security-maintenance', '0 2 * * *', 'SELECT security_monitor.perform_maintenance();');
-- SELECT cron.schedule('metrics-calculation', '0 */6 * * *', 'SELECT security_monitor.calculate_security_metrics();');

-- Documentation and usage examples
COMMENT ON SCHEMA security_monitor IS 'Comprehensive cybersecurity monitoring and incident response database schema';
COMMENT ON TABLE security_events IS 'Central repository for all security-related events with advanced correlation capabilities';
COMMENT ON TABLE vulnerability_assessments IS 'CVSS-based vulnerability tracking with comprehensive remediation workflow';
COMMENT ON TABLE threat_intelligence IS 'Threat intelligence platform with IOC management and MITRE ATT&CK mapping';
COMMENT ON TABLE security_incidents IS 'Enterprise incident response tracking with timeline and impact analysis';
COMMENT ON FUNCTION detect_advanced_threats IS 'Machine learning-ready threat detection based on behavioral patterns';
COMMENT ON FUNCTION calculate_comprehensive_risk_score IS 'Multi-factor risk scoring algorithm for prioritization';

-- Reset search path
SET search_path TO DEFAULT;events se
        WHERE 
            se.created_at >= NOW() - p_time_window
            AND se.status NOT IN ('false_positive', 'resolved')
        GROUP BY se.source_ip, se.username, se.event_type, se.severity
        HAVING COUNT(*) >= 2
    )
    SELECT 
        tp.event_type::TEXT as threat_type,
        tp.source_ip,
        tp.username,
        tp.event_count,
        tp.severity as max_severity,
        tp.first_occurrence as first_seen,
        tp.last_occurrence as last_seen,
        tp.confidence as confidence_score
    FROM threat_patterns tp
    WHERE tp.confidence >= p_min_confidence
    ORDER BY tp.confidence DESC, tp.event_count DESC;
END;
$$ LANGUAGE plpgsql;

-- Function: IOC enrichment and correlation
CREATE OR REPLACE FUNCTION enrich_with_threat_intel(
    p_ioc_value TEXT,
    p_ioc_type ioc_type_enum
) RETURNS TABLE(
    threat_match BOOLEAN,
    threat_type TEXT,
    confidence INTEGER,
    severity severity_enum,
    tags TEXT[],
    description TEXT,
    last_seen TIMESTAMP WITH TIME ZONE
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        TRUE as threat_match,
        ti.threat_type,
        ti.confidence_level as confidence,
        ti.severity,
        ti.tags,
        ti.description,
        ti.last_seen
    FROM threat_intelligence ti
    WHERE 
        ti.ioc_type = p_ioc_type
        AND ti.ioc_normalized = LOWER(TRIM(p_ioc_value))
        AND ti.is_active = TRUE
        AND ti.is_whitelisted = FALSE
        AND (ti.expiration_date IS NULL OR ti.expiration_date > NOW())
    ORDER BY ti.confidence_level DESC, ti.last_seen DESC
    LIMIT 1;
    
    -- If no match found, return default row
    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, NULL::TEXT, NULL::INTEGER, NULL::severity_enum, NULL::TEXT[], NULL::TEXT, NULL::TIMESTAMP WITH TIME ZONE;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Function: Automated security metrics calculation
CREATE OR REPLACE FUNCTION calculate_security_metrics(
    p_start_date TIMESTAMP WITH TIME ZONE DEFAULT DATE_TRUNC('day', NOW() - INTERVAL '1 day'),
    p_end_date TIMESTAMP WITH TIME ZONE DEFAULT DATE_TRUNC('day', NOW())
) RETURNS INTEGER AS $$
DECLARE
    metrics_calculated INTEGER := 0;
BEGIN
    -- Clear existing metrics for the period
    DELETE FROM security_metrics 
    WHERE period_start = p_start_date AND period_end = p_end_date;
    
    -- Security Events Metrics
    INSERT INTO security_metrics (
        metric_category, metric_name, metric_value, metric_unit,
        period_start, period_end, calculation_method
    )
    SELECT 
        'security_events',
        'total_events',
        COUNT(*),
        'count',
        p_start_date,
        p_end_date,
        'Direct count from security_events table'
    FROM security_events
    WHERE created_at >= p_start_date AND created_at < p_end_date;
    
    -- Critical Events Rate
    INSERT INTO security_metrics (
        metric_category, metric_name, metric_value, metric_unit,
        period_start, period_end, calculation_method, is_kpi
    )
    SELECT 
        'security_events',
        'critical_events_rate',
        CASE 
            WHEN total.count > 0 THEN (critical.count * 100.0 / total.count)
            ELSE 0
        END,
        'percentage',
        p_start_date,
        p_end_date,
        'Percentage of critical/emergency events vs total events',
        TRUE
    FROM 
        (SELECT COUNT(*) as count FROM security_events 
         WHERE created_at >= p_start_date AND created_at < p_end_date) total,
        (SELECT COUNT(*) as count FROM security_events 
         WHERE created_at >= p_start_date AND created_at < p_end_date 
         AND severity IN ('critical', 'emergency')) critical;
    
    -- Mean Time to Detection (MTTD)
    INSERT INTO security_metrics (
        metric_category, metric_name, metric_value, metric_unit,
        period_start, period_end, calculation_method, is_kpi
    )
    SELECT 
        'incident_response',
        'mean_time_to_detect',
        COALESCE(EXTRACT(EPOCH FROM AVG(time_to_detect))/3600, 0),
        'hours',
        p_start_date,
        p_end_date,
        'Average time between incident occurrence and detection',
        TRUE
    FROM security_incidents
    WHERE detected_at >= p_start_date AND detected_at < p_end_date
    AND time_to_detect IS NOT NULL;
    
    -- Vulnerability Management Metrics
    INSERT INTO security_metrics (
        metric_category, metric_name, metric_value, metric_unit,
        period_start, period_end, calculation_method, is_kpi
    )
    SELECT 
        'vulnerability_management',
        'critical_vulns_open',
        COUNT(*),
        'count',
        p_start_date,
        p_end_date,
        'Count of critical vulnerabilities in open status',
        TRUE
    FROM vulnerability_assessments
    WHERE status IN ('new', 'confirmed', 'in_progress')
    AND cvss_score >= 9.0;
    
    GET DIAGNOSTICS metrics_calculated = ROW_COUNT;
    
    RETURN metrics_calculated;
END;
$$ LANGUAGE plpgsql;

-- Trigger functions for automatic maintenance
CREATE OR REPLACE FUNCTION update_timestamp_trigger() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION calculate_incident_metrics_trigger() RETURNS TRIGGER AS $$
BEGIN
    -- Calculate time-based metrics when incident status changes
    IF NEW.acknowledged_at IS NOT NULL AND OLD.acknowledged_at IS NULL THEN
        NEW.time_to_respond = NEW.acknowledged_at - NEW.detected_at;
    END IF;
    
    IF NEW.contained_at IS NOT NULL AND OLD.contained_at IS NULL THEN
        NEW.time_to_contain = NEW.contained_at - NEW.detected_at;
    END IF;
    
    IF NEW.closed_at IS NOT NULL AND OLD.closed_at IS NULL THEN
        NEW.time_to_resolve = NEW.closed_at - NEW.detected_at;
    END IF;
    
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create triggers
CREATE TRIGGER tr_security_events_updated_at
    BEFORE UPDATE ON security_events
    FOR EACH ROW EXECUTE FUNCTION update_timestamp_trigger();

CREATE TRIGGER tr_vulnerability_assessments_updated_at
    BEFORE UPDATE ON vulnerability_assessments
    FOR EACH ROW EXECUTE FUNCTION update_timestamp_trigger();

CREATE TRIGGER tr_threat_intelligence_updated_at
    BEFORE UPDATE ON threat_intelligence
    FOR EACH ROW EXECUTE FUNCTION update_timestamp_trigger();

CREATE TRIGGER tr_security_incidents_metrics
    BEFORE UPDATE ON security_incidents
    FOR EACH ROW EXECUTE FUNCTION calculate_incident_metrics_trigger();

-- Materialize views for performance
CREATE MATERIALIZED VIEW mv_security_dashboard AS
SELECT 
    'Last 24 Hours' as time_period,
    COUNT(*) as total_events,
    COUNT(*) FILTER (WHERE severity IN ('critical', 'emergency')) as critical_events,
    COUNT(*) FILTER (WHERE event_type LIKE '%authentication%') as auth_events,
    COUNT(*) FILTER (WHERE event_type LIKE '%malware%') as malware_events,
    COUNT(*) FILTER (WHERE status = 'new') as unprocessed_events,
    AVG(CASE WHEN processed_at IS NOT NULL THEN 
        EXTRACT(EPOCH FROM (processed_at - created_at))/60 
        ELSE NULL END) as avg_processing_time_minutes
FROM security_
