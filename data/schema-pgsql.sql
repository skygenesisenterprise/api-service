-- ======================================
-- SKY GENESIS ENTERPRISE - OFFICIAL API
-- PostgreSQL Schema v1.0
-- ======================================

CREATE SCHEMA IF NOT EXISTS api_service;

SET search_path TO api_service;

-- ======================================
-- CORE STRUCTURE
-- ======================================

CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    country_code CHAR(2),
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL UNIQUE,
    full_name VARCHAR(255),
    password_hash TEXT NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
);

CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    access_token TEXT NOT NULL,
    refresh_token TEXT,
    expires_at TIMESTAMP NOT NULL,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT now()
);

-- ======================================
-- API MANAGEMENT
-- ======================================

CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    key_value TEXT UNIQUE NOT NULL,
    label VARCHAR(255),
    permissions TEXT[],
    quota_limit INTEGER DEFAULT 100000,
    usage_count INTEGER DEFAULT 0,
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE api_routes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    path VARCHAR(255) NOT NULL,
    service_name VARCHAR(100),
    is_public BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE api_access_log (
    id BIGSERIAL PRIMARY KEY,
    api_key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL,
    route_id UUID REFERENCES api_routes(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    ip_address INET,
    response_status INTEGER,
    latency_ms INTEGER,
    timestamp TIMESTAMP DEFAULT now()
);

-- ======================================
-- INFRASTRUCTURE (OPTIONAL)
-- ======================================

CREATE TABLE infra_nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    region VARCHAR(50),
    ip_address INET,
    status VARCHAR(50) DEFAULT 'online',
    capacity_score NUMERIC(5,2) DEFAULT 100.0,
    created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE service_registry (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    version VARCHAR(50),
    base_url TEXT NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    node_id UUID REFERENCES infra_nodes(id) ON DELETE SET NULL,
    registered_at TIMESTAMP DEFAULT now()
);

-- ======================================
-- AI & ANALYTICS (OPTIONAL)
-- ======================================

CREATE TABLE ai_models (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    version VARCHAR(50),
    owner_id UUID REFERENCES users(id),
    repo_url TEXT,
    framework VARCHAR(50),
    status VARCHAR(50) DEFAULT 'training',
    created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE ai_inference_log (
    id BIGSERIAL PRIMARY KEY,
    model_id UUID REFERENCES ai_models(id),
    user_id UUID REFERENCES users(id),
    input_size INTEGER,
    output_size INTEGER,
    latency_ms INTEGER,
    created_at TIMESTAMP DEFAULT now()
);

-- ======================================
-- AUDIT & MONITORING
-- ======================================

CREATE TABLE audit_events (
    id BIGSERIAL PRIMARY KEY,
    actor_id UUID REFERENCES users(id),
    organization_id UUID REFERENCES organizations(id),
    event_type VARCHAR(255),
    event_data JSONB,
    created_at TIMESTAMP DEFAULT now()
);

-- ======================================
-- TRIGGERS
-- ======================================

CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_users_timestamp
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION update_timestamp();

CREATE TRIGGER update_orgs_timestamp
BEFORE UPDATE ON organizations
FOR EACH ROW
EXECUTE FUNCTION update_timestamp();
