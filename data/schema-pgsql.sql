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
    public_key TEXT,
    private_key TEXT,
    certificate_type VARCHAR(50), -- 'RSA', 'ECDSA', or NULL for no certificate
    certificate_fingerprint VARCHAR(128), -- SHA256 fingerprint for certificate verification
    private_key_path TEXT, -- Path in vault where private key is stored
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

CREATE TABLE data_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    db_type VARCHAR(50) NOT NULL, -- 'postgresql', 'mysql', 'mariadb'
    host VARCHAR(255) NOT NULL,
    port INTEGER DEFAULT 5432,
    database_name VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    password_hash TEXT NOT NULL,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
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
-- MESSAGING SYSTEM
-- ======================================

CREATE TABLE conversations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    title VARCHAR(255),
    type VARCHAR(50) DEFAULT 'direct', -- 'direct', 'group', 'channel'
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    is_archived BOOLEAN DEFAULT false,
    last_message_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
);

CREATE TABLE conversation_participants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(50) DEFAULT 'member', -- 'admin', 'member', 'guest'
    joined_at TIMESTAMP DEFAULT now(),
    last_read_at TIMESTAMP,
    is_muted BOOLEAN DEFAULT false,
    UNIQUE(conversation_id, user_id)
);

CREATE TABLE messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
    sender_id UUID REFERENCES users(id) ON DELETE SET NULL,
    content TEXT,
    message_type VARCHAR(50) DEFAULT 'text', -- 'text', 'image', 'file', 'system'
    reply_to_id UUID REFERENCES messages(id) ON DELETE SET NULL,
    is_edited BOOLEAN DEFAULT false,
    edited_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
);

CREATE TABLE message_attachments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id UUID REFERENCES messages(id) ON DELETE CASCADE,
    filename VARCHAR(255) NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    mime_type VARCHAR(100),
    file_size INTEGER,
    file_url TEXT,
    created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE message_reactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id UUID REFERENCES messages(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    reaction VARCHAR(50) NOT NULL, -- emoji or reaction type
    created_at TIMESTAMP DEFAULT now(),
    UNIQUE(message_id, user_id, reaction)
);

CREATE TABLE message_reads (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id UUID REFERENCES messages(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    read_at TIMESTAMP DEFAULT now(),
    UNIQUE(message_id, user_id)
);

-- ======================================
-- DEVICE MANAGEMENT
-- ======================================

CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    ip_address INET,
    device_type VARCHAR(50) NOT NULL,
    connection_type VARCHAR(50) NOT NULL,
    vendor VARCHAR(255),
    model VARCHAR(255),
    os_version VARCHAR(255),
    status VARCHAR(50) DEFAULT 'unknown',
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    location VARCHAR(255),
    tags TEXT[],
    management_port INTEGER,
    credentials_ref VARCHAR(255),
    last_seen TIMESTAMP,
    uptime BIGINT,
    cpu_usage REAL,
    memory_usage REAL,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
);

CREATE TABLE device_commands (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    command TEXT NOT NULL,
    parameters JSONB,
    status VARCHAR(50) DEFAULT 'pending',
    output TEXT,
    exit_code INTEGER,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE device_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    timestamp TIMESTAMP DEFAULT now(),
    cpu_usage REAL,
    memory_usage REAL,
    disk_usage REAL,
    network_stats JSONB,
    temperature REAL,
    power_usage REAL,
    custom_metrics JSONB DEFAULT '{}'
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

CREATE OR REPLACE FUNCTION update_conversation_last_message()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE conversations
    SET last_message_at = NEW.created_at
    WHERE id = NEW.conversation_id;
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

CREATE TRIGGER update_conversations_timestamp
BEFORE UPDATE ON conversations
FOR EACH ROW
EXECUTE FUNCTION update_timestamp();

CREATE TRIGGER update_messages_timestamp
BEFORE UPDATE ON messages
FOR EACH ROW
EXECUTE FUNCTION update_timestamp();

CREATE TRIGGER update_data_sources_timestamp
BEFORE UPDATE ON data_sources
FOR EACH ROW
EXECUTE FUNCTION update_timestamp();

CREATE TRIGGER update_devices_timestamp
BEFORE UPDATE ON devices
FOR EACH ROW
EXECUTE FUNCTION update_timestamp();

CREATE TRIGGER update_conversation_last_message_trigger
AFTER INSERT ON messages
FOR EACH ROW
EXECUTE FUNCTION update_conversation_last_message();
