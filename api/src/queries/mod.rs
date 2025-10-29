// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Queries Module
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Organize database query abstractions for secure data access,
//  providing type-safe database operations with audit logging and
//  tenant isolation.
//  NOTICE: Queries implement database abstraction with prepared statements,
//  connection pooling, and security controls for all data operations.
//  DB STANDARDS: PostgreSQL, Prepared Statements, Connection Pooling
//  COMPLIANCE: Data Security, Audit Requirements, Tenant Isolation
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

/// [GENERIC QUERY MODULE] Common database query utilities
pub mod query;
/// [KEY QUERIES MODULE] API key database operations
pub mod key_queries;