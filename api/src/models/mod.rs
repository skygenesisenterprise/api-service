// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Models Module
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Organize and expose data models for the enterprise API service,
//  providing type-safe structures for users, keys, mail, and other entities.
//  NOTICE: Models implement serialization, validation, and type safety for
//  all API data structures with enterprise security standards.
//  MODEL STANDARDS: Type Safety, Serialization, Validation, Documentation
//  COMPLIANCE: Data Protection, Type Safety, API Standards
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

/// [KEY MODEL MODULE] API key and certificate data structures
pub mod key_model;
/// [USER MODEL MODULE] User account and authentication models
pub mod user;
/// [MAIL MODEL MODULE] Email and messaging data structures
pub mod mail;
/// [DATABASE MODEL MODULE] Database connection and management models
pub mod data_model;
/// [SEARCH MODEL MODULE] Search and indexing data structures
pub mod search_models;
/// [OPENPGP MODEL MODULE] OpenPGP cryptographic data structures
pub mod openpgp_model;
/// [VOIP MODEL MODULE] Voice over IP call and conference data structures
pub mod voip;
/// [DISCORD MODEL MODULE] Discord bot integration data structures
pub mod discord_model;