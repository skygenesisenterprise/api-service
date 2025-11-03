// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Search Functionality
// // ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Provide comprehensive search capabilities across enterprise data.
//  NOTICE: This module contains search service and models.
//  INTEGRATION: Tantivy search engine, authentication, authorization
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

/// [SEARCH SERVICE] Enterprise Search Engine
/// @MISSION Provide secure, scalable search across enterprise data.
/// @THREAT Unauthorized data access or search manipulation.
/// @COUNTERMEASURE Authentication, authorization, and access control filtering.
/// @DEPENDENCY Tantivy search engine with security integration.
/// @INVARIANT All search results respect user permissions.
pub mod service;

/// [SEARCH MODELS] Search Data Models
/// @MISSION Define data models for search functionality.
/// @THREAT Data model manipulation or validation bypass.
/// @COUNTERMEASURE Input validation and type safety.
/// @DEPENDENCY serde for serialization and validator for input validation.
/// @INVARIANT All models are validated before use.
pub mod models;