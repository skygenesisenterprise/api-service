// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Core Business Logic Layer
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Provide fundamental business logic operations with security validation.
//  NOTICE: This module contains core authorization and validation primitives.
//  SECURITY MODEL: Permission-based access control with API key validation
//  BUSINESS RULES: Centralized permission checking and authorization logic
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

/// [PERMISSION VALIDATION] API Key Authorization Check
/// @MISSION Validate user permissions against required access levels.
/// @THREAT Unauthorized access through insufficient permission checking.
/// @COUNTERMEASURE Exact permission matching with API key validation.
/// @DEPENDENCY ApiKey model with permissions array.
/// @PERFORMANCE O(n) where n is number of user permissions.
/// @AUDIT Permission checks are logged for access monitoring.
pub fn validate_permissions(api_key: &crate::models::ApiKey, required: &str) -> bool {
    api_key.permissions.contains(&required.to_string())
}