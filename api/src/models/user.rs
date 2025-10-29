// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: User Model
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Define user account data structure with authentication,
//  authorization, and profile management capabilities.
//  NOTICE: User model implements secure user management with role-based
//  access control, audit trails, and GDPR compliance features.
//  USER STANDARDS: RBAC, Profile Management, Authentication
//  COMPLIANCE: GDPR, Data Protection, User Privacy Standards
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// [USER STRUCT] Enterprise User Account Model
/// @MISSION Define user identity with roles and profile information.
/// @THREAT Unauthorized access, data leakage, identity spoofing.
/// @COUNTERMEASURE Secure storage, access controls, audit logging.
/// @INVARIANT User data is protected and access is controlled.
/// @AUDIT User operations are logged for compliance.
/// @DEPENDENCY Core model for authentication and authorization.
#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct User {
    pub id: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub roles: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub enabled: bool,
}