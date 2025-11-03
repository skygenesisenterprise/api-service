// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: User Query Builders
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Build query parameters for user service API calls.
//  NOTICE: This module provides structured query builders for user operations.
//  SECURITY: Query validation and sanitization
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use serde_json::{json, Value};

/// User query builders for API requests
#[allow(dead_code)]
pub struct UserQuery;

#[allow(dead_code)]
impl UserQuery {
    /// Build query for listing users
    #[allow(dead_code)]
    pub fn list(limit: Option<u64>, offset: Option<u64>) -> Value {
        json!({
            "action": "list",
            "limit": limit.unwrap_or(50),
            "offset": offset.unwrap_or(0)
        })
    }

    /// Build query for getting user details
    #[allow(dead_code)]
    pub fn get(username: &str) -> Value {
        json!({
            "action": "get",
            "username": username
        })
    }

    /// Build query for creating a user
    #[allow(dead_code)]
    pub fn create(username: &str, email: &str, role: &str) -> Value {
        json!({
            "action": "create",
            "username": username,
            "email": email,
            "role": role
        })
    }

    /// Build query for updating a user
    #[allow(dead_code)]
    pub fn update(username: &str, email: Option<&str>, role: Option<&str>, status: Option<&str>) -> Value {
        let mut params = json!({
            "action": "update",
            "username": username
        });

        if let Some(e) = email {
            params["email"] = json!(e);
        }
        if let Some(r) = role {
            params["role"] = json!(r);
        }
        if let Some(s) = status {
            params["status"] = json!(s);
        }

        params
    }

    /// Build query for deleting a user
    #[allow(dead_code)]
    pub fn delete(username: &str) -> Value {
        json!({
            "action": "delete",
            "username": username
        })
    }

    /// Build query for user authentication
    #[allow(dead_code)]
    pub fn authenticate(username: &str, password: &str) -> Value {
        json!({
            "action": "authenticate",
            "username": username,
            "password": password
        })
    }

    /// Build query for changing password
    #[allow(dead_code)]
    pub fn change_password(username: &str, old_password: &str, new_password: &str) -> Value {
        json!({
            "action": "change_password",
            "username": username,
            "old_password": old_password,
            "new_password": new_password
        })
    }

    /// Build query for user permissions
    #[allow(dead_code)]
    pub fn permissions(username: &str) -> Value {
        json!({
            "action": "permissions",
            "username": username
        })
    }
}