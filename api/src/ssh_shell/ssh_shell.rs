use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshShellSession {
    pub id: Uuid,
    pub user_id: String,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub is_active: bool,
}

#[derive(Debug, Clone)]
pub struct SshShellHandler {
    sessions: Arc<RwLock<std::collections::HashMap<Uuid, SshShellSession>>>,
}

impl SshShellHandler {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    pub async fn create_session(&self, user_id: String) -> Uuid {
        let session_id = Uuid::new_v4();
        let session = SshShellSession {
            id: session_id,
            user_id,
            created_at: Utc::now(),
            last_activity: Utc::now(),
            is_active: true,
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id, session);
        session_id
    }

    pub async fn get_session(&self, session_id: &Uuid) -> Option<SshShellSession> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned()
    }

    pub async fn update_activity(&self, session_id: &Uuid) {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.last_activity = Utc::now();
        }
    }

    pub async fn close_session(&self, session_id: &Uuid) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id);
    }
}

#[derive(Debug, Clone)]
pub struct ShellSessionManager {
    handler: Arc<SshShellHandler>,
}

impl ShellSessionManager {
    pub fn new() -> Self {
        Self {
            handler: Arc::new(SshShellHandler::new()),
        }
    }

    pub fn handler(&self) -> Arc<SshShellHandler> {
        self.handler.clone()
    }
}