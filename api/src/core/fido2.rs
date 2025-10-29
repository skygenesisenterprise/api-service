use webauthn_rs::prelude::*;
use webauthn_rs::Webauthn;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Serialize, Deserialize, Clone)]
pub struct Fido2Credential {
    pub cred_id: String,
    pub cred: Credential,
    pub counter: u32,
    pub user_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct Fido2RegistrationRequest {
    pub username: String,
    pub display_name: String,
}

#[derive(Serialize, Deserialize)]
pub struct Fido2RegistrationResponse {
    pub challenge: String,
    pub user_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct Fido2AuthenticationRequest {
    pub username: String,
}

#[derive(Serialize, Deserialize)]
pub struct Fido2AuthenticationResponse {
    pub challenge: String,
}

pub struct Fido2Manager {
    webauthn: Webauthn,
    credentials: Arc<RwLock<HashMap<String, Vec<Fido2Credential>>>>, // user_id -> credentials
}

impl Fido2Manager {
    pub fn new(rp_id: &str, rp_origin: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let webauthn = Webauthn::new(
            Url::parse(rp_origin)?,
            Url::parse(rp_origin)?,
            vec![Url::parse(rp_origin)?],
        );

        Ok(Fido2Manager {
            webauthn,
            credentials: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn start_registration(&self, request: Fido2RegistrationRequest) -> Result<Fido2RegistrationResponse, Box<dyn std::error::Error>> {
        let user_id = uuid::Uuid::new_v4().to_string();
        let user = User::builder()
            .name(request.username.clone())
            .display_name(request.display_name)
            .id(user_id.clone().into())
            .credentials(vec![])
            .build();

        let (challenge, passkey_registration) = self.webauthn.start_passkey_registration(
            user,
            None,
            WebauthnCredential::new_random(),
        )?;

        // Store the challenge temporarily (in production, use Redis/session)
        // For now, we'll return it directly

        Ok(Fido2RegistrationResponse {
            challenge: serde_json::to_string(&passkey_registration)?,
            user_id,
        })
    }

    pub async fn finish_registration(
        &self,
        user_id: &str,
        challenge: &str,
        response: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let passkey_registration: CreationChallengeResponse = serde_json::from_str(challenge)?;
        let credential: RegisterPublicKeyCredential = serde_json::from_str(response)?;

        let passkey = self.webauthn.finish_passkey_registration(&credential, &passkey_registration)?;

        let fido_cred = Fido2Credential {
            cred_id: passkey.cred_id().to_string(),
            cred: passkey.cred.clone(),
            counter: passkey.counter,
            user_id: user_id.to_string(),
        };

        let mut creds = self.credentials.write().await;
        creds.entry(user_id.to_string()).or_insert_with(Vec::new).push(fido_cred);

        Ok(())
    }

    pub async fn start_authentication(&self, username: &str) -> Result<Fido2AuthenticationResponse, Box<dyn std::error::Error>> {
        let creds = self.credentials.read().await;
        let user_creds = creds.get(username).ok_or("User not found")?;

        let credentials: Vec<Credential> = user_creds.iter().map(|c| c.cred.clone()).collect();

        let (challenge, authentication_state) = self.webauthn.start_passkey_authentication(&credentials)?;

        Ok(Fido2AuthenticationResponse {
            challenge: serde_json::to_string(&authentication_state)?,
        })
    }

    pub async fn finish_authentication(
        &self,
        username: &str,
        challenge: &str,
        response: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let creds = self.credentials.read().await;
        let user_creds = creds.get(username).ok_or("User not found")?;
        let credentials: Vec<Credential> = user_creds.iter().map(|c| c.cred.clone()).collect();

        let authentication_state: AuthenticationState = serde_json::from_str(challenge)?;
        let credential: PublicKeyCredential = serde_json::from_str(response)?;

        let _auth_result = self.webauthn.finish_passkey_authentication(&credential, &authentication_state, &credentials)?;

        Ok(())
    }

    pub async fn get_user_credentials(&self, user_id: &str) -> Vec<Fido2Credential> {
        let creds = self.credentials.read().await;
        creds.get(user_id).cloned().unwrap_or_default()
    }
}