use warp::Filter;
use std::sync::Arc;
use crate::controllers::openpgp_controller;
use crate::services::openpgp_service::OpenPGPService;
use crate::middlewares::auth_middleware::jwt_auth;
use crate::middlewares::openpgp_middleware::{pgp_message_size_limit, validate_pgp_key};
use crate::models::openpgp_model::*;

pub fn openpgp_routes(
    openpgp_service: Arc<OpenPGPService>,
    keycloak_client: Arc<crate::core::keycloak::KeycloakClient>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let generate_key = warp::path!("api" / "v1" / "openpgp" / "generate")
        .and(warp::post())
        .and(jwt_auth(keycloak_client.clone()))
        .and(warp::body::json::<GenerateKeyRequest>())
        .and(warp::any().map(move || openpgp_service.clone()))
        .and_then(|_claims, request, service| async move {
            openpgp_controller::generate_key(service, request).await
        });

    let sign = warp::path!("api" / "v1" / "openpgp" / "sign")
        .and(warp::post())
        .and(jwt_auth(keycloak_client.clone()))
        .and(pgp_message_size_limit())
        .and(warp::body::json::<SignMessageRequest>())
        .and(warp::any().map(move || openpgp_service.clone()))
        .and_then(|_claims, request, service| async move {
            openpgp_controller::sign_message(service, request).await
        });

    let verify = warp::path!("api" / "v1" / "openpgp" / "verify")
        .and(warp::post())
        .and(jwt_auth(keycloak_client.clone()))
        .and(pgp_message_size_limit())
        .and(warp::body::json::<VerifySignatureRequest>())
        .and(warp::any().map(move || openpgp_service.clone()))
        .and_then(|_claims, request, service| async move {
            openpgp_controller::verify_signature(service, request).await
        });

    let encrypt = warp::path!("api" / "v1" / "openpgp" / "encrypt")
        .and(warp::post())
        .and(jwt_auth(keycloak_client.clone()))
        .and(pgp_message_size_limit())
        .and(warp::body::json::<EncryptMessageRequest>())
        .and(warp::any().map(move || openpgp_service.clone()))
        .and_then(|_claims, request, service| async move {
            openpgp_controller::encrypt_message(service, request).await
        });

    let decrypt = warp::path!("api" / "v1" / "openpgp" / "decrypt")
        .and(warp::post())
        .and(jwt_auth(keycloak_client.clone()))
        .and(pgp_message_size_limit())
        .and(warp::body::json::<DecryptMessageRequest>())
        .and(warp::any().map(move || openpgp_service.clone()))
        .and_then(|_claims, request, service| async move {
            openpgp_controller::decrypt_message(service, request).await
        });

    // Optional: Route with PGP key validation
    let secure_generate = warp::path!("api" / "v1" / "openpgp" / "secure" / "generate")
        .and(warp::post())
        .and(validate_pgp_key(openpgp_service.clone()))
        .and(warp::body::json::<GenerateKeyRequest>())
        .and(warp::any().map(move || openpgp_service.clone()))
        .and_then(|_validated_key, request, service| async move {
            openpgp_controller::generate_key(service, request).await
        });

    generate_key.or(sign).or(verify).or(encrypt).or(decrypt).or(secure_generate)
}