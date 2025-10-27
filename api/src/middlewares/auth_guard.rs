use warp::{Filter, Rejection};
use crate::utils::tokens;
use crate::middlewares::auth_middleware::Claims;

pub fn auth_guard() -> impl Filter<Extract = (Claims,), Error = Rejection> + Clone {
    warp::header::<String>("authorization")
        .and_then(|auth: String| async move {
            if !auth.starts_with("Bearer ") {
                return Err(warp::reject::custom(crate::middlewares::auth::AuthError::InvalidToken));
            }
            let token = auth.trim_start_matches("Bearer ");
            match tokens::validate_jwt(token) {
                Ok(claims) => Ok(Claims {
                    sub: claims.sub,
                    email: claims.email,
                    roles: claims.roles,
                    exp: claims.exp,
                    iat: claims.iat,
                }),
                Err(_) => Err(warp::reject::custom(crate::middlewares::auth::AuthError::InvalidToken)),
            }
        })
}