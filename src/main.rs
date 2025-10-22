mod models;
mod handlers;
mod middleware;
mod services;
mod utils;

use actix_web::{web, App, HttpServer, middleware::Logger};
use dotenvy::dotenv;
use std::env;

use crate::middleware::auth::AuthenticateApiKey;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");

    // Create database connection pool
    let pool = utils::db::establish_connection(&database_url);

    log::info!("Starting server on http://localhost:3001");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .wrap(actix_cors::Cors::permissive())
            .wrap(Logger::default())
            .service(
                web::scope("/api")
                    .configure(handlers::auth::config)
            )
            .service(
                web::scope("/api/v1")
                    .wrap(AuthenticateApiKey::new(pool.clone()))
                    .configure(handlers::api_key::config)
                    .configure(handlers::messaging::config)
            )
    })
    .bind("127.0.0.1:3001")?
    .run()
    .await
}