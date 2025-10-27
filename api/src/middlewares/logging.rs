// Logging middleware

use warp::{Filter, Reply};

pub fn log_requests() -> impl Filter<Extract = (impl Reply,), Error = warp::Rejection> + Clone {
    warp::log::custom(|info| {
        println!("{} {} {}", info.method(), info.path(), info.status());
    })
}