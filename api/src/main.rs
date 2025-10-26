use warp::{Filter, Reply};
use std::convert::Infallible;

#[tokio::main]
async fn main() {
    let hello = warp::path!("hello")
        .map(|| "Hello, World!");

    println!("Server started at http://localhost:3000");

    warp::serve(hello)
        .run(([127, 0, 0, 1], 3000))
        .await;
}
