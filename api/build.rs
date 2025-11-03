fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Skip proto compilation if protoc is not available
    if std::env::var("PROTOC").is_err() && !std::path::Path::new("protoc").exists() {
        println!("cargo:warning=protoc not found, skipping proto compilation");
        return Ok(());
    }
    
    tonic_build::configure()
        .build_client(true)    // optional: generate client code
        .build_server(true)    // optional: generate server code
        .compile_protos(&["proto/sky_genesis.proto"], &["proto"])?;
    Ok(())
}
