fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_client(true)    // optional: generate client code
        .build_server(true)    // optional: generate server code
        .compile_protos(&["proto/sky_genesis.proto"], &["proto"])?;
    Ok(())
}
