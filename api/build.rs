fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/sky_genesis.proto")?;
    Ok(())
}