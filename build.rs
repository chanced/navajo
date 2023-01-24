use std::fs;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    fs::remove_dir_all("src/proto").unwrap_or(());
    fs::create_dir_all("src/proto").unwrap();
    let protos = [
        "proto/aead.proto",
        "proto/aes_gcm.proto",
        "proto/chacha20_poly1305.proto",
        "proto/daead.proto",
        "proto/ed25519.proto",
        "proto/hybrid.proto",
        "proto/keyset.proto",
        "proto/mac.proto",
        "proto/signature.proto",
        "proto/status.proto",
    ];

    prost_build::Config::new()
        .out_dir("src/proto")
        .compile_protos(&protos, &["."])?;
    Ok(())
}
