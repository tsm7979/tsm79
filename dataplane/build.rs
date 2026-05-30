/// build.rs — generates Rust gRPC client code from proto/detect.proto via tonic.
///
/// The generated code lives in `dataplane/src/gen/` and is imported by
/// `pipeline.rs` as `crate::gen::tsm_detect::detect_service_client::DetectServiceClient`.
///
/// Why tonic for gRPC instead of raw HTTP:
///   - Type-safe: request/response structs are generated from the .proto contract.
///   - Multiplexing: one TCP connection handles many concurrent detect calls.
///   - Streaming: DetectStream RPC streams findings as each ML layer completes.
///   - Backpressure: gRPC flow control prevents the Python pod from being
///     overwhelmed when detection is slower than request arrival.
///
/// To activate gRPC, add to Cargo.toml:
///   [dependencies]
///   tonic = "0.11"
///   prost = "0.12"
///
///   [build-dependencies]
///   tonic-build = "0.11"

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Only regenerate when the proto file changes (cargo caching)
    println!("cargo:rerun-if-changed=../proto/detect.proto");

    // Check whether tonic-build is available (feature-gated to avoid forcing
    // the dependency on users who only build the fast-path binary).
    #[cfg(feature = "grpc")]
    {
        // tonic-build writes into out_dir but does not create it.
        std::fs::create_dir_all("src/gen")?;
        tonic_build::configure()
            .out_dir("src/gen")
            .build_client(true)
            .build_server(false)   // dataplane is the client; Python is the server
            .compile(&["../proto/detect.proto"], &["../proto"])?;
    }

    Ok(())
}
