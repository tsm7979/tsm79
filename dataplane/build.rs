/// build.rs — generates Rust gRPC client code from proto/*.proto via tonic.
///
/// Compiles two contracts:
///   • proto/detect.proto — dataplane ↔ Python ML detector
///   • proto/edge.proto   — dataplane ↔ C++ wasmtime edge worker host (#28)
///
/// The generated code lives in `dataplane/src/gen/` and is imported by:
///   • `pipeline.rs` → `crate::gen::tsm_detect::detect_service_client::DetectServiceClient`
///   • `edge/client.rs` → `crate::gen::tsm_edge::edge_service_client::EdgeServiceClient`
///
/// Why tonic for gRPC instead of raw HTTP:
///   - Type-safe: request/response structs are generated from the .proto contract.
///   - Multiplexing: one TCP connection handles many concurrent calls.
///   - Streaming: DetectStream RPC streams findings as each ML layer completes.
///   - Backpressure: gRPC flow control prevents the Python pod from being
///     overwhelmed when detection is slower than request arrival.
///
/// To activate gRPC, add to Cargo.toml:
///   [features]
///   grpc = ["tonic", "prost"]
///
///   [dependencies]
///   tonic = { version = "0.11", optional = true }
///   prost = { version = "0.12", optional = true }
///
///   [build-dependencies]
///   tonic-build = "0.11"

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Only regenerate when proto files change (cargo caching)
    println!("cargo:rerun-if-changed=../proto/detect.proto");
    println!("cargo:rerun-if-changed=../proto/edge.proto");

    // Check whether tonic-build is available (feature-gated to avoid forcing
    // the dependency on users who only build the fast-path binary).
    #[cfg(feature = "grpc")]
    {
        // tonic-build writes into out_dir but does not create it.
        std::fs::create_dir_all("src/gen")?;
        tonic_build::configure()
            .out_dir("src/gen")
            .build_client(true)
            .build_server(false)   // dataplane is the client for both detector + edge
            .compile(
                &[
                    "../proto/detect.proto",
                    "../proto/edge.proto",   // #28 — edge worker contract
                ],
                &["../proto"],
            )?;
    }

    Ok(())
}
