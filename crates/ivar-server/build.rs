//! Generates the gRPC Ingest service; messages come from ivar_contracts.

fn main() {
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path().expect("vendored protoc"));
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .extern_path(".ivar.v1", "::ivar_contracts::proto")
        .compile_protos(&["../../proto/ivar/v1/ingest.proto"], &["../../proto"])
        .expect("compile ingest.proto");
    println!("cargo:rerun-if-changed=../../proto/ivar/v1");
}
