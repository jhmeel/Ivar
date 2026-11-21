//! Compiles every proto file in proto/ivar/v1 with serde support.

fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");
    std::env::set_var("PROTOC", protoc);

    let mut protos: Vec<String> = std::fs::read_dir("../../proto/ivar/v1")
        .expect("proto directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path().display().to_string())
        .filter(|path| path.ends_with(".proto"))
        .collect();
    protos.sort();

    let mut cfg = prost_build::Config::new();
    cfg.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    cfg.message_attribute(".", "#[serde(default)]");
    cfg.btree_map(["."]);
    cfg.compile_protos(&protos, &["../../proto"]).expect("compile ivar.v1 protos");
    println!("cargo:rerun-if-changed=../../proto/ivar/v1");
}
