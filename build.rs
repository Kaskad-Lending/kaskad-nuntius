//! Build script: compiles the MEXC protobuf schema using the vendored
//! protoc binary so the build doesn't require apt-get protobuf-compiler.

fn main() {
    println!("cargo:rerun-if-changed=proto/mexc.proto");
    let protoc = protoc_bin_vendored::protoc_bin_path()
        .expect("protoc-bin-vendored: binary missing for this target");
    std::env::set_var("PROTOC", protoc);

    let mut config = prost_build::Config::new();
    config
        .compile_protos(&["proto/mexc.proto"], &["proto/"])
        .expect("compile MEXC protos");
}
