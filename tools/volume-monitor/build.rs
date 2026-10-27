fn main() {
    std::env::set_var(
        "PROTOC",
        protoc_bin_vendored::protoc_bin_path().expect("vendored protoc"),
    );
    prost_build::compile_protos(&["proto/mexc_deals.proto"], &["proto/"])
        .expect("compile mexc_deals.proto");
    println!("cargo:rerun-if-changed=proto/mexc_deals.proto");
}
