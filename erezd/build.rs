use std::{env, ffi::OsStr, path::PathBuf};

use libbpf_cargo::SkeletonBuilder;

const COMPILER: &str = "clang-19";
const HDR: &str = "src/bpf/erez.bpf.h";
const SRC: &str = "src/bpf/erez.bpf.c";

fn main() {
    #[cfg(not(target_os = "linux"))]
    compile_error!("Only Linux is supported");

    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");
    let skel_out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("bpf")
    .join("erez.skel.rs");

    #[cfg(target_os = "linux")]
    SkeletonBuilder::new()
        .clang(COMPILER)
        .source(SRC)
        .clang_args([
            OsStr::new("-Wall"),
            OsStr::new(&format!("-I/usr/include/{arch}-linux-gnu")),
        ])
        .build_and_generate(&skel_out)
        .unwrap();

    println!("cargo::rerun-if-changed={SRC}");
    println!("cargo::rerun-if-changed={HDR}");
}
