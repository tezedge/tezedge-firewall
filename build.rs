use std::{env, fs};
use std::path::{Path, PathBuf};

use cargo_bpf_lib as cargo_bpf;

fn main() {
    if env::var("SKIP_BUILD_MODULE").is_ok() {
        return;
    }

    let cargo = PathBuf::from(env::var("CARGO").unwrap());
    let target = PathBuf::from(env::var("OUT_DIR").unwrap());
    let module = Path::new("xdp-module");

    cargo_bpf::build(&cargo, &module, &target.join("target"), Vec::new())
        .expect("couldn't compile module");

    fs::copy(target.join("target/bpf/programs/xdp_module/xdp_module.elf"), "./xdp_module.elf")
        .unwrap();

    cargo_bpf::probe_files(&module)
        .expect("couldn't list module files")
        .iter()
        .for_each(|file| {
            println!("cargo:rerun-if-changed={}", file);
        });
}
