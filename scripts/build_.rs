#!/usr/bin/env run-cargo-script

use std::{process::{Command, Stdio}, env, fs};

fn main() {
    let kernel_version = std::env::args().nth(1).unwrap();

    let expect = "output of (uname -r) expected";
    let mut i = kernel_version.split('-');
    let mut i = i.next().expect(expect).split('.');
    let major = i.next().expect(expect).parse::<u8>().expect(expect);
    let minor = i.next().expect(expect).parse::<u8>().expect(expect);
    let patch = i.next().unwrap_or("0").parse::<u8>().expect(expect);
    let version = format!("{}.{}.{}", major, minor, patch);

    Command::new("wget")
        .args(&["wget", "-cq"])
        .arg(format!("https://cdn.kernel.org/pub/linux/kernel/v{}.x/linux-{}.tar.xz", major, version))
        .output()
        .unwrap();
    Command::new("tar")
        .arg("-xf")
        .arg(format!("linux-{}.tar.xz", version))
        .output()
        .unwrap();
    Command::new("make")
        .current_dir(format!("linux-{}", version))
        .arg("defconfig")
        .output()
        .unwrap();
    Command::new("make")
        .current_dir(format!("linux-{}", version))
        .arg("modules_prepare")
        .output()
        .unwrap();

    Command::new("cargo")
        .env("KERNEL_SOURCE", format!("{}/linux-{}", env::var("PWD").unwrap(), version))
        .env_remove("KERNEL_VERSION")
        .args(&["build", "-p", "tezedge-firewall", "--release"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap()
        .wait()
        .unwrap();

    Command::new("cargo")
        .env("KERNEL_SOURCE", format!("{}/linux-{}", env::var("PWD").unwrap(), version))
        .env_remove("KERNEL_VERSION")
        .args(&["build", "-p", "tezedge-firewall", "--bin", "fw", "--release"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap()
        .wait()
        .unwrap();

    fs::remove_dir_all(format!("linux-{}", version)).unwrap();
    fs::remove_file(format!("linux-{}.tar.xz", version)).unwrap();
    fs::create_dir_all("bin").unwrap();
    fs::rename("target/release/tezedge-firewall", format!("./bin/firewall-{}", kernel_version)).unwrap();
    fs::rename("target/release/fw", "./bin/fw").unwrap();
}
