use std::env;
use std::process::Command;

fn main() {
    let output = Command::new("git")
        .args(&["rev-parse", "HEAD"])
        .output()
        .unwrap();
    let git_hash = String::from_utf8(output.stdout).unwrap();
    let version = env::var("CARGO_PKG_VERSION").unwrap();
    println!("cargo:rustc-env=FULL_VERSION={}-{}", version, git_hash);
}
