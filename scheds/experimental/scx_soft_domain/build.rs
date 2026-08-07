use std::process::Command;

fn main() {
    let commit_id = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|hash| format!(" (git commit id: {})", hash.trim()))
        .unwrap_or_else(|| "".to_string());

    println!("cargo:rustc-env=GIT_COMMIT_ID={}", commit_id);
    println!("cargo:rerun-if-changed=.git/HEAD");

    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .compile_link_gen()
        .unwrap();
}
