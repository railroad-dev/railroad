use std::process::Command;

fn main() {
    // Embed the current git commit hash at compile time
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok();

    let hash = output
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=RAILYARD_GIT_HASH={}", hash);
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads/main");
}
