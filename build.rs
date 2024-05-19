
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=script.sh");

    let output = Command::new("sh")
        .arg("./ebpf/enable.sh")
        .output()
        .expect("Failed to execute script");

    if !output.status.success() {
        panic!("Script execution failed with: {:?}", output);
    }

    println!("Script executed successfully!");
}

