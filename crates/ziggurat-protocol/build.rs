use std::process::Command;

fn git(args: &[&str]) -> String {
    let output = Command::new("git").args(args).output().unwrap();
    assert!(output.status.success(), "git {args:?} failed");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

#[allow(clippy::option_if_let_else)]
fn main() {
    // Builds without a .git directory (Docker contexts) pass the version in.
    println!("cargo:rerun-if-env-changed=ZIGGURAT_GIT_VERSION");

    let version = match std::env::var("ZIGGURAT_GIT_VERSION") {
        Ok(version) => version,
        Err(_) => {
            // HEAD and logs/HEAD move on checkout and commit; the index changes on staging.
            // An edit that is not staged does not re-run this script.
            for path in ["HEAD", "logs/HEAD", "index"] {
                println!(
                    "cargo:rerun-if-changed={}",
                    git(&["rev-parse", "--path-format=absolute", "--git-path", path])
                );
            }
            git(&["describe", "--always", "--dirty"])
        }
    };

    println!("cargo:rustc-env=ZIGGURAT_GIT_VERSION={version}");
}
