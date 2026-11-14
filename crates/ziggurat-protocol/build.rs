use std::process::Command;

use chrono::{DateTime, Utc};

fn git(args: &[&str]) -> Option<String> {
    // Git must not rewrite the index we watch, or every build would rerun this script
    let output = Command::new("git")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8(output.stdout).unwrap().trim().to_owned())
}

#[allow(clippy::option_if_let_else)]
fn main() {
    println!("cargo:rerun-if-env-changed=ZIGGURAT_GIT_VERSION");

    let describe = std::env::var("ZIGGURAT_GIT_VERSION").ok().or_else(|| {
        for path in ["HEAD", "logs/HEAD", "index"] {
            let path = git(&["rev-parse", "--path-format=absolute", "--git-path", path])?;
            println!("cargo:rerun-if-changed={path}");
        }

        // An unstaged edit to a tracked file makes the tree dirty but changes none of
        // the Git files above
        let root = git(&["rev-parse", "--show-toplevel"])?;
        for file in git(&["-C", &root, "ls-files", "-z"])?.split_terminator('\0') {
            println!("cargo:rerun-if-changed={root}/{file}");
        }

        // Not `describe --dirty`: it rewrites the index even with optional locks off
        let describe = git(&["describe", "--always"])?;
        let status = git(&["status", "--porcelain", "--untracked-files=no"])?;
        Some(if status.is_empty() {
            describe
        } else {
            format!("{describe}-dirty")
        })
    });

    let package = std::env::var("CARGO_PKG_VERSION").unwrap();
    let version = match &describe {
        Some(describe) => format!("{package}+{describe}"),
        None => package,
    };
    println!("cargo:rustc-env=ZIGGURAT_VERSION={version}");

    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    let epoch = std::env::var("SOURCE_DATE_EPOCH").ok().or_else(|| {
        if describe?.ends_with("-dirty") {
            return None;
        }
        git(&["log", "-1", "--format=%ct"])
    });
    let datetime = match epoch {
        Some(epoch) => DateTime::from_timestamp(epoch.parse().unwrap(), 0).unwrap(),
        None => Utc::now(),
    };
    println!(
        "cargo:rustc-env=ZIGGURAT_BUILD_DATETIME={}",
        datetime.format("%b %e %Y %H:%M:%S")
    );
}
