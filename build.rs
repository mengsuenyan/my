use chrono::{DateTime, Local};
use std::{process::Command, time::SystemTime};

fn exe_cmd(cmd: &mut Command) -> anyhow::Result<String> {
    let output = cmd.output()?;

    Ok(if output.status.success() {
        String::from_utf8(output.stdout)?
    } else {
        String::from_utf8(output.stderr)?
    })
}

fn main() {
    let is_ingore_cmd = std::env::var("IGNORE_CMD_ERR").is_ok();

    let git_commit_hash = match exe_cmd(Command::new("git").args([
        "log",
        "-n",
        "1",
        "--pretty=format:%H",
    ])) {
        Ok(s) => s[..8.min(s.len())].trim().to_string(),
        Err(e) => {
            if !is_ingore_cmd {
                panic!("git log run failed: {e}\nYou can use the environment variable `IGNORE_CMD_ERR` to disable this panic");
            }
            String::default()
        }
    };

    let git_branch = match exe_cmd(Command::new("git").args(["branch", "--show-current"])) {
        Ok(s) => s.trim().to_string(),
        Err(e) => {
            if !is_ingore_cmd {
                panic!("git branch run failed: {e}\nYou can use the environment variable `IGNORE_CMD_ERR` to disable this panic");
            }
            String::default()
        }
    };

    println!(
        "cargo:rustc-env=MY_VERSION_INFO={}-{}",
        env!("CARGO_PKG_VERSION"),
        DateTime::<Local>::from(SystemTime::now()).format("%Y/%m/%d-%H:%M:%S:%Z")
    );

    println!(
        "cargo:rustc-env=MY_GIT_INFO={}-{}",
        git_branch, git_commit_hash
    );
}
