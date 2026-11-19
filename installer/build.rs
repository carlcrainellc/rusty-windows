use embed_manifest::{embed_manifest, manifest::ExecutionLevel, new_manifest};

fn main() {
    // Ask for admin rights up front (UAC), since installing a service needs them.
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        embed_manifest(
            new_manifest("Rusty.Setup")
                .requested_execution_level(ExecutionLevel::RequireAdministrator),
        )
        .expect("manifest");
    }
    let dir = std::env::var("PACKAGE_DIR").expect("set PACKAGE_DIR to the folder with the files to package");
    println!("cargo:rustc-env=PACKAGE_DIR={dir}");
    // Shown on the first line so people can tell which build they ran.
    let release = std::env::var("RUSTY_VERSION").unwrap_or_else(|_| "(dev build)".into());
    println!("cargo:rustc-env=RUSTY_VERSION={release}");
    println!("cargo:rerun-if-env-changed=RUSTY_VERSION");
    println!("cargo:rerun-if-env-changed=PACKAGE_DIR");
    println!("cargo:rerun-if-changed={dir}");
}
