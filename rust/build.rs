//! Compile the vendored SQLite amalgamation with the system C compiler.
//!
//! We deliberately avoid the `cc` crate (and all crates.io build deps): this
//! just shells out to `$CC`/cc and `ar`, both already required to build the
//! project. The SQLite source is the official single-file amalgamation from
//! sqlite.org, vendored under vendor/sqlite and reviewable in-tree.

use std::path::Path;
use std::process::Command;

fn main() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let src = format!("{manifest}/vendor/sqlite/sqlite3.c");
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let obj = format!("{out_dir}/sqlite3.o");
    let lib = format!("{out_dir}/libsqlite3.a");

    println!("cargo:rerun-if-changed={src}");
    println!("cargo:rerun-if-changed=build.rs");

    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());

    // Lean, server-appropriate build options.
    let defines = [
        "-DSQLITE_THREADSAFE=1",
        "-DSQLITE_DEFAULT_WAL_SYNCHRONOUS=1",
        "-DSQLITE_OMIT_LOAD_EXTENSION",
        "-DSQLITE_DQS=0",
        "-DSQLITE_DEFAULT_FOREIGN_KEYS=0",
        "-DSQLITE_ENABLE_COLUMN_METADATA",
    ];

    let mut compile = Command::new(&cc);
    compile
        .args(["-O2", "-fPIC", "-c", &src, "-o", &obj])
        .args(defines);
    run(&mut compile, "compile sqlite3.c");

    if Path::new(&lib).exists() {
        let _ = std::fs::remove_file(&lib);
    }
    let mut archive = Command::new("ar");
    archive.args(["rcs", &lib, &obj]);
    run(&mut archive, "archive libsqlite3.a");

    println!("cargo:rustc-link-search=native={out_dir}");
    println!("cargo:rustc-link-lib=static=sqlite3");
    // SQLite needs these system libraries at link time.
    println!("cargo:rustc-link-lib=dylib=pthread");
    println!("cargo:rustc-link-lib=dylib=dl");
    println!("cargo:rustc-link-lib=dylib=m");
}

fn run(cmd: &mut Command, what: &str) {
    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("failed to {what}: {e}"));
    if !status.success() {
        panic!("failed to {what}: exit {status}");
    }
}
