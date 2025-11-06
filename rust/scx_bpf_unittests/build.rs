// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use indoc::formatdoc;

use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let out_dir: PathBuf = env::var("OUT_DIR").unwrap().into();
    let manifest_dir: PathBuf = env::var("CARGO_MANIFEST_DIR").unwrap().into();
    let root_dir = manifest_dir.join("../..");

    let include_path = &[
        root_dir.join("lib/scxtest/"),
        root_dir.join("scheds/include/"),
        root_dir.join("scheds/include/lib"),
        root_dir.join("scheds/vmlinux/"),
        root_dir.join("scheds/vmlinux/arch/x86/"),
        root_dir.join("scheds/include/bpf-compat/"),
        env::var("DEP_BPF_INCLUDE")
            .expect("libbpf-sys include must be avaiable")
            .into(),
    ];

    // Build the support library
    cc::Build::new()
        .compiler(env::var("BPF_CLANG").unwrap_or_else(|_| "clang".into()))
        .files(&[
            root_dir.join("lib/scxtest/scx_test.c"),
            root_dir.join("lib/scxtest/overrides.c"),
            root_dir.join("lib/scxtest/scx_test_map.c"),
            root_dir.join("lib/scxtest/scx_test_cpumask.c"),
        ])
        .define("SCX_BPF_UNITTEST", None)
        .includes(include_path)
        .compile("scxtest");

    // Extract test names
    let tests: Vec<String> = vec![];

    // Generate Rust wrappers for the tests
    let mut test_content = fs::File::create(out_dir.join("gen_tests.rs")).unwrap();
    for name in &tests {
        test_content
            .write_all(
                formatdoc! {r#"
                    extern "C" {{ fn {name}() -> i32; }}
                    #[test]
                    fn p2dq_{name}() -> ::std::result::Result<(), i32> {{
                        let ret = unsafe {{ {name}() }};

                        (ret == 0)
                            .then(|| ())
                            .ok_or(ret)
                    }}
        "#, name = name}
                .as_bytes(),
            )
            .unwrap();
    }

    // Rebuild directives
    println!("cargo:rerun-if-changed=../../lib/scxtest");
}
