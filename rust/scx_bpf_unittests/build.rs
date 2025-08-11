// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use indoc::formatdoc;
use object::read::archive::ArchiveFile;
use object::Object;
use object::ObjectSection;
use object::ObjectSymbol;

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
        root_dir.join("scheds/include/arch/x86/"),
        root_dir.join("scheds/include/bpf-compat/"),
        env::var("DEP_BPF_INCLUDE").unwrap().into(),
    ];

    // Build the C tests
    cc::Build::new()
        .compiler(env::var("BPF_CLANG").unwrap_or_else(|_| "clang".into()))
        .files(&[root_dir.join("scheds/rust/scx_p2dq/src/bpf/main.test.bpf.c")])
        .warnings(false)
        .define("SCX_BPF_UNITTEST", None)
        .flags(&[
            "-Wno-attributes",
            "-Wno-unknown-pragmas",
            "-Wno-incompatible-pointer-types",
            "-Wno-unused-variable",
        ])
        .includes(include_path)
        .compile("p2dq_tests");

    // Build the support library - this has to come after p2dq_tests, and is a good reason to
    // separate the crates.
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
    let mut tests = vec![];

    let archive_data = fs::read(&out_dir.join("libp2dq_tests.a")).unwrap();
    let archive = ArchiveFile::parse(&*archive_data).unwrap();
    for member in archive.members() {
        let member = member.unwrap();

        let obj_data = member.data(&*archive_data).unwrap();
        let obj = object::File::parse(obj_data).unwrap();

        let test_section_index = if let Some(s) = obj.section_by_name(".scxtest") {
            s.index()
        } else {
            continue;
        };

        for symbol in obj.symbols() {
            if let Some(i) = symbol.section_index() {
                if i != test_section_index {
                    continue;
                }

                let name = if let Ok(n) = symbol.name() {
                    n.to_string()
                } else {
                    continue;
                };

                // unclear where the empty name comes from, filter it out
                if symbol.is_definition() {
                    tests.push(name);
                }
            }
        }
    }

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
    println!("cargo:rerun-if-changed=../../scheds/rust/scx_p2dq/src/bpf");
}
