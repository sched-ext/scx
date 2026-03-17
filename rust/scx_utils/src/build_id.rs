// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::fmt::Write;

lazy_static::lazy_static! {
    static ref GIT_VERSION: String = {
        let mut ver = String::new();
        if let Some(sha) = option_env!("SCX_GIT_SHA") {
            if !sha.is_empty() {
                ver += "g";
                ver += sha;
                if option_env!("SCX_GIT_DIRTY").is_some() {
                    ver += "-dirty";
                }
            }
        }
        ver
    };
    static ref BUILD_TAG: String = {
        let mut tag = env!("SCX_TARGET_TRIPLE").to_string();
        if cfg!(debug_assertions) {
            write!(tag, "/debug").unwrap();
        }
        tag
    };
}

pub fn full_version(semver: &str) -> String {
    let mut ver = semver.to_string();
    if !GIT_VERSION.is_empty() {
        write!(ver, "-{}", &*GIT_VERSION).unwrap();
    }
    if !BUILD_TAG.is_empty() {
        write!(ver, " {}", &*BUILD_TAG).unwrap();
    }
    ver
}

pub fn ops_version_suffix(semver: &str) -> String {
    let mut ver = String::from("_");
    ver.push_str(semver);
    if !GIT_VERSION.is_empty() {
        write!(ver, "_{}", &*GIT_VERSION).unwrap();
    }
    if !BUILD_TAG.is_empty() {
        write!(ver, "_{}", &*BUILD_TAG).unwrap();
    }
    ver = ver
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    ver
}

lazy_static::lazy_static! {
    pub static ref SCX_CARGO_VERSION: &'static str = env!("CARGO_PKG_VERSION");
    pub static ref SCX_FULL_VERSION: String = full_version(*SCX_CARGO_VERSION);
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_cargo_ver() {
        //assert_eq!(super::*SCX_CARGO_VERSION, 1);
        println!("{}", *super::SCX_CARGO_VERSION);
    }

    #[test]
    fn test_full_ver() {
        //assert_eq!(super::*SCX_CARGO_VERSION, 1);
        println!("{}", *super::SCX_FULL_VERSION);
    }
}
