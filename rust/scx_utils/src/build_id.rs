// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::fmt::Write;

lazy_static::lazy_static! {
    static ref GIT_VERSION: String = {
        let mut ver = String::new();
        match option_env!("VERGEN_GIT_SHA") {
            Some(v) if v != "VERGEN_IDEMPOTENT_OUTPUT" => {
                ver += "g";
                ver += v;
                if let Some("true") = option_env!("VERGEN_GIT_DIRTY") {
                    ver += "-dirty";
                }
            }
            _ => {}
        }
        ver
    };
    static ref BUILD_TAG: String = {
        let mut tag = env!("VERGEN_CARGO_TARGET_TRIPLE").to_string();
        if cfg!(debug_assertions) {
            write!(tag, "/debug").unwrap();
        }
        tag
    };
}

fn full_version(semver: &str) -> String {
    let mut ver = semver.to_string();
    if GIT_VERSION.len() > 0 {
        write!(ver, "-{}", &*GIT_VERSION).unwrap();
    }
    if BUILD_TAG.len() > 0 {
        write!(ver, " {}", &*BUILD_TAG).unwrap();
    }
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
        println!("{}", super::*SCX_CARGO_VERSION);
    }

    #[test]
    fn test_full_ver() {
        //assert_eq!(super::*SCX_CARGO_VERSION, 1);
        println!("{}", super::*SCX_FULL_VERSION);
    }
}
