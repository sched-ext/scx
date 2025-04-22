{
  description = "Nix flake for the scx CI environment.";

  inputs = {
    nixpkgs.url = "github:JakeHillion/nixpkgs/virtme-ng";
    flake-utils.url = "github:numtide/flake-utils";

    nix-develop-gha.url = "github:nicknovitski/nix-develop";
    nix-develop-gha.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils, nix-develop-gha, ... }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ]
      (system:
        let
          pkgs = import nixpkgs { inherit system; };
          lib = pkgs.lib;
        in
        {
          devShells =
            let
              common = with pkgs; [ git gnutar zstd ];
            in
            {
              restore-kernels = pkgs.mkShellNoCC {
                buildInputs = with pkgs; common ++ [
                  jq
                ];
              };

              update-kernels = pkgs.mkShell {
                buildInputs = with pkgs; common ++ [
                  gh
                  git
                  jq
                ];
              };

              build-kernel = pkgs.mkShell {
                buildInputs = with pkgs; common ++ [
                  bc
                  bison
                  cpio
                  elfutils
                  flex
                  git
                  jq
                  openssl
                  pahole
                  perl
                  virtme-ng
                  zlib
                ];
              };
            };

          packages = {
            nix-develop-gha = nix-develop-gha.packages."${system}".default;

            kernels = builtins.mapAttrs
              (name: details: (pkgs.callPackage ./build-kernel.nix {
                inherit name;
                inherit (details) repo branch commitHash narHash;
                version = details.kernelVersion;
              }))
              (builtins.fromJSON (builtins.readFile ./../../kernel-versions.json));

            ci =
              pkgs.python3Packages.buildPythonApplication rec {
                pname = "ci";
                version = "git";

                pyproject = false;
                dontUnpack = true;

                propagatedBuildInputs = with pkgs; [
                  bash
                  binutils
                  black
                  cargo
                  cargo-nextest
                  clang
                  clippy
                  coreutils
                  gcc
                  git
                  gnugrep
                  gnumake
                  gnused
                  isort
                  jq
                  llvmPackages.libclang
                  llvmPackages.libllvm
                  nix
                  pkg-config
                  protobuf
                  rustc
                  rustfmt
                  virtme-ng

                  elfutils.dev
                  zlib.dev
                  zstd.dev
                ];

                makeWrapperArgs = lib.lists.flatten [
                  [ "--set" "CC" "gcc" ]
                  [ "--set" "LD" "ld" ]

                  [ "--set" "BPF_CLANG" (lib.getExe pkgs.llvmPackages.clang) ]
                  [ "--set" "LIBCLANG_PATH" "${lib.getLib pkgs.llvmPackages.libclang}/lib" ]

                  [ "--set" "PKG_CONFIG_PATH" "${lib.makeSearchPath "lib/pkgconfig" propagatedBuildInputs}" ]

                  [ "--set" "RUSTFLAGS" "'-C relocation-model=pic -C link-args=-lelf -C link-args=-lz -C link-args=-lzstd'" ]

                  [ "--set" "NIX_BINTOOLS" pkgs.binutils ]
                  [ "--set" "NIX_CC" pkgs.gcc ]

                  (
                    let system = builtins.replaceStrings [ "-" ] [ "_" ] pkgs.stdenv.hostPlatform.config; in [
                      [ "--set" "NIX_BINTOOLS_WRAPPER_TARGET_HOST_${system}" "1" ]
                      [ "--set" "NIX_CC_WRAPPER_TARGET_HOST_${system}" "1" ]
                      [ "--set" "NIX_PKG_CONFIG_WRAPPER_TARGET_HOST_${system}" "1" ]
                    ]
                  )

                  [
                    "--set"
                    "NIX_LDFLAGS"
                    ("'" + (lib.concatStringsSep " " (builtins.map (drv: "-L${drv}/lib") (with pkgs; [
                      elfutils.out
                      zlib
                      zstd.out
                    ]))) + "'")
                  ]
                ];

                installPhase = "install -Dm755 ${../include/ci.py} $out/bin/ci";
              };
          };
        }) // flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        formatter = pkgs.nixpkgs-fmt;

        apps = {
          update-kernels =
            let
              script = pkgs.python3Packages.buildPythonApplication {
                pname = "update-kernels";
                version = "git";

                pyproject = false;
                dontUnpack = true;

                dependencies = with pkgs; [
                  bash
                  coreutils
                  git
                  gnumake
                  gnused
                  nix
                ];

                installPhase = "install -Dm755 ${../include/update-kernels.py} $out/bin/update-kernels";
              };
            in
            {
              type = "app";
              program = "${script}/bin/update-kernels";
            };
        };
      });
}

