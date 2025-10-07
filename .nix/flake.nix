{
  description = "Nix flake for the scx CI environment.";

  nixConfig = {
    extra-substituters = [ "https://sched-ext.cachix.org" ];
    extra-trusted-public-keys = [ "sched-ext.cachix.org-1:dtoM9QOUUqJs3JkmSgVoKYp9cLY0BrupOqp4DVz35/g=" ];
  };

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";

    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    nix-develop-gha.url = "github:nicknovitski/nix-develop";
    nix-develop-gha.inputs.nixpkgs.follows = "nixpkgs";

    libbpf-src = {
      url = "github:libbpf/libbpf";
      flake = false;
    };

    veristat-src = {
      url = "github:libbpf/veristat";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, fenix, nix-develop-gha, libbpf-src, veristat-src, ... }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ]
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [
              (final: prev: {
                libbpf-git = prev.libbpf.overrideAttrs (oldAttrs: {
                  src = libbpf-src;
                  version = "git";
                });
                virtme-ng = prev.callPackage ./pkgs/virtme-ng.nix { };
              })
            ];
          };
          lib = pkgs.lib;

          rust-toolchain = fenix.packages.${system}.stable.withComponents [
            "cargo"
            "clippy"
            "rust-src"
            "rustc"
            "rustfmt"
          ];

          makeBpfClang = llvmPackages: kernel: pkgs.stdenv.mkDerivation {
            pname = "bpf-clang";
            version = llvmPackages.clang.version;
            meta.mainProgram = "clang";

            dontUnpack = true;
            dontConfigure = true;
            dontBuild = true;

            nativeBuildInputs = [ pkgs.makeWrapper ];

            installPhase = ''
              mkdir -p $out/bin
              makeWrapper ${pkgs.llvmPackages.clang-unwrapped}/bin/clang \
                $out/bin/clang \
                --add-flags "-I${llvmPackages.clang-unwrapped.lib}/lib/clang/${lib.versions.major llvmPackages.clang-unwrapped.version}/include" \
                --add-flags "-I${kernel.headers}/usr/include" \
                --add-flags "-I${pkgs.glibc.dev}/include" \
                --prefix PATH : ${llvmPackages.clang-unwrapped}/bin
            '';
          };

          build-env-vars = {
            BPF_CLANG = lib.getExe self.packages.${system}.bpf-clang;
            LIBCLANG_PATH = "${lib.getLib pkgs.llvmPackages.libclang}/lib";
          };

          gha-common-pkgs = with pkgs; [
            cachix
            git
            gnutar
            zstd
          ];
        in
        {
          devShells = {
            default = pkgs.mkShell ({
              buildInputs = with pkgs; [
                bash
                binutils
                bpftools
                clang
                coreutils
                elfutils
                gcc
                git
                glibc
                gnumake
                jq
                libbpf-git
                libseccomp
                pkg-config
                protobuf
                zlib
                zstd

                llvmPackages.libclang
                llvmPackages.libllvm

                # fenix managed rust toolchain
                rust-toolchain
              ];
            } // build-env-vars);

            gha-common = pkgs.mkShellNoCC {
              buildInputs = gha-common-pkgs;
            };

            gha-build-kernels = pkgs.mkShellNoCC {
              buildInputs = with pkgs; gha-common-pkgs ++ [
                gawk
                jq
              ];
            };

            gha-update-kernels = pkgs.mkShellNoCC {
              buildInputs = with pkgs; gha-common-pkgs ++ [
                gh
                jq
              ];
            };
          };

          packages = {
            nix-develop-gha = nix-develop-gha.packages.${system}.default;
            bpf-clang = makeBpfClang pkgs.llvmPackages self.packages.${system}."kernel_sched_ext/for-next";

            veristat = pkgs.callPackage ./pkgs/veristat.nix {
              version = "git";
              src = veristat-src;
              libbpf = pkgs.libbpf-git;
            };

            list-integration-tests = pkgs.python3Packages.buildPythonApplication rec {
              pname = "list-integration-tests";
              version = "git";

              pyproject = false;
              dontUnpack = true;

              propagatedBuildInputs = [
                rust-toolchain # requires cargo, use the toolchain to match version exactly
              ];

              installPhase = "install -Dm755 ${../.github/include/list-integration-tests.py} $out/bin/list-integration-tests";
            };

            ci = pkgs.python3Packages.buildPythonApplication rec {
              pname = "ci";
              version = "git";

              pyproject = false;
              dontUnpack = true;

              propagatedBuildInputs = with pkgs; [
                bash
                binutils
                black
                bpftools
                clang
                coreutils
                diffutils
                gcc
                git
                gnugrep
                gnumake
                gnused
                gnutar
                isort
                jq
                libbpf-git
                libseccomp.lib
                llvmPackages.libclang
                llvmPackages.libllvm
                pkg-config
                protobuf
                virtme-ng

                elfutils.dev
                zlib.dev
                zstd.dev

                # fenix managed rust toolchain + nixpkgs cargo-nextest
                cargo-nextest
                rust-toolchain
              ] ++ [
                self.packages.${system}.veristat
              ];

              makeWrapperArgs = lib.lists.flatten ([
                [ "--set" "CC" "gcc" ]
                [ "--set" "LD" "ld" ]

                [ "--set" "PKG_CONFIG_PATH" "${lib.makeSearchPath "lib/pkgconfig" propagatedBuildInputs}" ]

                [ "--set" "RUSTFLAGS" "\"-C relocation-model=pic -C link-args=-lelf -C link-args=-lz -C link-args=-lzstd\"" ]

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
                    libseccomp.lib
                  ]))) + "'")
                ]
              ] ++ (lib.mapAttrsToList (key: val: "--set ${key} \"${val}\"") build-env-vars));

              installPhase = "install -Dm755 ${../.github/include/ci.py} $out/bin/ci";
            };
          } // (with lib.attrsets; mapAttrs'
            (name: details: nameValuePair "kernel_${name}" (pkgs.callPackage ./pkgs/build-kernel.nix {
              inherit name;
              inherit (details) repo branch commitHash narHash;
              version = details.kernelVersion;
              patches = map (patchName: ./kernel-patches + ("/" + patchName)) (details.patches or [ ]);
            }))
            (builtins.fromJSON (builtins.readFile ./../kernel-versions.json)));
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

                installPhase = "install -Dm755 ${../.github/include/update-kernels.py} $out/bin/update-kernels";
              };
            in
            {
              type = "app";
              program = "${script}/bin/update-kernels";
            };
        };
      });
}
