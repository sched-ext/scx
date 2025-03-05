{
  description = "Nix flake for the scx CI environment.";

  inputs = {
    nixpkgs.url = "github:JakeHillion/nixpkgs/virtme-ng";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ]
      (system: {
        devShells =
          let
            pkgs = import nixpkgs { inherit system; };
            common = with pkgs; [ git gnutar zstd ];
          in
          {
            build-kernel = pkgs.mkShell {
              buildInputs = with pkgs; common ++ [
                bc
                bison
                cpio
                elfutils
                flex
                git
                openssl
                pahole
                perl
                virtme-ng
                zlib
              ];
            };

            rust-tests = pkgs.mkShellNoCC {
              buildInputs = with pkgs; common ++ [
                cargo
                clang
                clippy
                elfutils
                jq
                llvmPackages.libclang
                llvmPackages.libllvm
                pkg-config
                rustfmt
                virtme-ng
                zlib
              ];

              LIBCLANG_PATH = "${pkgs.lib.getLib pkgs.llvmPackages.libclang}/lib";

              hardeningDisable = [
                "stackprotector"
                "zerocallusedregs"
              ];
            };
          };
      }) // flake-utils.lib.eachDefaultSystem (system: {
      formatter = nixpkgs.legacyPackages.${system}.nixpkgs-fmt;
    });
}

