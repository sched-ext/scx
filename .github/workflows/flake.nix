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
        in
        {
          devShells = let common = with pkgs; [ gnutar zstd ]; in {
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

                installPhase = "install -Dm755 ${./update-kernels.py} $out/bin/update-kernels";
              };
            in
            {
              type = "app";
              program = "${script}/bin/update-kernels";
            };
        };
      });
}

