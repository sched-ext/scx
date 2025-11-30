{ lib
, stdenv
, fetchgit
, virtme-ng
, linuxManualConfig
, linuxPackages_latest
, name
, repo
, branch
, commitHash
, narHash
, version
, patches ? [ ]
}:

let
  src = fetchgit {
    url = repo;
    rev = commitHash;
    branchName = branch;

    hash = narHash;
  };

  configfile = stdenv.mkDerivation {
    inherit src patches;
    name = name + "-configfile";

    buildInputs = linuxPackages_latest.kernel.buildInputs;
    nativeBuildInputs = linuxPackages_latest.kernel.nativeBuildInputs;

    buildPhase = ''
      ${virtme-ng}/bin/virtme-ng -v --kconfig --config ${../../kernel.config}
    '';
    installPhase = ''
      mv .config $out
    '';
  };

  headers = stdenv.mkDerivation {
    name = "linux-headers-${version}";
    inherit src version patches;

    buildInputs = linuxPackages_latest.kernel.buildInputs;
    nativeBuildInputs = linuxPackages_latest.kernel.nativeBuildInputs;

    buildPhase = ''
      cp ${configfile} .config
      make headers
    '';
    installPhase = ''
      mkdir -p $out
      find . -type f \
        \( -path 'usr/include/*' -o -name '*.h' \) \
        -exec cp --parents '{}' $out \;
    '';
  };
in
(linuxManualConfig {
  inherit src version configfile;
  kernelPatches = map
    (patch: {
      inherit patch;
      name = builtins.baseNameOf patch;
    })
    patches;
}).overrideAttrs {
  passthru = {
    inherit headers;
  };
}
