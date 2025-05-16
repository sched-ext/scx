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
}:

let
  src = fetchgit {
    url = repo;
    rev = commitHash;
    branchName = branch;

    hash = narHash;
  };

  configfile = stdenv.mkDerivation {
    inherit src;
    name = name + "-configfile";

    buildInputs = linuxPackages_latest.kernel.buildInputs;
    nativeBuildInputs = linuxPackages_latest.kernel.nativeBuildInputs;

    buildPhase = ''
      ${virtme-ng}/bin/virtme-ng -v --kconfig --config ${./sched-ext.config}
    '';
    installPhase = ''
      mv .config $out
    '';
  };

  headers = stdenv.mkDerivation {
    name = "linux-headers-${version}";
    inherit src version;

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
}).overrideAttrs {
  passthru = {
    inherit headers;
  };
}
