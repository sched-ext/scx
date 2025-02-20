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

in
linuxManualConfig {
  inherit src version configfile;
}
