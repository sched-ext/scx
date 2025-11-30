{ lib
, pkgs
, crane
, rust-toolchain
, bpf-clang
, pkg-config
, clang
, libclang
, elfutils
, libbpf-git
, libseccomp
, protobuf
, zlib
, zstd
}:

let
  craneLib = (crane.mkLib pkgs).overrideToolchain rust-toolchain;

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      (craneLib.fileset.commonCargoSources ../.)
      (lib.fileset.fileFilter (file: file.hasExt "h") ../.)
      (lib.fileset.fileFilter (file: file.hasExt "c") ../.)
      (lib.fileset.fileFilter (file: file.hasExt "zst") ../.)
      (lib.fileset.fileFilter (file: file.type == "symlink") ../.)
    ];
  };

  # Common crane arguments
  commonArgs = {
    inherit src;
    strictDeps = true;

    nativeBuildInputs = [
      pkg-config
      clang
      libclang
    ];

    buildInputs = [
      elfutils
      libbpf-git
      libseccomp
      protobuf
      zlib
      zstd
    ];

    env = {
      BPF_CLANG = lib.getExe bpf-clang;
      LIBCLANG_PATH = "${lib.getLib libclang}/lib";
      RUSTFLAGS = "-C relocation-model=pic -C link-args=-lelf -C link-args=-lz -C link-args=-lzstd -C link-args=-Wl,-rpath,${lib.makeLibraryPath [
          elfutils
          zlib
        ]}";
    };
  };

  cargoArtifacts = craneLib.buildDepsOnly (commonArgs // {
    pname = "scx-workspace";
    version = "git";
  });

  individualCrateArgs = commonArgs // {
    inherit cargoArtifacts;
    doCheck = false;
  };
in
{
  makeCargoSchedulerPackage = name:
    craneLib.buildPackage (individualCrateArgs // {
      pname = name;
      version = "git";
      cargoExtraArgs = "-p ${name}";

      meta = with lib; {
        description = "sched_ext scheduler: ${name}";
        homepage = "https://github.com/sched-ext/scx";
        license = licenses.gpl2Only;
        maintainers = [ ];
        platforms = platforms.linux;
      };
    });
}
