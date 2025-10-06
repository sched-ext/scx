{ lib
, stdenv
, fetchFromGitHub
, llvmPackages
, clang
, libbpf
, elfutils
, zlib
, pkg-config
, version
, src
}:

stdenv.mkDerivation {
  pname = "veristat";
  inherit version src;

  buildInputs = [
    elfutils
    zlib
  ];

  buildPhase = ''
    # The Makefile expects to build libbpf from source. We already have a built
    # version, and this is a single C file with minimal dependencies, so compile
    # and link it by hand.

    cd src
    $CC $CFLAGS -I${libbpf}/include -DVERISTAT_VERSION='"${version}"' \
        -c veristat.c -o veristat.o
    $CC veristat.o ${libbpf}/lib/libbpf.a -lelf -lz -o veristat
  '';

  installPhase = ''
    mkdir -p $out/bin
    install -m755 veristat $out/bin/
  '';

  meta = with lib; {
    description = "Tool to provide statistics from the BPF verifier for BPF programs";
    homepage = "https://github.com/libbpf/veristat";
    license = licenses.bsd2;
    platforms = platforms.linux;
  };
}
