#!/bin/bash
# Builds the upstream C++ library in cpp/ (no CMake needed) plus the C++ side of the interop test.
# usage: interop/build_cpp.sh [out dir]   (default: interop/bin/cpp)
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
C=$(cd "$HERE/../cpp" && pwd)
O=${1:-$HERE/bin/cpp}
mkdir -p "$O"; cd "$O"
INC="-I$C -I$C/include -I$C/serialize -I$C/netcode -I$C/reliable -I$C/sodium -I$C/tlsf -I$C/source"
FL="-O2 -ffp-contract=off -DNDEBUG"
cc $FL $INC -c "$C/sodium/sodium.c" -o sodium.o
cc $FL $INC -c "$C/netcode/netcode.c" -o netcode.o
cc $FL $INC -c "$C/reliable/reliable.c" -o reliable.o
cc $FL $INC -c "$C/tlsf/tlsf.c" -o tlsf.o
for f in "$C"/source/*.cpp; do c++ -std=c++11 $FL $INC -c "$f" -o "$(basename "$f" .cpp).o"; done
rm -f libyojimbo.a; ar rcs libyojimbo.a *.o
c++ -std=c++11 $FL $INC "$HERE/interop.cpp" libyojimbo.a -o interop
echo "$O/interop"
