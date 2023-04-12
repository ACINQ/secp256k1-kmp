#!/usr/bin/env bash
set -e

[[ -z "$TARGET" ]] && echo "Please set the TARGET variable" && exit 1

if [ "$(id -u)" == "0" ]; then
  [[ -z "$TO_UID" ]] && echo "Please set the TO_UID variable" && exit 1
fi

cd "$(dirname "$0")"

cd secp256k1

if [ "$TARGET" == "mingw" ]; then
  CONF_OPTS="CFLAGS=-fPIC --host=x86_64-w64-mingw32"
elif [ "$TARGET" == "linux" ]; then
  CONF_OPTS="CFLAGS=-fPIC"
elif [ "$TARGET" == "darwin" ]; then
  CONF_OPTS=""
else
  echo "Unknown TARGET=$TARGET"
  exit 1
fi

./autogen.sh
./configure $CONF_OPTS --enable-experimental --enable-module_ecdh --enable-module-recovery --enable-module-schnorrsig --enable-benchmark=no --enable-shared=no --enable-exhaustive-tests=no --enable-tests=no
make clean
make

[[ ! -z "$TO_UID" ]] && chown -R $TO_UID:$TO_UID .

cd ..

mkdir -p build/$TARGET
cp -v secp256k1/.libs/libsecp256k1.a build/$TARGET/

[[ ! -z "$TO_UID" ]] && chown -R $TO_UID:$TO_UID build

echo "Build done for $TARGET"
