#!/usr/bin/env bash
set -e

cp xconfigure.sh secp256k1

cd secp256k1

./autogen.sh
sh xconfigure.sh --enable-experimental --enable-module_ecdh --enable-module-recovery --enable-module-schnorrsig --enable-benchmark=no --enable-shared=no --enable-exhaustive-tests=no --enable-tests=no

mkdir -p ../build/ios
cp -v _build/universal/libsecp256k1.xcframework/ios-arm64_arm64e/libsecp256k1.a ../build/ios/

rm -rf _build
make clean
