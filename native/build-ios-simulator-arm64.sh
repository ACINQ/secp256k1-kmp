#!/usr/bin/env bash
set -e

cp xconfigure.sh secp256k1

cd secp256k1

./autogen.sh
sh xconfigure.sh --enable-experimental --enable-module_ecdh --enable-module-recovery --enable-module-schnorrsig --enable-benchmark=no --enable-shared=no --enable-exhaustive-tests=no --enable-tests=no

mkdir -p ../build/iosSimulatorArm64
cp -v _build/universal/libsecp256k1.xcframework/ios-arm64-simulator/libsecp256k1.a ../build/iosSimulatorArm64/

rm -rf _build
make clean
