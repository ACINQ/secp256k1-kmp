#!/usr/bin/env bash
set -e

[[ -z "$CMAKE_DEFAULT_OPTS" ]] && echo "Please set the CMAKE_DEFAULT_OPTS variable" && exit 1

rm -rf buid_ios build_iosSimulator
cd secp256k1
cmake -B ../build_ios -G Xcode -DCMAKE_INSTALL_PREFIX=../build_ios -DCMAKE_TOOLCHAIN_FILE=../ios.toolchain.cmake -DPLATFORM=OS64COMBINED ${CMAKE_DEFAULT_OPTS}
cmake --build ../build_ios --config Release
cmake --install ../build_ios --config Release
cmake -B ../build_iosSimulator -G Xcode -DCMAKE_INSTALL_PREFIX=../build_iosSimulator -DCMAKE_TOOLCHAIN_FILE=../ios.toolchain.cmake -DPLATFORM=SIMULATOR64COMBINED ${CMAKE_DEFAULT_OPTS}
cmake --build ../build_iosSimulator --config Release
cmake --install ../build_iosSimulator --config Release
cd ..

mkdir -p build/ios
cp -v build_ios/lib/libsecp256k1.a build/ios
mkdir -p build/iosSimulator
cp -v build_iosSimulator/lib/libsecp256k1.a build/iosSimulator
