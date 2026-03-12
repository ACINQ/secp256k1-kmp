#!/usr/bin/env bash
set -ex

[[ -z "$TARGET" ]] && echo "Please set the TARGET variable" && exit 1
[[ -z "$CMAKE_DEFAULT_OPTS" ]] && echo "Please set the CMAKE_DEFAULT_OPTS variable" && exit 1

cd "$(dirname "$0")"

cd secp256k1

case $TARGET in
  "mingw")
    CMAKE_OPTS="-DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_TOOLCHAIN_FILE=cmake/x86_64-w64-mingw32.toolchain.cmake"
    ;;
  "linux")
    CMAKE_OPTS="-DCMAKE_POSITION_INDEPENDENT_CODE=ON"
    ;;
  "linuxArm64")
    CMAKE_OPTS="-DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_TOOLCHAIN_FILE=../toolchain-aarch64.cmake"
    ;;
  "darwin")
    CMAKE_OPTS=-DCMAKE_OSX_ARCHITECTURES="x86_64;arm64"
    ;;
  "ios")
    CMAKE_OPTS="-G Xcode -DCMAKE_TOOLCHAIN_FILE=../ios.toolchain.cmake -DPLATFORM=OS64COMBINED"
    ;;
  "iosSimulator")
    CMAKE_OPTS="-G Xcode -DCMAKE_TOOLCHAIN_FILE=../ios.toolchain.cmake -DPLATFORM=SIMULATOR64COMBINED"
    ;;
  *)
    echo "Unknown TARGET=$TARGET"
    exit 1
    ;;
esac

rm -rf ../build_$TARGET
cmake -B ../build_$TARGET ${CMAKE_OPTS} ${CMAKE_DEFAULT_OPTS}
cmake --build ../build_$TARGET  --config Release

cd ..

mkdir -p build/$TARGET
cp -v build_$TARGET/lib/libsecp256k1.a build/$TARGET/ ||  cp -v build_$TARGET/lib/Release/libsecp256k1.a build/$TARGET/

echo "Build done for $TARGET"
