#!/usr/bin/env bash
set -e

[[ -z "$ANDROID_NDK" ]] && echo "Please set the ANDROID_NDK variable" && exit 1
[[ -z "$ARCH" ]] && echo "Please set the ARCH variable" && exit 1
[[ -z "$TOOLCHAIN" ]] && echo "Please set the TOOLCHAIN variable" && exit 1

if [ "$ARCH" == "x86_64" ]; then
  SYS=x86_64
elif [ "$ARCH" == "x86" ]; then
  SYS=i686
elif [ "$ARCH" == "arm64-v8a" ]; then
  SYS=aarch64
elif [ "$ARCH" == "armeabi-v7a" ]; then
  SYS=armv7a
else
  echo "Unsupported ARCH: $ARCH"
  exit 1
fi

TARGET=$SYS-linux-android
if [ "$SYS" == "armv7a" ]; then
  TARGET=armv7a-linux-androideabi
fi

export CC=$ANDROID_NDK/toolchains/llvm/prebuilt/$TOOLCHAIN/bin/${TARGET}21-clang
export LD=$ANDROID_NDK/toolchains/llvm/prebuilt/$TOOLCHAIN/bin/ld
export AR=$ANDROID_NDK/toolchains/llvm/prebuilt/$TOOLCHAIN/bin/llvm-ar
export AS=$CC
export RANLIB=$ANDROID_NDK/toolchains/llvm/prebuilt/$TOOLCHAIN/bin/llvm-ranlib
export STRIP=$ANDROID_NDK/toolchains/llvm/prebuilt/$TOOLCHAIN/bin/llvm-strip

cd secp256k1

./autogen.sh
./configure CFLAGS=-fpic --host=$TARGET --enable-experimental --enable-module_ecdh --enable-module-recovery --enable-module-schnorrsig --enable-benchmark=no --enable-shared=no --enable-exhaustive-tests=no --enable-tests=no
make clean
make

cd ..

mkdir -p build/android-$ARCH
cp -v secp256k1/.libs/libsecp256k1.a build/android-$ARCH
