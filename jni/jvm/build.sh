#!/usr/bin/env bash
set -e

[[ -z "$TARGET" ]] && echo "Please set the TARGET variable" && exit 1

cd "$(dirname "$0")"

CC=gcc
JNI_HEADERS=$TARGET

case $TARGET in
  "mingw")
    OUTFILE=secp256k1-jni.dll
    CC=x86_64-w64-mingw32-gcc
    ;;
  "linux")
    OUTFILE=libsecp256k1-jni.so
    CC_OPTS="-fPIC"
    ;;
  "linuxArm64")
    CC=aarch64-linux-gnu-gcc
    OUTFILE=libsecp256k1-jni.so
    JNI_HEADERS=linux
    CC_OPTS="-fPIC"
    ;;
  "darwin")
    OUTFILE=libsecp256k1-jni.dylib
    CC_OPTS="-arch arm64 -arch x86_64"
    ;;
  *)
    echo "Unknown TARGET=$TARGET"
    exit 1
    ;;
esac

mkdir -p build/jni/$TARGET

$CC -shared $CC_OPTS -o build/$TARGET/$OUTFILE ../c/src/fr_acinq_secp256k1_Secp256k1CFunctions.c -I../c/headers/ -I../c/headers/java -I../c/headers/$JNI_HEADERS/ -I../../native/secp256k1/ -lsecp256k1 -L../../native/build/$TARGET/ $ADD_LIB

echo "Build done for $TARGET"
