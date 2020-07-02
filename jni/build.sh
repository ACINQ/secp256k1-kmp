#!/usr/bin/env bash
set -e

[[ -z "$TARGET" ]] && echo "Please set the TARGET variable" && exit 1

if [ "$(id -u)" == "0" ]; then
  [[ -z "$TO_UID" ]] && echo "Please set the TO_UID variable" && exit 1
fi

cd "$(dirname "$0")"

CC=gcc
JNI_HEADERS=$TARGET

if [ "$TARGET" == "linux" ]; then
  OUTFILE=libsecp256k1-jni.so
  ADD_LIB=-lgmp
elif [ "$TARGET" == "darwin" ]; then
  OUTFILE=libsecp256k1-jni.dylib
  if [ -z "$CROSS_TRIPLE" ]; then
    ADD_LIB=-lgmp
  fi
elif [ "$TARGET" == "mingw" ]; then
  OUTFILE=secp256k1-jni.dll
  CC=/usr/src/mxe/usr/bin/x86_64-w64-mingw32.static-gcc
  JNI_HEADERS=linux
  CC_OPTS="-fpic"
fi

mkdir -p build/jni/$TARGET

$CC -shared $CC_OPTS -o build/jni/$TARGET/$OUTFILE c/src/fr_acinq_secp256k1_Secp256k1CFunctions.c -Ic/headers/ -Ic/headers/java -Ic/headers/$JNI_HEADERS/ -I../native/secp256k1/ -lsecp256k1 -L../native/build/$TARGET/ $ADD_LIB

[[ ! -z "$TO_UID" ]] && chown -R $TO_UID:$TO_UID .

echo "Build done for $TARGET"
