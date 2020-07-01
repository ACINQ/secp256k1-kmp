#!/usr/bin/env bash
set -e

[[ -z "$TARGET" ]] && echo "Please set the TARGET variable" && exit 1

if [ "$(id -u)" == "0" ]; then
  [[ -z "$TO_UID" ]] && echo "Please set the TO_UID variable" && exit 1
fi

cd secp256k1

if [ "$TARGET" == "mingw" ]; then
  CONF_OPTS="CFLAGS=-fpic --host=x86_64-w64-mingw32"
elif [ "$TARGET" == "linux" ]; then
  CONF_OPTS="CFLAGS=-fpic"
  [ "$CROSS" == "1" ] && sudo apt -y install libgmp-dev
elif [ "$TARGET" == "darwin" ]; then
  CONF_OPTS="--host=x86_64-w64-darwin"
fi

./autogen.sh
./configure $CONF_OPTS --enable-experimental --enable-module_ecdh --enable-module-recovery --enable-benchmark=no --enable-shared=no --enable-exhaustive-tests=no --enable-tests=no
make clean
make

[[ ! -z "$TO_UID" ]] && chown -R $TO_UID:$TO_UID .

cd ..

mkdir -p build/$TARGET
cp -v secp256k1/.libs/libsecp256k1.a build/$TARGET/

[[ ! -z "$TO_UID" ]] && chown -R $TO_UID:$TO_UID build

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

$CC -shared $CC_OPTS -o build/$TARGET/$OUTFILE jni/src/org_bitcoin_Secp256k1CFunctions.c -Ijni/headers/ -Ijni/headers/java -Ijni/headers/$JNI_HEADERS/ -Isecp256k1/ -lsecp256k1 -Lbuild/$TARGET/ $ADD_LIB

[[ ! -z "$TO_UID" ]] && chown -R $TO_UID:$TO_UID build

echo "Build done for $TARGET"
