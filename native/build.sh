#!/usr/bin/env bash
set -e

[[ -z "$TARGET" ]] && echo "Please set the PLATFORM variable" && exit 1

cd secp256k1

if [ "$TARGET" == "mingw" ]; then
  CONF_OPTS="CFLAGS=-fpic --host=x86_64-w64-mingw32"
elif [ "$TARGET" == "linux" ]; then
  CONF_OPTS="CFLAGS=-fpic"
fi

./autogen.sh
./configure $CONF_OPTS --enable-experimental --enable-module_ecdh --enable-module-recovery --enable-benchmark=no --enable-shared=no --enable-exhaustive-tests=no --enable-tests=no
make clean
make

cd ..

mkdir -p build/$TARGET
cp -r secp256k1/.libs/libsecp256k1.a build/$TARGET/

GCC=gcc
JNI_HEADERS=$TARGET

if [ "$TARGET" == "linux" ]; then
  OUTFILE=libsecp256k1-jni.so
elif [ "$TARGET" == "darwin" ]; then
  OUTFILE=libsecp256k1-jni.dylib
  ADD_LIB=-lgmp
elif [ "$TARGET" == "mingw" ]; then
  OUTFILE=secp256k1-jni.dll
  GCC=/usr/src/mxe/usr/bin/x86_64-w64-mingw32.static-gcc
  JNI_HEADERS=linux
  GCC_OPTS="-fpic"
fi

echo $GCC -shared $GCC_OPTS -o build/$TARGET/$OUTFILE jni/src/org_bitcoin_NativeSecp256k1.c jni/src/org_bitcoin_Secp256k1Context.c -Ijni/headers/ -Ijni/headers/$JNI_HEADERS/ -Isecp256k1/ -lsecp256k1 -Lbuild/$TARGET/ $ADD_LIB

$GCC -shared $GCC_OPTS -o build/$TARGET/$OUTFILE jni/src/org_bitcoin_NativeSecp256k1.c jni/src/org_bitcoin_Secp256k1Context.c -Ijni/headers/ -Ijni/headers/$JNI_HEADERS/ -Isecp256k1/ -lsecp256k1 -Lbuild/$TARGET/ $ADD_LIB
