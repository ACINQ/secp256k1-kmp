#!/bin/bash -x

if [ $# -eq 0 ]
  then
    echo "specify either snapshot or release"
    exit 1
fi

DYLIB=fr/acinq/secp256k1/jni/native/darwin-aarch64/libsecp256k1-jni.dylib

# add aarch64 (ARM64) library to the darwin jar
if [ -e $DYLIB ]
then
    file $DYLIB | grep arm64
    if [ $? -eq 0 ]
    then
      jar -uf $1/fr/acinq/secp256k1/secp256k1-kmp-jni-jvm-darwin/$VERSION/secp256k1-kmp-jni-jvm-darwin-$VERSION.jar fr || exit
    else
      echo "libsecp256k1-jni.dylib is built for a different architecture"
      file $DYLIB
      exit 2
    fi
else
    echo "libsecp256k1-jni.dylib for darwin-arch64 is missing"
    exit 1
fi
