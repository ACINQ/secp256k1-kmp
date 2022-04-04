#!/bin/bash -x

if [ $# -eq 0 ]
  then
    echo "specify either snapshot or release"
    exit 1
fi

# add aarch64 (ARM64) library to the linux jar
if [ -e fr/acinq/secp256k1/jni/native/linux-aarch64/libsecp256k1-jni.so ]
then
    jar -uf $1/fr/acinq/secp256k1/secp256k1-kmp-jni-jvm-linux/$VERSION/secp256k1-kmp-jni-jvm-linux-$VERSION.jar fr || exit
else
    libsecp256k1-jni.so for arch64 is missing
    exit 1
fi

