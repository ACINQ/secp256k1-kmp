#!/bin/bash -x
#
# first you must sign all files:
# find release -type f -print -exec gpg -ab {} \;

VERSION=0.6.2
for i in 	secp256k1-kmp \
		secp256k1-kmp-iosarm64 \
		secp256k1-kmp-iosx64 \
		secp256k1-kmp-jni-android \
		secp256k1-kmp-jni-common \
		secp256k1-kmp-jni-jvm \
		secp256k1-kmp-jni-jvm-darwin \
		secp256k1-kmp-jni-jvm-extract \
		secp256k1-kmp-jni-jvm-linux \
		secp256k1-kmp-jni-jvm-mingw \
		secp256k1-kmp-jvm \
		secp256k1-kmp-linux
do
	pushd .
	cd release/fr/acinq/secp256k1/$i/$VERSION
	pwd
	jar -cvf bundle.jar *
	# use correct sonatype credentials here
  curl -v -XPOST -u USER:PASSWORD --upload-file bundle.jar https://oss.sonatype.org/service/local/staging/bundle_upload
  popd
done

