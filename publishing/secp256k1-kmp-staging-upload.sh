#!/bin/bash -x
#
# first you must sign all files:
# find release -type f -print -exec gpg -ab {} \;

if [[ -z "${VERSION}" ]]; then
  echo "VERSION is not defined"
  exit 1
fi

if [[ -z "${OSS_USER}" ]]; then
  echo "OSS_USER is not defined"
  exit 1
fi

read -p "Password : " -s OSS_PASSWORD


for i in 	secp256k1-kmp \
		secp256k1-kmp-iosarm64 \
		secp256k1-kmp-iossimulatorarm64 \
		secp256k1-kmp-iosx64 \
		secp256k1-kmp-jni-android \
		secp256k1-kmp-jni-common \
		secp256k1-kmp-jni-jvm \
		secp256k1-kmp-jni-jvm-darwin \
		secp256k1-kmp-jni-jvm-extract \
		secp256k1-kmp-jni-jvm-linux \
		secp256k1-kmp-jni-jvm-mingw \
		secp256k1-kmp-jvm \
		secp256k1-kmp-linuxx64
do
	pushd .
	cd release/fr/acinq/secp256k1/$i/$VERSION
	pwd
	jar -cvf bundle.jar *
	# use correct sonatype credentials here
  curl -v -XPOST -u $OSS_USER:$OSS_PASSWORD --upload-file bundle.jar https://oss.sonatype.org/service/local/staging/bundle_upload
  popd
done

