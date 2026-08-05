#!/bin/bash
#
# usage:
# VERSION=XXX ./secp256k1-kmp-staging-upload.sh create # to create bundles, which include checksums and signatures (requires access to a valid gpg key)
# VERSION=XXX ./secp256k1-kmp-staging-upload.sh upload # to upload bundles to sonatype's staging area (requires a valid portal token)
# this script assumes that you have a ~/.m2/settings.xml file that contains the following server definition:

#<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
#          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 https://maven.apache.org/xsd/settings-1.0.0.xsd">
#    <servers>
#        <server>
#            <id>central_portal</id>
#            <username>${env.MVN_USER}</username>
#            <password>${env.MVN_PASS}</password>
#        </server>
#    </servers>
#</settings>

if [[ -z "${VERSION}" ]]; then
  echo "VERSION is not defined"
  exit 1
fi

if [[ -z "${CENTRAL_TOKEN_GPG_FILE}" ]]; then
  echo "CENTRAL_TOKEN_GPG_FILE is not defined"
  exit 1
fi

CENTRAL_TOKEN=$(gpg --decrypt $CENTRAL_TOKEN_GPG_FILE)

pushd .
cd release
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
		secp256k1-kmp-linuxarm64 \
		secp256k1-kmp-linuxx64 \
		secp256k1-kmp-macosarm64 \
		secp256k1-kmp-macosx64
do
	DIR=fr/acinq/secp256k1/$i/$VERSION
	case $1 in
	create)
  	for file in $DIR/*
	  do
	    sha1sum $file | sed 's/ .*//' > $file.sha1
	    md5sum $file | sed 's/ .*//' > $file.md5
	    gpg -ab $file
    done
	  zip -r $i.zip $DIR
	  ;;
	upload)
    curl --request POST --verbose --header "Authorization: Bearer ${CENTRAL_TOKEN}" --form bundle=@$i.zip https://central.sonatype.com/api/v1/publisher/upload
    ;;
  esac
done
popd