#!/bin/bash
#
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

GROUP_ID=fr.acinq.secp256k1
ARTIFACT_ID_BASE=secp256k1-kmp

if [[ -z "${VERSION}" ]]; then
  echo "VERSION is not defined"
  exit 1
fi

if [[ -z "${CENTRAL_TOKEN_GPG_FILE}" ]]; then
  echo "CENTRAL_TOKEN_GPG_FILE is not defined"
  exit 1
fi

CENTRAL_TOKEN="$(gpg --decrypt $CENTRAL_TOKEN_GPG_FILE | base64 -d)"
IFS=":" read -r MVNUSER MVNPASS <<< "$CENTRAL_TOKEN"

cd snapshot
pushd .
cd fr/acinq/secp256k1/secp256k1-kmp/$VERSION
MVN_USER=$MVNUSER MVN_PASS=$MVNPASS mvn deploy:deploy-file -DrepositoryId=central_portal -Durl=https://central.sonatype.com/repository/maven-snapshots/ \
  -DpomFile=$ARTIFACT_ID_BASE-$VERSION.pom \
  -Dfile=$ARTIFACT_ID_BASE-$VERSION.jar \
  -Dfiles=$ARTIFACT_ID_BASE-$VERSION.module,$ARTIFACT_ID_BASE-$VERSION-kotlin-tooling-metadata.json \
  -Dtypes=module,json \
  -Dclassifiers=,kotlin-tooling-metadata \
  -Dsources=$ARTIFACT_ID_BASE-$VERSION-sources.jar \
  -Djavadoc=$ARTIFACT_ID_BASE-$VERSION-javadoc.jar
popd
pushd .
for i in iosarm64 iossimulatorarm64 iosx64 macosarm64 macosx64 jni-android jni-common jni-jvm-darwin jni-jvm-extract jni-jvm-linux jni-jvm-mingw jni-jvm jvm linuxarm64 linuxx64; do
  cd fr/acinq/secp256k1/secp256k1-kmp-$i/$VERSION

  case $i in
    iosarm64 | iossimulatorarm64 | iosx64 | macosarm64 | macosx64)
          MVN_USER=$MVNUSER MVN_PASS=$MVNPASS mvn deploy:deploy-file -DrepositoryId=central_portal -Durl=https://central.sonatype.com/repository/maven-snapshots/ \
            -DpomFile=$ARTIFACT_ID_BASE-$i-$VERSION.pom \
            -Dfile=$ARTIFACT_ID_BASE-$i-$VERSION.klib \
            -Dfiles=$ARTIFACT_ID_BASE-$i-$VERSION-metadata.jar,$ARTIFACT_ID_BASE-$i-$VERSION.module,$ARTIFACT_ID_BASE-$i-$VERSION-cinterop-libsecp256k1.klib \
            -Dtypes=jar,module,klib \
            -Dclassifiers=metadata,,cinterop-libsecp256k1 \
            -Dsources=$ARTIFACT_ID_BASE-$i-$VERSION-sources.jar \
            -Djavadoc=$ARTIFACT_ID_BASE-$i-$VERSION-javadoc.jar
          ;;
    linuxx64 | linuxarm64)
      MVN_USER=$MVNUSER MVN_PASS=$MVNPASS mvn deploy:deploy-file -DrepositoryId=central_portal -Durl=https://central.sonatype.com/repository/maven-snapshots/ \
        -DpomFile=$ARTIFACT_ID_BASE-$i-$VERSION.pom \
        -Dfile=$ARTIFACT_ID_BASE-$i-$VERSION.klib \
        -Dfiles=$ARTIFACT_ID_BASE-$i-$VERSION.module,$ARTIFACT_ID_BASE-$i-$VERSION-cinterop-libsecp256k1.klib \
        -Dtypes=module,klib \
        -Dclassifiers=,cinterop-libsecp256k1 \
        -Dsources=$ARTIFACT_ID_BASE-$i-$VERSION-sources.jar \
        -Djavadoc=$ARTIFACT_ID_BASE-$i-$VERSION-javadoc.jar
      ;;
    jni-android)
      MVN_USER=$MVNUSER MVN_PASS=$MVNPASS mvn deploy:deploy-file -DrepositoryId=central_portal -Durl=https://central.sonatype.com/repository/maven-snapshots/ \
        -DpomFile=$ARTIFACT_ID_BASE-$i-$VERSION.pom \
        -Dfile=$ARTIFACT_ID_BASE-$i-$VERSION.aar \
        -Dfiles=$ARTIFACT_ID_BASE-$i-$VERSION.module \
        -Dtypes=module \
        -Dclassifiers= \
        -Dsources=$ARTIFACT_ID_BASE-$i-$VERSION-sources.jar \
        -Djavadoc=$ARTIFACT_ID_BASE-$i-$VERSION-javadoc.jar
      ;;
    *)
      MVN_USER=$MVNUSER MVN_PASS=$MVNPASS mvn deploy:deploy-file -DrepositoryId=central_portal -Durl=https://central.sonatype.com/repository/maven-snapshots/ \
        -DpomFile=$ARTIFACT_ID_BASE-$i-$VERSION.pom \
        -Dfile=$ARTIFACT_ID_BASE-$i-$VERSION.jar \
        -Dfiles=$ARTIFACT_ID_BASE-$i-$VERSION.module \
        -Dtypes=module \
        -Dclassifiers= \
        -Dsources=$ARTIFACT_ID_BASE-$i-$VERSION-sources.jar \
        -Djavadoc=$ARTIFACT_ID_BASE-$i-$VERSION-javadoc.jar
      ;;
  esac

  popd
  pushd .
done
