#!/bin/bash -x

GROUP_ID=fr.acinq.secp256k1
ARTIFACT_ID_BASE=secp256k1-kmp

if [[ -z "${VERSION}" ]]; then
  echo "VERSION is not defined"
  exit 1
fi

cd snapshot
pushd .
cd fr/acinq/secp256k1/secp256k1-kmp/$VERSION
mvn deploy:deploy-file -DrepositoryId=ossrh -Durl=https://oss.sonatype.org/content/repositories/snapshots/ \
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
          mvn deploy:deploy-file -DrepositoryId=ossrh -Durl=https://oss.sonatype.org/content/repositories/snapshots/ \
            -DpomFile=$ARTIFACT_ID_BASE-$i-$VERSION.pom \
            -Dfile=$ARTIFACT_ID_BASE-$i-$VERSION.klib \
            -Dfiles=$ARTIFACT_ID_BASE-$i-$VERSION-metadata.jar,$ARTIFACT_ID_BASE-$i-$VERSION.module,$ARTIFACT_ID_BASE-$i-$VERSION-cinterop-libsecp256k1.klib \
            -Dtypes=jar,module,klib \
            -Dclassifiers=metadata,,cinterop-libsecp256k1 \
            -Dsources=$ARTIFACT_ID_BASE-$i-$VERSION-sources.jar \
            -Djavadoc=$ARTIFACT_ID_BASE-$i-$VERSION-javadoc.jar
          ;;
    linuxx64 | linuxarm64)
      mvn deploy:deploy-file -DrepositoryId=ossrh -Durl=https://oss.sonatype.org/content/repositories/snapshots/ \
        -DpomFile=$ARTIFACT_ID_BASE-$i-$VERSION.pom \
        -Dfile=$ARTIFACT_ID_BASE-$i-$VERSION.klib \
        -Dfiles=$ARTIFACT_ID_BASE-$i-$VERSION.module,$ARTIFACT_ID_BASE-$i-$VERSION-cinterop-libsecp256k1.klib \
        -Dtypes=module,klib \
        -Dclassifiers=,cinterop-libsecp256k1 \
        -Dsources=$ARTIFACT_ID_BASE-$i-$VERSION-sources.jar \
        -Djavadoc=$ARTIFACT_ID_BASE-$i-$VERSION-javadoc.jar
      ;;
    jni-android)
      mvn deploy:deploy-file -DrepositoryId=ossrh -Durl=https://oss.sonatype.org/content/repositories/snapshots/ \
        -DpomFile=$ARTIFACT_ID_BASE-$i-$VERSION.pom \
        -Dfile=$ARTIFACT_ID_BASE-$i-$VERSION.aar \
        -Dfiles=$ARTIFACT_ID_BASE-$i-$VERSION.module \
        -Dtypes=module \
        -Dclassifiers= \
        -Dsources=$ARTIFACT_ID_BASE-$i-$VERSION-sources.jar \
        -Djavadoc=$ARTIFACT_ID_BASE-$i-$VERSION-javadoc.jar
      ;;
    *)
      mvn deploy:deploy-file -DrepositoryId=ossrh -Durl=https://oss.sonatype.org/content/repositories/snapshots/ \
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
