#!/bin/bash -x

GROUP_ID=fr.acinq.secp256k1
ARTIFACT_ID_BASE=secp256k1-kmp
VERSION=0.9.0-SNAPSHOT

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
for i in iosarm64 iosx64 jni-android jni-common jni-jvm-darwin jni-jvm-extract jni-jvm-linux jni-jvm-mingw jni-jvm jvm linux
do
    cd fr/acinq/secp256k1/secp256k1-kmp-$i/$VERSION
    if [ $i == iosarm64 ] || [ $i == iosx64 ] || [ $i == linux ]; then
        mvn deploy:deploy-file -DrepositoryId=ossrh -Durl=https://oss.sonatype.org/content/repositories/snapshots/ \
        -DpomFile=$ARTIFACT_ID_BASE-$i-$VERSION.pom \
        -Dfile=$ARTIFACT_ID_BASE-$i-$VERSION.klib \
    	-Dfiles=$ARTIFACT_ID_BASE-$i-$VERSION.module,$ARTIFACT_ID_BASE-$i-$VERSION-cinterop-libsecp256k1.klib  \
    	-Dtypes=module,klib \
    	-Dclassifiers=,cinterop-libsecp256k1 \
        -Dsources=$ARTIFACT_ID_BASE-$i-$VERSION-sources.jar \
        -Djavadoc=$ARTIFACT_ID_BASE-$i-$VERSION-javadoc.jar
    elif [ $i == jni-android ]; then
        mvn deploy:deploy-file -DrepositoryId=ossrh -Durl=https://oss.sonatype.org/content/repositories/snapshots/ \
        -DpomFile=$ARTIFACT_ID_BASE-$i-$VERSION.pom \
        -Dfile=$ARTIFACT_ID_BASE-$i-$VERSION.aar \
    	-Dfiles=$ARTIFACT_ID_BASE-$i-$VERSION.module \
    	-Dtypes=module \
        -Dclassifiers= \
    	-Dsources=$ARTIFACT_ID_BASE-$i-$VERSION-sources.jar \
        -Djavadoc=$ARTIFACT_ID_BASE-$i-$VERSION-javadoc.jar
    else
        mvn deploy:deploy-file -DrepositoryId=ossrh -Durl=https://oss.sonatype.org/content/repositories/snapshots/ \
        -DpomFile=$ARTIFACT_ID_BASE-$i-$VERSION.pom \
        -Dfile=$ARTIFACT_ID_BASE-$i-$VERSION.jar \
    	-Dfiles=$ARTIFACT_ID_BASE-$i-$VERSION.module \
    	-Dtypes=module \
        -Dclassifiers= \
        -Dsources=$ARTIFACT_ID_BASE-$i-$VERSION-sources.jar \
        -Djavadoc=$ARTIFACT_ID_BASE-$i-$VERSION-javadoc.jar
    fi    
    popd
    pushd .
done
