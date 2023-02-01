[![Kotlin](https://img.shields.io/badge/Kotlin-1.6.21-blue.svg?style=flat&logo=kotlin)](http://kotlinlang.org)
[![Maven Central](https://img.shields.io/maven-central/v/fr.acinq.secp256k1/secp256k1-kmp)](https://search.maven.org/search?q=g:fr.acinq.secp256k1%20a:secp256k1-kmp*)
![Github Actions](https://github.com/ACINQ/secp256k1-kmp/actions/workflows/test.yml/badge.svg)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/ACINQ/secp256k1-kmp/blob/master/LICENSE)

# Secp256k1 for Kotlin/Multiplatform

Kotlin/Multiplatform wrapper for Bitcoin Core's secp256k1 library. Targets: JVM, Android, iOS & Linux.

## Installation

secp256k1-kmp is available on [maven central](https://search.maven.org/search?q=g:fr.acinq.secp256k1%20a:secp256k1-kmp*)

Then, the actual dependency depends on your targeted platform(s):

### Multiplatform

Add the `secp256k1` dependency to the common sourceSet, and the JNI dependencies to JVM and Android sourcesets:

```kotlin
// build.gradle.kts

kotlin {
    jvm()
    android()
    linuxX64("linux")
    ios()

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(kotlin("stdlib-common"))
                implementation("fr.acinq.secp256k1:secp256k1-kmp:$secp256k1_version")
            }
        }
        val jvmMain by getting {
            dependencies {
                implementation(kotlin("stdlib"))
                implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm:$secp256k1_version")
            }
        }
        val androidMain by getting {
            dependencies {
                implementation(kotlin("stdlib"))
                implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-android:$secp256k1_version")
            }
        }
    }
}
```

### Native targets (iOS, linux64)

Native targets include libsecp256k1, called through KMP's c-interop, simply add the `fr.acinq.secp256k1:secp256k1` dependency.

### JVM targets & Android

The JVM library uses JNI bindings for libsecp256k1, which is much faster than BouncyCastle. It will extract and load native bindings for your operating system in a temporary directory.

JNI libraries are included for:
- Linux 64 bits
- Windows 64 bits
- Macos 64 bits

Along this library, you **must** specify which JNI native library to use in your dependency manager:

* **For desktop or server JVMs**, you must add the dependency:
  * Either the `fr.acinq.secp256k1:secp256k1-kmp-jni-jvm` dependency which imports all supported platforms.
  * Or the platform specific dependencies (note that you can add multiple as they do not conflict):
    * `fr.acinq.secp256k1:secp256k1-kmp-jni-jvm-linux` for Linux
    * `fr.acinq.secp256k1:secp256k1-kmp-jni-jvm-darwin` for Mac OS X
    * `fr.acinq.secp256k1:secp256k1-kmp-jni-jvm-mingw` for Windows
* **For Android**, you must add the `fr.acinq.secp256k1:secp256k1-kmp-jni-android` dependency

If you are using the JVM on an OS for which we don't provide JNI bindings (32 bits OS for example), you can use your own library native library by
adding the `fr.acinq.secp256k1:secp256k1-kmp-jni-jvm` dependency and specifying its path with `-Dfr.acinq.secp256k1.lib.path` and optionally its name with `-Dfr.acinq.secp256k1.lib.name`
(if unspecified bitcoink use the standard name for your OS i.e. libsecp256k1.so on Linux, secp256k1.dll on Windows, ...).

To compile your own JNI bindings, have a look add the `native/build.sh` and `jni/build.sh` scripts.

You can also specify the temporary directory where the library will be extracted with `-Djava.io.tmpdir` or `-Dfr.acinq.secp256k1.tmpdir`
(if you want to use a different directory from `-Djava.io.tmpdir`).

## Usage

Please have a look at unit tests, more samples will be added soon.

## Building

**secp256k1-kmp** is a [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html) wrapper for Bitcoin Core's [secp256k1 library](https://github.com/bitcoin-core/secp256k1).

To build the library you need the following:
- Window 64 bits, Linux 64 bits, or MacOs 64 Bits
- OpenJDK11 (we recommend using packages provided by https://adoptopenjdk.net/ but there are other options)
- (optional) Android SDK

It may work with other Operating Systems and JDKs, but then you're on your own (in particular we don't plan to support 32 bits Operating Systems).
To build the library and publish compiled artefacts locally (so they can be used by other projects):

```sh
./gradlew :build
./gradlew :publishToMavenLocal
```

To run all tests on all platforms:

```sh
./gradlew allTests
```

To run tests on a single platform, for example the JVM:

```sh
./gradlew jvmTest
```

If you want to skip building Android artefacts create a `local.properties` file in the project's root directory and add the following line:

```
skip.android=true
```

## Contributing to and extending the library

secp256k1-kmp follows 2 simples rules:
- copy as literally as possible what the original [secp256k1 library](https://github.com/bitcoin-core/secp256k1) does: use the same function names, parameters, options, ... 
- follow JNI best practices (memory allocation, error handling, ...)
 
"Porting" C/C++ code that uses [secp256k1](https://github.com/bitcoin-core/secp256k1) should be a no-brainer and we should not have to document secp256k1-kmp


To extend this library and support methods that have been added to specific versions of [secp256k1](https://github.com/bitcoin-core/secp256k1) you have to:
- add new methods to the Secp256k1 interface src/commonMain/kotlin/fr/acinq/secp256k1/Secp256k1.kt (please follow rule #1 above and try and match secp256k1's interface as much as possible)
- implement these new methods in jni/src/main/kotlin/fr/acinq/secp256k1/NativeSecp256k1.kt (JNI implementation) and src/nativeMain/kotlin/fr/acinq/secp256k1/Secp256k1Native.kt (native linux/ios/... implementation)
- update the JNI interface src/main/java/fr/acinq/secp256k1/Secp256k1CFunctions.java (NativeSecp256k1 calls Secp256k1CFunctions)
- generate a new JNI header file jni/c/headers/java/fr_acinq_secp256k1_Secp256k1CFunctions.h with `javac -h jni/c/headers/java jni/src/main/java/fr/acinq/secp256k1/Secp256k1CFunctions.java`
- implement the new methods in jni/c/src/fr_acinq_secp256k1_Secp256k1CFunctions.c

You may also need to modify build files if you need to compile [secp256k1](https://github.com/bitcoin-core/secp256k1) with custom options

We use [secp256k1](https://github.com/bitcoin-core/secp256k1) through git submodules so you may also need to change what they point to
