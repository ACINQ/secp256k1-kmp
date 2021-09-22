[![Kotlin](https://img.shields.io/badge/Kotlin-1.5.31-blue.svg?style=flat&logo=kotlin)](http://kotlinlang.org)
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
                implementation(kotlin("fr.acinq.secp256k1:secp256k1:$secp256k1_version"))
            }
        }
        val jvmMain by getting {
            dependencies {
                implementation(kotlin("stdlib"))
                implementation(kotlin("fr.acinq.secp256k1:secp256k1-jni-jvm:$secp256k1_version"))
            }
        }
        val androidMain by getting {
            dependencies {
                implementation(kotlin("stdlib"))
                implementation(kotlin("fr.acinq.secp256k1:secp256k1-jni-android:$secp256k1_version"))
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
  * Either the `fr.acinq.secp256k1:secp256k1-jni-jvm` dependency which imports all supported platforms.
  * Or the platform specific dependencies (note that you can add multiple as they do not conflict):
    * `fr.acinq.secp256k1:secp256k1-jni-jvm-linux` for Linux
    * `fr.acinq.secp256k1:secp256k1-jni-jvm-darwin` for Mac OS X
    * `fr.acinq.secp256k1:secp256k1-jni-jvm-mingw` for Windows
* **For Android**, you must add the `fr.acinq.secp256k1:secp256k1-jni-android` dependency

If you are using the JVM on an OS for which we don't provide JNI bindings (32 bits OS for example), you can use your own library native library by
adding the `fr.acinq.secp256k1:secp256k1-jni-jvm` dependency and specifying its path with `-Dfr.acinq.secp256k1.lib.path` and optionally its name with `-Dfr.acinq.secp256k1.lib.name`
(if unspecified bitcoink use the standard name for your OS i.e. libsecp256k1.so on Linux, secp256k1.dll on Windows, ...).

To compile your own JNI bindings, have a look add the `native/build.sh` and `jni/build.sh` scripts.

You can also specify the temporary directory where the library will be extracted with `-Djava.io.tmpdir` or `-Dfr.acinq.secp256k1.tmpdir`
(if you want to use a different directory from `-Djava.io.tmpdir`).

## Usage

Please have a look at unit tests, more samples will be added soon.
