# Secp256k1 for Kotlin/Multiplatform

Kotlin/Multiplatform wrapper for Bitcoin Core's secp256k1 library. Targets: JVM, Android, iOS & Linux.

## Installation

[ ![Download](https://api.bintray.com/packages/acinq/libs/secp256k1-kmp/images/download.svg) ](https://bintray.com/acinq/libs/secp256k1-kmp/0.1.0-1.4-M2/link)

First, you need to add the ACINQ libraries repository:

```kotlin
// build.gradle.kts
repositories {
    maven(url = "https://dl.bintray.com/acinq/libs")
}
```

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

* For desktop or server JVMs, you must add the `fr.acinq.secp256k1:secp256k1-jni-jvm` dependency
* For Android, you must add the `fr.acinq.secp256k1:secp256k1-jni-android` dependency

If you are using the JVM on an OS for which we don't provide JNI bindings (32 bits OS for example), you can use your own library native library by
adding the `fr.acinq.secp256k1:secp256k1-jni-jvm` dependency and specifying its path with `-Dfr.acinq.secp256k1.lib.path` and optionally its name with `-Dfr.acinq.secp256k1.lib.name`
(if unspecified bitcoink use the standard name for your OS i.e. libsecp256k1.so on Linux, secp256k1.dll on Windows, ...).

You can also specify the temporary directory where the library will be extracted with `-Djava.io.tmpdir` or `-Dfr.acinq.secp256k1.tmpdir`
(if you want to use a different directory from `-Djava.io.tmpdir`).

## Usage

Please have a look at unit tests, more samples will be added soon.
