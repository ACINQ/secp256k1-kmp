plugins {
    kotlin("multiplatform") version "1.4-M2-mt"
}
group = "fr.acinq.phoenix"
version = "1.0-1.4-M2"

repositories {
    jcenter()
    maven(url = "https://dl.bintray.com/kotlin/kotlin-eap")
    maven("https://dl.bintray.com/kotlin/kotlin-eap")
}

val currentOs = org.gradle.internal.os.OperatingSystem.current()

kotlin {
    explicitApi()

    jvm {
        compilations.all {
            kotlinOptions.jvmTarget = "1.8"
        }
    }

//    linuxX64()
//    ios()

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(kotlin("stdlib-common"))
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test-common"))
                implementation(kotlin("test-annotations-common"))
            }
        }
        val jvmMain by getting {
            dependencies {
                implementation(kotlin("stdlib-jdk8"))
                implementation(kotlin("test-junit"))
            }
        }
        val jvmTest by getting {
            dependencies {
                implementation(kotlin("test-junit"))
            }
        }
    }
}

val buildSecp256k1 by tasks.creating { group = "build" }
fun creatingBuildSecp256k1(target: String, cross: String? = null, env: String = "", configuration: Task.() -> Unit = {}) = tasks.creating {
    group = "build"
    buildSecp256k1.dependsOn(this)

    inputs.files(projectDir.resolve("native/build.sh"))
    outputs.dir(projectDir.resolve("native/build/$target"))

    doLast {
        exec {
            workingDir = projectDir.resolve("native")
            environment("TARGET", target)
            if (cross == null) commandLine("./build.sh")
            else commandLine("./dockcross-$cross", "bash", "-c", "TARGET=$target ./build.sh")
        }
    }

    configuration()
}

val buildSecp256k1Darwin by creatingBuildSecp256k1("darwin")
val buildSecp256k1Linux by creatingBuildSecp256k1("linux", cross = if (currentOs.isMacOsX) "linux-x64" else null)
val buildSecp256k1Mingw by creatingBuildSecp256k1("mingw", cross = "windows-x64", env = "CONF_OPTS=--host=x86_64-w64-mingw32")

val copyJni by tasks.creating(Sync::class) {
    dependsOn(buildSecp256k1)
    from(projectDir.resolve("native/build/linux/libsecp256k1-jni.so")) { rename { "libsecp256k1-jni-linux-x86_64.so" } }
    from(projectDir.resolve("native/build/darwin/libsecp256k1-jni.dylib")) { rename { "libsecp256k1-jni-darwin-x86_64.dylib" } }
    from(projectDir.resolve("native/build/mingw/secp256k1-jni.dll")) { rename { "secp256k1-jni-mingw-x86_64.dll" } }
    into(buildDir.resolve("jniResources/fr/acinq/secp256k1/native"))
}

(tasks[kotlin.jvm().compilations["main"].processResourcesTaskName] as ProcessResources).apply{
    dependsOn(copyJni)
    from(buildDir.resolve("jniResources"))
}
