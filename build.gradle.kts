plugins {
    kotlin("multiplatform") version "1.4-M2-mt"
    id("com.android.library") version "4.0.0"
    `maven-publish`
}
group = "fr.acinq.secp256k1"
version = "0.2.1-1.4-M2"

repositories {
    jcenter()
    google()
    maven(url = "https://dl.bintray.com/kotlin/kotlin-eap")
}

val currentOs = org.gradle.internal.os.OperatingSystem.current()

kotlin {
    explicitApi()

    val commonMain by sourceSets.getting {
        dependencies {
            implementation(kotlin("stdlib-common"))
        }
    }
    val commonTest by sourceSets.getting {
        dependencies {
            implementation(kotlin("test-common"))
            implementation(kotlin("test-annotations-common"))
        }
    }

    val jvmAndAndroidMain by sourceSets.creating {
        dependsOn(commonMain)
        dependencies {
            implementation(kotlin("stdlib-jdk8"))
        }
    }

    jvm {
        compilations.all {
            kotlinOptions.jvmTarget = "1.8"
        }
        (tasks[compilations["main"].processResourcesTaskName] as ProcessResources).apply{
            dependsOn("copyJni")
            from(buildDir.resolve("jniResources"))
        }
        compilations["main"].defaultSourceSet.dependsOn(jvmAndAndroidMain)
        compilations["test"].dependencies {
            implementation(kotlin("test-junit"))
        }
    }

    android {
        publishLibraryVariants("release", "debug")
        compilations.all {
            kotlinOptions.jvmTarget = "1.8"
        }
        sourceSets["androidMain"].dependsOn(jvmAndAndroidMain)
        sourceSets["androidTest"].dependencies {
            implementation(kotlin("test-junit"))
            implementation("androidx.test.ext:junit:1.1.1")
            implementation("androidx.test.espresso:espresso-core:3.2.0")
        }
    }

    fun org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget.secp256k1CInterop() {
        compilations["main"].cinterops {
            val libsecp256k1 by creating {
                includeDirs.headerFilterOnly(project.file("native/secp256k1/include/"))
                tasks[interopProcessingTaskName].dependsOn("buildSecp256k1Ios")
            }
        }
    }

    val nativeMain by sourceSets.creating { dependsOn(commonMain) }

    linuxX64 {
        secp256k1CInterop()
        // https://youtrack.jetbrains.com/issue/KT-39396
        compilations["main"].kotlinOptions.freeCompilerArgs += listOf("-include-binary", "$rootDir/native/build/linux/libsecp256k1.a")
        compilations["main"].defaultSourceSet.dependsOn(nativeMain)
    }

    ios {
        secp256k1CInterop()
        // https://youtrack.jetbrains.com/issue/KT-39396
        compilations["main"].kotlinOptions.freeCompilerArgs += listOf("-include-binary", "$rootDir/native/build/ios/libsecp256k1.a")
        compilations["main"].defaultSourceSet.dependsOn(nativeMain)
    }

    sourceSets.all {
        languageSettings.useExperimentalAnnotation("kotlin.RequiresOptIn")
    }

}

// Disable cross compilation
afterEvaluate {
    val currentOs = org.gradle.internal.os.OperatingSystem.current()
    val targets = when {
        currentOs.isLinux -> listOf()
        currentOs.isMacOsX -> listOf("linux")
        currentOs.isWindows -> listOf("linux")
        else -> listOf("linux")
    }.mapNotNull { kotlin.targets.findByName(it) as? org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget }

    configure(targets) {
        compilations.all {
            cinterops.all { tasks[interopProcessingTaskName].enabled = false }
            compileKotlinTask.enabled = false
            tasks[processResourcesTaskName].enabled = false
        }
        binaries.all { linkTask.enabled = false }

        mavenPublication {
            val publicationToDisable = this
            tasks.withType<AbstractPublishToMaven>().all { onlyIf { publication != publicationToDisable } }
            tasks.withType<GenerateModuleMetadata>().all { onlyIf { publication.get() != publicationToDisable } }
        }
    }
}

android {
    defaultConfig {
        compileSdkVersion(30)
        minSdkVersion(21)
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        externalNativeBuild {
            cmake {}
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    externalNativeBuild {
        cmake {
            setPath("src/androidMain/CMakeLists.txt")
        }
    }
    ndkVersion = "21.3.6528147"

    sourceSets["main"].manifest.srcFile("src/androidMain/AndroidManifest.xml")

    afterEvaluate {
        tasks.withType<com.android.build.gradle.tasks.factory.AndroidUnitTest>().all {
            enabled = false
        }
    }
}

val buildSecp256k1 by tasks.creating { group = "build" }
sealed class Cross {
    abstract fun cmd(target: String, nativeDir: File): List<String>
    class DockCross(val cross: String) : Cross() {
        override fun cmd(target: String, nativeDir: File): List<String> = listOf("./dockcross-$cross", "bash", "-c", "CROSS=1 TARGET=$target ./build.sh")
    }
    class MultiArch(val crossTriple: String) : Cross() {
        override fun cmd(target: String, nativeDir: File): List<String> {
            val uid = Runtime.getRuntime().exec("id -u").inputStream.use { it.reader().readText() }.trim().toInt()
            return listOf(
                "docker", "run", "--rm", "-v", "${nativeDir.absolutePath}:/workdir",
                "-e", "CROSS_TRIPLE=$crossTriple", "-e", "TARGET=$target", "-e", "TO_UID=$uid", "-e", "CROSS=1",
                "multiarch/crossbuild", "./build.sh"
            )
        }
    }
}
fun creatingBuildSecp256k1(target: String, cross: Cross?) = tasks.creating(Exec::class) {
    group = "build"
    buildSecp256k1.dependsOn(this)

    inputs.files(projectDir.resolve("native/build.sh"))
    outputs.dir(projectDir.resolve("native/build/$target"))

    workingDir = projectDir.resolve("native")
    environment("TARGET", target)
    commandLine((cross?.cmd(target, workingDir) ?: emptyList()) + "./build.sh")
}
val buildSecp256k1Darwin by creatingBuildSecp256k1("darwin", if (currentOs.isMacOsX) null else Cross.MultiArch("x86_64-apple-darwin"))
val buildSecp256k1Linux by creatingBuildSecp256k1("linux", if (currentOs.isLinux) null else Cross.DockCross("linux-x64"))
val buildSecp256k1Mingw by creatingBuildSecp256k1("mingw", if (currentOs.isWindows) null else Cross.DockCross("windows-x64"))

val copyJni by tasks.creating(Sync::class) {
    dependsOn(buildSecp256k1)
    from(projectDir.resolve("native/build/linux/libsecp256k1-jni.so")) { rename { "libsecp256k1-jni-linux-x86_64.so" } }
    from(projectDir.resolve("native/build/darwin/libsecp256k1-jni.dylib")) { rename { "libsecp256k1-jni-darwin-x86_64.dylib" } }
    from(projectDir.resolve("native/build/mingw/secp256k1-jni.dll")) { rename { "secp256k1-jni-mingw-x86_64.dll" } }
    into(buildDir.resolve("jniResources/fr/acinq/secp256k1/native"))
}

val buildSecp256k1Ios by tasks.creating(Exec::class) {
    group = "build"
    buildSecp256k1.dependsOn(this)

    onlyIf { currentOs.isMacOsX }

    inputs.files(projectDir.resolve("native/build-ios.sh"))
    outputs.dir(projectDir.resolve("native/build/ios"))

    workingDir = projectDir.resolve("native")
    commandLine("./build-ios.sh")
}

val buildSecp256k1Android by tasks.creating {
    group = "build"
    buildSecp256k1.dependsOn(this)
}
fun creatingBuildSecp256k1Android(arch: String) = tasks.creating(Exec::class) {
    group = "build"
    buildSecp256k1Android.dependsOn(this)

    inputs.files(projectDir.resolve("native/build-android.sh"))
    outputs.dir(projectDir.resolve("native/build/android/$arch"))

    workingDir = projectDir.resolve("native")

    val toolchain = when {
        currentOs.isLinux -> "linux-x86_64"
        currentOs.isMacOsX -> "darwin-x86_64"
        currentOs.isWindows -> "windows-x86_64"
        else -> error("No Android toolchain defined for this OS: $currentOs")
    }
    environment("TOOLCHAIN", toolchain)
    environment("ARCH", arch)
    environment("ANDROID_NDK", android.ndkDirectory)
    commandLine("./build-android.sh")
}
val buildSecp256k1AndroidX86_64 by creatingBuildSecp256k1Android("x86_64")
val buildSecp256k1AndroidX86 by creatingBuildSecp256k1Android("x86")
val buildSecp256k1AndroidArm64v8a by creatingBuildSecp256k1Android("arm64-v8a")
val buildSecp256k1AndroidArmeabiv7a by creatingBuildSecp256k1Android("armeabi-v7a")

afterEvaluate {
    configure(listOf("Debug", "Release").map { tasks["externalNativeBuild$it"] }) {
        dependsOn(buildSecp256k1Android)
    }
}

tasks["clean"].doLast {
    delete(projectDir.resolve("native/build"))
}

publishing {
    val snapshotName: String? by project
    val snapshotNumber: String? by project

    val bintrayUsername: String? = (properties["bintrayUsername"] as String?) ?: System.getenv("BINTRAY_USER")
    val bintrayApiKey: String? = (properties["bintrayApiKey"] as String?) ?: System.getenv("BINTRAY_APIKEY")
    if (bintrayUsername == null || bintrayApiKey == null) logger.warn("Skipping bintray configuration as bintrayUsername or bintrayApiKey is not defined")
    else {
        val btRepo = if (snapshotNumber != null) "snapshots" else "libs"
        repositories {
            maven {
                name = "bintray"
                setUrl("https://api.bintray.com/maven/acinq/$btRepo/${project.name}/;publish=0")
                credentials {
                    username = bintrayUsername
                    password = bintrayApiKey
                }
            }
        }
    }

    publications.withType<MavenPublication>().configureEach {
        if (snapshotName != null && snapshotNumber != null) version = "${project.version}-${snapshotName}-${snapshotNumber}"
        pom {
            description.set("Bitcoin's secp256k1 library ported to Kotlin/Multiplatform for JVM, Android, iOS & Linux")
            url.set("https://github.com/ACINQ/secp256k1-kmp")
            licenses {
                name.set("Apache License v2.0")
                url.set("https://www.apache.org/licenses/LICENSE-2.0")
            }
            issueManagement {
                system.set("Github")
                url.set("https://github.com/ACINQ/secp256k1-kmp/issues")
            }
            scm {
                connection.set("https://github.com/ACINQ/secp256k1-kmp.git")
            }
        }
    }
}
