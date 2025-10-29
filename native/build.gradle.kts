import com.android.build.gradle.LibraryExtension
import org.gradle.internal.os.OperatingSystem

val includeAndroid = System.getProperty("includeAndroid")?.toBoolean() ?: true

if (includeAndroid) {
    evaluationDependsOn(":jni:android")
}

val currentOs = OperatingSystem.current()
val bash = "bash"

val buildSecp256k1 = tasks.register("buildSecp256k1") {
    group = "build"
    dependsOn("buildSecp256k1Host")
}

tasks.register<Exec>("buildSecp256k1Host") {
    group = "build"

    val target = when {
        currentOs.isLinux -> "linux"
        currentOs.isMacOsX -> "darwin"
        currentOs.isWindows -> "mingw"
        else -> error("Unsupported OS $currentOs")
    }

    inputs.files(projectDir.resolve("build.sh"))
    outputs.dir(projectDir.resolve("build/$target"))

    workingDir = projectDir
    environment("TARGET", target)
    commandLine(bash, "-l", "build.sh")
}


// specific build task for linux arm64, which is cross-compiled on a linux x64 host
tasks.register<Exec>("buildSecp256k1LinuxArm64") {
    group = "build"

    val target = "linuxArm64"

    inputs.files(projectDir.resolve("build.sh"))
    outputs.dir(projectDir.resolve("build/$target"))

    workingDir = projectDir
    environment("TARGET", target)
    commandLine(bash, "-l", "build.sh")
}

tasks.register<Exec>("buildSecp256k1Ios") {
    group = "build"

    onlyIf { currentOs.isMacOsX }

    inputs.files(projectDir.resolve("build-ios.sh"))
    outputs.dir(projectDir.resolve("build/ios"))

    workingDir = projectDir
    commandLine(bash, "build-ios.sh")
}

if (includeAndroid) {
    tasks.register("buildSecp256k1Android") {
        group = "build"
        dependsOn("buildSecp256k1Androidx86_64")
        dependsOn("buildSecp256k1Androidx86")
        dependsOn("buildSecp256k1Androidarm64-v8a")
        dependsOn("buildSecp256k1Androidarmeabi-v7a")
    }

    buildSecp256k1 { dependsOn("buildSecp256k1Android") }

    fun createBuildSecp256k1Android(arch: String) = tasks.register<Exec>("buildSecp256k1Android$arch") {
        group = "build"

        inputs.files(projectDir.resolve("build-android.sh"))
        outputs.dir(projectDir.resolve("build/android/$arch"))

        workingDir = projectDir

        val toolchain = when {
            currentOs.isLinux -> "linux-x86_64"
            currentOs.isMacOsX -> "darwin-x86_64"
            currentOs.isWindows -> "windows-x86_64"
            else -> error("No Android toolchain defined for this OS: $currentOs")
        }
        environment("TOOLCHAIN", toolchain)
        environment("ARCH", arch)
        environment("ANDROID_NDK", (project(":jni:android").extensions["android"] as LibraryExtension).ndkDirectory)
        commandLine(bash, "build-android.sh")
    }

    createBuildSecp256k1Android("x86_64")
    createBuildSecp256k1Android("x86")
    createBuildSecp256k1Android("arm64-v8a")
    createBuildSecp256k1Android("armeabi-v7a")
}

val clean by tasks.registering {
    group = "build"
    doLast {
        delete(projectDir.resolve("build"))
    }
}
