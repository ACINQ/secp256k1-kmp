plugins {
    kotlin("jvm")
    `maven-publish`
}

val currentOs = org.gradle.internal.os.OperatingSystem.current()

kotlin {
    explicitApi()
}

dependencies {
    api(rootProject)
    implementation(kotlin("stdlib-jdk8"))
}

val generateJniHeaders by tasks.creating(JavaCompile::class) {
    group = "build"
    classpath = sourceSets["main"].compileClasspath
    destinationDir = file("${buildDir}/generated/jni")
    source = sourceSets["main"].java
    options.compilerArgs = listOf(
        "-h", file("${buildDir}/generated/jni").absolutePath,
        "-d", file("${buildDir}/generated/jni-tmp").absolutePath
    )
    // options.verbose = true
    doLast {
        delete(file("${buildDir}/generated/jni-tmp"))
    }
}

sealed class Cross {
    abstract fun cmd(target: String, project: Project): List<String>
    class DockCross(val cross: String) : Cross() {
        override fun cmd(target: String, project: Project): List<String> = listOf("${project.rootDir}/cross-scripts/dockcross-$cross", "bash", "-c", "CROSS=1 TARGET=$target jni/build.sh")
    }
    class MultiArch(val crossTriple: String) : Cross() {
        override fun cmd(target: String, project: Project): List<String> {
            val uid = Runtime.getRuntime().exec("id -u").inputStream.use { it.reader().readText() }.trim().toInt()
            return listOf(
                "docker", "run", "--rm", "-v", "${project.rootDir.absolutePath}:/workdir",
                "-e", "CROSS_TRIPLE=$crossTriple", "-e", "TARGET=$target", "-e", "TO_UID=$uid", "-e", "CROSS=1",
                "multiarch/crossbuild", "jni/build.sh"
            )
        }
    }
}

val buildNativeJni by tasks.creating {
    group = "build"
}
val noCrossCompile: String? by project
fun creatingBuildNativeJni(target: String, cross: Cross?) = tasks.creating(Exec::class) {
    group = "build"
    dependsOn(generateJniHeaders)
    dependsOn(":native:buildSecp256k1${target.capitalize()}")
    buildNativeJni.dependsOn(this)

    if (noCrossCompile == "true") onlyIf { cross == null }

    inputs.files(projectDir.resolve("build.sh"))
    outputs.dir(buildDir.resolve("build/cmake/$target"))

    workingDir = rootDir
    environment("TARGET", target)
    commandLine((cross?.cmd(target, project) ?: emptyList()) + "jni/build.sh")
}
val buildNativeJniDarwin by creatingBuildNativeJni("darwin", if (currentOs.isMacOsX) null else Cross.MultiArch("x86_64-apple-darwin"))
val buildNativeJniLinux by creatingBuildNativeJni("linux", if (currentOs.isLinux) null else Cross.DockCross("linux-x64"))
val buildNativeJniMingw by creatingBuildNativeJni("mingw", if (currentOs.isWindows) null else Cross.DockCross("windows-x64"))

afterEvaluate {
    tasks["clean"].doLast {
        delete(buildDir.resolve("build/cmake"))
    }
}

publishing {
    publications {
        create<MavenPublication>("jvm") {
            artifactId = "secp256k1-jni-common"
            from(components["java"])
        }
    }
}
