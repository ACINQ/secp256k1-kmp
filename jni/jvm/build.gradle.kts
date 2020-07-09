plugins {
    kotlin("jvm")
    `maven-publish`
}

val currentOs = org.gradle.internal.os.OperatingSystem.current()
val bash = if (currentOs.isWindows) "bash.exe" else "bash"

val buildNativeHost by tasks.creating(Exec::class) {
    group = "build"
    dependsOn(":jni:generateHeaders")
    dependsOn(":native:buildSecp256k1Host")

    val target = when {
        currentOs.isLinux -> "linux"
        currentOs.isMacOsX -> "darwin"
        currentOs.isWindows -> "mingw"
        else -> error("Unsupported OS $currentOs")
    }

    inputs.files(projectDir.resolve("build.sh"))
    outputs.dir(buildDir.resolve(target))

    workingDir = projectDir
    environment("TARGET", target)
    commandLine(bash, "build.sh")
}

dependencies {
    api(project(":jni"))
    implementation(kotlin("stdlib-jdk8"))
}

publishing {
    publications {
        create<MavenPublication>("jvm") {
            artifactId = "secp256k1-jni-jvm-extract"
            from(components["java"])
        }
    }
}

afterEvaluate {
    tasks["clean"].doLast {
        delete("$buildDir/build/cmake")
    }
}
