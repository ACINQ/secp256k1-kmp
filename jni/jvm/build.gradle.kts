import org.gradle.kotlin.dsl.register
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm")
    id("org.jetbrains.dokka")
    `maven-publish`
}

val currentOs = org.gradle.internal.os.OperatingSystem.current()
val bash = if (currentOs.isWindows) "bash.exe" else "bash"

val buildNativeHost by tasks.registering(Exec::class) {
    ->
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
    outputs.dir(layout.buildDirectory.dir(target))

    workingDir = projectDir
    environment("TARGET", target)
    commandLine(bash, "build.sh")
}

dependencies {
    api(project(":jni"))
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_1_8)
        // See https://jakewharton.com/kotlins-jdk-release-compatibility-flag/ and https://youtrack.jetbrains.com/issue/KT-49746/
        freeCompilerArgs.add("-Xjdk-release=1.8")
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

publishing {
    publications {
        create<MavenPublication>("jvm") {
            artifactId = "secp256k1-kmp-jni-jvm-extract"
            from(components["java"])
            val sourcesJar = tasks.register<Jar>("sourcesJar") {
                archiveClassifier.set("sources")
            }
            artifact(sourcesJar)
        }
    }
}

afterEvaluate {
    tasks["clean"].doLast {
        delete(layout.buildDirectory.dir("build/cmake"))
    }
}
