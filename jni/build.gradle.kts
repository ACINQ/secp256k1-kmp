import org.gradle.kotlin.dsl.register
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm")
    id("org.jetbrains.dokka")
    `maven-publish`
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

kotlin {
    explicitApi()
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_1_8)
        // See https://jakewharton.com/kotlins-jdk-release-compatibility-flag/ and https://youtrack.jetbrains.com/issue/KT-49746/
        freeCompilerArgs.add("-Xjdk-release=1.8")
    }
}

dependencies {
    api(rootProject)
}

val generateHeaders by tasks.registering(JavaCompile::class) { ->
    group = "build"
    classpath = sourceSets["main"].compileClasspath
    destinationDirectory.set(layout.buildDirectory.dir("generated/jni"))
    source = sourceSets["main"].java
    options.compilerArgs = listOf(
        "-h", layout.buildDirectory.dir("generated./jni").get().asFile.absolutePath,
        "-d", layout.buildDirectory.dir("generated./jni-tmp").get().asFile.absolutePath
    )
    doLast {
        layout.buildDirectory.dir("generated/jni-tmp").get().asFile.delete()
    }
}

publishing {
    publications {
        create<MavenPublication>("jvm") {
            artifactId = "secp256k1-kmp-jni-common"
            from(components["java"])
            val sourcesJar = tasks.register<Jar>("sourcesJar") {
                archiveClassifier.set("sources")
                from(sourceSets["main"].allSource)
            }
            artifact(sourcesJar)
        }
    }
}
