import org.gradle.kotlin.dsl.register
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm")
    id("org.jetbrains.dokka")
    `maven-publish`
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

dependencies {
    implementation(project(":jni:jvm"))
}

val copyJni by tasks.registering(Sync::class) {
    ->
    onlyIf { org.gradle.internal.os.OperatingSystem.current().isWindows }
    dependsOn(":jni:jvm:buildNativeHost")
    from(rootDir.resolve("jni/jvm/build/mingw/secp256k1-jni.dll"))
    into(layout.buildDirectory.dir("jniResources/fr/acinq/secp256k1/jni/native/mingw-x86_64"))
}

(tasks["processResources"] as ProcessResources).apply {
    onlyIf { org.gradle.internal.os.OperatingSystem.current().isWindows }
    dependsOn(copyJni)
    from(layout.buildDirectory.dir("jniResources"))
}

publishing {
    publications {
        val pub = create<MavenPublication>("jvm") {
            artifactId = "secp256k1-kmp-jni-jvm-mingw"
            from(components["java"])
            val sourcesJar = tasks.register<Jar>("sourcesJar") {
                archiveClassifier.set("sources")
            }
            artifact(sourcesJar)
        }
        if (!org.gradle.internal.os.OperatingSystem.current().isWindows) {
            tasks.withType<AbstractPublishToMaven>().all { onlyIf { publication != pub } }
        }
    }
}
