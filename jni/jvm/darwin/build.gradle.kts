plugins {
    kotlin("jvm")
    `java-library`
    id("org.jetbrains.dokka")
    `maven-publish`
}

dependencies {
    implementation(project(":jni:jvm"))
}

val copyJni by tasks.creating(Sync::class) {
    onlyIf { org.gradle.internal.os.OperatingSystem.current().isMacOsX }
    dependsOn(":jni:jvm:buildNativeHost")
    val arch = when (System.getProperty("os.arch")) {
        "aarch64" -> "aarch64"
        else -> "x86_64"
    }
    from(rootDir.resolve("jni/jvm/build/darwin/libsecp256k1-jni.dylib"))
    into(buildDir.resolve("jniResources/fr/acinq/secp256k1/jni/native/darwin-$arch"))
}

(tasks["processResources"] as ProcessResources).apply {
    onlyIf { org.gradle.internal.os.OperatingSystem.current().isMacOsX }
    dependsOn(copyJni)
    from(buildDir.resolve("jniResources"))
}

publishing {
    publications {
        val pub = create<MavenPublication>("jvm") {
            artifactId = "secp256k1-kmp-jni-jvm-darwin"
            from(components["java"])
            val sourcesJar = task<Jar>("sourcesJar") {
                archiveClassifier.set("sources")
            }
            artifact(sourcesJar)
        }
        if (!org.gradle.internal.os.OperatingSystem.current().isMacOsX) {
            tasks.withType<AbstractPublishToMaven>().all { onlyIf { publication != pub } }
        }
    }
}
