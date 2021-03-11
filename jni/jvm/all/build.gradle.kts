plugins {
    `java-library`
    id("org.jetbrains.dokka")
    `maven-publish`
}

dependencies {
    api(project(":jni:jvm:darwin"))
    api(project(":jni:jvm:linux"))
    api(project(":jni:jvm:mingw"))
}

publishing {
    publications {
        create<MavenPublication>("jvm") {
            artifactId = "secp256k1-kmp-jni-jvm"
            from(components["java"])
            val sourcesJar = task<Jar>("sourcesJar") {
                archiveClassifier.set("sources")
            }
            artifact(sourcesJar)
        }
    }
}
