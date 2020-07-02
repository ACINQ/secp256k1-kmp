plugins {
    kotlin("jvm")
    `maven-publish`
}

kotlin {
    explicitApi()
}

dependencies {
    api(project(":jni"))
    implementation(kotlin("stdlib-jdk8"))
}

val copyJni by tasks.creating(Sync::class) {
    dependsOn(":jni:buildNativeJni")
    from(rootDir.resolve("jni/build/jni/linux/libsecp256k1-jni.so")) { rename { "libsecp256k1-jni-linux-x86_64.so" } }
    from(rootDir.resolve("jni/build/jni/darwin/libsecp256k1-jni.dylib")) { rename { "libsecp256k1-jni-darwin-x86_64.dylib" } }
    from(rootDir.resolve("jni/build/jni/mingw/secp256k1-jni.dll")) { rename { "secp256k1-jni-mingw-x86_64.dll" } }
    into(buildDir.resolve("jniResources/fr/acinq/secp256k1/jni/native"))
}

(tasks["processResources"] as ProcessResources).apply {
    dependsOn("copyJni")
    from(buildDir.resolve("jniResources"))
}

java.withSourcesJar()

publishing {
    publications {
        create<MavenPublication>("jvm") {
            artifactId = "secp256k1-jni-jvm"
            from(components["java"])
        }
    }
}
