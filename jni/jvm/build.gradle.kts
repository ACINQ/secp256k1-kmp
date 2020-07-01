plugins {
    kotlin("jvm")
}

kotlin {
    explicitApi()
}

dependencies {
    api(project(":jni"))
    implementation(kotlin("stdlib-jdk8"))
}

val copyJni by tasks.creating(Sync::class) {
    dependsOn(":native:buildSecp256k1Jvm")
    from(rootDir.resolve("native/build/linux/libsecp256k1-jni.so")) { rename { "libsecp256k1-jni-linux-x86_64.so" } }
    from(rootDir.resolve("native/build/darwin/libsecp256k1-jni.dylib")) { rename { "libsecp256k1-jni-darwin-x86_64.dylib" } }
    from(rootDir.resolve("native/build/mingw/secp256k1-jni.dll")) { rename { "secp256k1-jni-mingw-x86_64.dll" } }
    into(buildDir.resolve("jniResources/fr/acinq/secp256k1/jni/native"))
}

(tasks["processResources"] as ProcessResources).apply {
    dependsOn("copyJni")
    from(buildDir.resolve("jniResources"))
}
