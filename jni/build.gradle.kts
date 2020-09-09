plugins {
    kotlin("jvm")
    `maven-publish`
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

kotlin {
    explicitApi()
}

dependencies {
    api(rootProject)
}

val generateHeaders by tasks.creating(JavaCompile::class) {
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

publishing {
    publications {
        create<MavenPublication>("jvm") {
            artifactId = "secp256k1-kmp-jni-common"
            from(components["java"])
        }
    }
}
