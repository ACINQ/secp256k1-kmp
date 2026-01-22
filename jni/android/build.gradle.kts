import org.gradle.kotlin.dsl.register
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.library")
    kotlin("android")
    id("org.jetbrains.dokka")
    `maven-publish`
}

kotlin {
    explicitApi()
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_1_8)
        // Setting freeCompilerArgs.add("-Xjdk-release=1.8" is not needed here because android builds are different from jvm builds
    }
}

dependencies {
    api(project(":jni"))
}

android {
    namespace = "fr.acinq.secp256k1.jni"

    defaultConfig {
        compileSdk = 35
        minSdk = 21
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    externalNativeBuild {
        cmake {
            version = "3.31.5"
            path("src/main/CMakeLists.txt")
        }
    }

    ndkVersion = "28.2.13676358"

    afterEvaluate {
        tasks.withType<com.android.build.gradle.tasks.factory.AndroidUnitTest>().all {
            enabled = false
        }
    }

    publishing {
        singleVariant("release")
    }
}

afterEvaluate {
    tasks.filter { it.name.startsWith("configureCMake") }.forEach {
        it.dependsOn(":native:buildSecp256k1Android")
    }
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("android") {
                artifactId = "secp256k1-kmp-jni-android"
                from(components["release"])
                val sourcesJar = tasks.register<Jar>("sourcesJar") {
                    archiveClassifier.set("sources")
                    from(android.sourceSets["main"].java.srcDirs)
                }
                artifact(sourcesJar)
            }
        }
    }
}
