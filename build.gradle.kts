plugins {
    kotlin("multiplatform") version "1.4-M2-mt"
    `maven-publish`
}

buildscript {
    repositories {
        google()
        maven("https://dl.bintray.com/kotlin/kotlin-eap")
        jcenter()
    }

    dependencies {
        classpath("com.android.tools.build:gradle:4.0.0")
    }
}

allprojects {
    group = "fr.acinq.secp256k1"
    version = "0.1.0-1.4-M2"

    repositories {
        jcenter()
        google()
        maven(url = "https://dl.bintray.com/kotlin/kotlin-eap")
    }
}

val currentOs = org.gradle.internal.os.OperatingSystem.current()

kotlin {
    explicitApi()

    val commonMain by sourceSets.getting {
        dependencies {
            implementation(kotlin("stdlib-common"))
        }
    }
    val commonTest by sourceSets.getting {
        dependencies {
            implementation(kotlin("test-common"))
            implementation(kotlin("test-annotations-common"))
        }
    }

    jvm {
        compilations.all {
            kotlinOptions.jvmTarget = "1.8"
        }
        compilations["main"].dependencies {
            implementation(kotlin("stdlib-jdk8"))
        }
        compilations["test"].dependencies {
            implementation(project(":jni:jvm"))
            implementation(kotlin("stdlib-jdk8"))
            implementation(kotlin("test-junit"))
        }
    }

    fun org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget.secp256k1CInterop(target: String) {
        compilations["main"].cinterops {
            val libsecp256k1 by creating {
                includeDirs.headerFilterOnly(project.file("native/secp256k1/include/"))
                tasks[interopProcessingTaskName].dependsOn(":native:buildSecp256k1${target.capitalize()}")
            }
        }
    }

    val nativeMain by sourceSets.creating { dependsOn(commonMain) }

    linuxX64("linux") {
        secp256k1CInterop("linux")
        // https://youtrack.jetbrains.com/issue/KT-39396
        compilations["main"].kotlinOptions.freeCompilerArgs += listOf("-include-binary", "$rootDir/native/build/linux/libsecp256k1.a")
        compilations["main"].defaultSourceSet.dependsOn(nativeMain)
    }

    ios {
        secp256k1CInterop("ios")
        // https://youtrack.jetbrains.com/issue/KT-39396
        compilations["main"].kotlinOptions.freeCompilerArgs += listOf("-include-binary", "$rootDir/native/build/ios/libsecp256k1.a")
        compilations["main"].defaultSourceSet.dependsOn(nativeMain)
    }

    sourceSets.all {
        languageSettings.useExperimentalAnnotation("kotlin.RequiresOptIn")
    }

}

// Disable cross compilation
afterEvaluate {
    val currentOs = org.gradle.internal.os.OperatingSystem.current()
    val targets = when {
        currentOs.isLinux -> listOf()
        currentOs.isMacOsX -> listOf("linux")
        currentOs.isWindows -> listOf("linux")
        else -> listOf("linux")
    }.mapNotNull { kotlin.targets.findByName(it) as? org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget }

    configure(targets) {
        compilations.all {
            cinterops.all { tasks[interopProcessingTaskName].enabled = false }
            compileKotlinTask.enabled = false
            tasks[processResourcesTaskName].enabled = false
        }
        binaries.all { linkTask.enabled = false }

        mavenPublication {
            val publicationToDisable = this
            tasks.withType<AbstractPublishToMaven>().all { onlyIf { publication != publicationToDisable } }
            tasks.withType<GenerateModuleMetadata>().all { onlyIf { publication.get() != publicationToDisable } }
        }
    }
}

allprojects {
    plugins.withId("maven-publish") {
        publishing {
            val snapshotName: String? by project
            val snapshotNumber: String? by project

            val bintrayUsername: String? = (properties["bintrayUsername"] as String?) ?: System.getenv("BINTRAY_USER")
            val bintrayApiKey: String? = (properties["bintrayApiKey"] as String?) ?: System.getenv("BINTRAY_APIKEY")
            if (bintrayUsername == null || bintrayApiKey == null) logger.warn("Skipping bintray configuration as bintrayUsername or bintrayApiKey is not defined")
            else {
                val btRepo = if (snapshotNumber != null) "snapshots" else "libs"
                repositories {
                    maven {
                        name = "bintray"
                        setUrl("https://api.bintray.com/maven/acinq/$btRepo/${project.name}/;publish=0")
                        credentials {
                            username = bintrayUsername
                            password = bintrayApiKey
                        }
                    }
                }
            }

            publications.withType<MavenPublication>().configureEach {
                if (snapshotName != null && snapshotNumber != null) version = "${project.version}-${snapshotName}-${snapshotNumber}"
                pom {
                    description.set("Bitcoin's secp256k1 library ported to Kotlin/Multiplatform for JVM, Android, iOS & Linux")
                    url.set("https://github.com/ACINQ/secp256k1-kmp")
                    licenses {
                        name.set("Apache License v2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0")
                    }
                    issueManagement {
                        system.set("Github")
                        url.set("https://github.com/ACINQ/secp256k1-kmp/issues")
                    }
                    scm {
                        connection.set("https://github.com/ACINQ/secp256k1-kmp.git")
                    }
                }
            }
        }
    }
}
