import org.gradle.internal.os.OperatingSystem
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import org.jetbrains.dokka.Platform

plugins {
    kotlin("multiplatform") version "1.6.21"
    id("org.jetbrains.dokka") version "1.6.21"
    `maven-publish`
}

buildscript {
    repositories {
        google()
        mavenCentral()
    }

    dependencies {
        classpath("com.android.tools.build:gradle:7.3.1")
        classpath("org.jetbrains.dokka:dokka-gradle-plugin:1.6.21")
    }
}

allprojects {
    group = "fr.acinq.secp256k1"
    version = "0.9.0-SNAPSHOT"

    repositories {
        google()
        mavenCentral()
    }
}

val currentOs = OperatingSystem.current()

kotlin {
    explicitApi()

    val commonMain by sourceSets.getting

    jvm {
        compilations.all {
            kotlinOptions.jvmTarget = "1.8"
        }
    }

    fun KotlinNativeTarget.secp256k1CInterop(target: String) {
        compilations["main"].cinterops {
            val libsecp256k1 by creating {
                includeDirs.headerFilterOnly(project.file("native/secp256k1/include/"))
                tasks[interopProcessingTaskName].dependsOn(":native:buildSecp256k1${target.capitalize()}")
            }
        }
    }

    val nativeMain by sourceSets.creating { dependsOn(commonMain) }

    linuxX64("linux") {
        secp256k1CInterop("host")
        compilations["main"].defaultSourceSet.dependsOn(nativeMain)
        // https://youtrack.jetbrains.com/issue/KT-39396
        compilations["main"].kotlinOptions.freeCompilerArgs += listOf("-include-binary", "$rootDir/native/build/linux/libsecp256k1.a")
    }

    ios {
        secp256k1CInterop("ios")
        compilations["main"].defaultSourceSet.dependsOn(nativeMain)
        // https://youtrack.jetbrains.com/issue/KT-39396
        compilations["main"].kotlinOptions.freeCompilerArgs += listOf("-include-binary", "$rootDir/native/build/ios/libsecp256k1.a")
    }

    sourceSets.all {
        languageSettings.optIn("kotlin.RequiresOptIn")
    }
}

// Disable cross compilation
allprojects {
    plugins.withId("org.jetbrains.kotlin.multiplatform") {
        afterEvaluate {
            val currentOs = OperatingSystem.current()
            val targets = when {
                currentOs.isLinux -> listOf()
                currentOs.isMacOsX -> listOf("linux")
                currentOs.isWindows -> listOf("linux")
                else -> listOf("linux")
            }.mapNotNull { kotlin.targets.findByName(it) as? KotlinNativeTarget }

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
    }
}

allprojects {
    val javadocJar = tasks.create<Jar>("javadocJar") {
        archiveClassifier.set("javadoc")
        duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    }

    // Publication
    plugins.withId("maven-publish") {
        publishing {
            publications.withType<MavenPublication>().configureEach {
                version = project.version.toString()
                artifact(javadocJar)
                pom {
                    name.set("secp256k1 for Kotlin/Multiplatform")
                    description.set("Bitcoin's secp256k1 library ported to Kotlin/Multiplatform for JVM, Android, iOS & Linux")
                    url.set("https://github.com/ACINQ/secp256k1-kmp")
                    licenses {
                        license {
                            name.set("Apache License v2.0")
                            url.set("https://www.apache.org/licenses/LICENSE-2.0")
                        }
                    }
                    issueManagement {
                        system.set("Github")
                        url.set("https://github.com/ACINQ/secp256k1-kmp/issues")
                    }
                    scm {
                        connection.set("https://github.com/ACINQ/secp256k1-kmp.git")
                        url.set("https://github.com/ACINQ/secp256k1-kmp")
                    }
                    developers {
                        developer {
                            name.set("ACINQ")
                            email.set("hello@acinq.co")
                        }
                    }
                }
            }
        }
    }

    if (project.name !in listOf("native", "tests")) {
        afterEvaluate {
            val dokkaOutputDir = buildDir.resolve("dokka")

            tasks.dokkaHtml {
                outputDirectory.set(file(dokkaOutputDir))
                dokkaSourceSets {
                    configureEach {
                        val platformName = when (platform.get()) {
                            Platform.jvm -> "jvm"
                            Platform.js -> "js"
                            Platform.native -> "native"
                            Platform.common -> "common"
                        }
                        displayName.set(platformName)

                        perPackageOption {
                            matchingRegex.set(".*\\.internal.*") // will match all .internal packages and sub-packages
                            suppress.set(true)
                        }
                    }
                }
            }

            val deleteDokkaOutputDir by tasks.register<Delete>("deleteDokkaOutputDirectory") {
                delete(dokkaOutputDir)
            }

            javadocJar.dependsOn(deleteDokkaOutputDir, tasks.dokkaHtml)
            javadocJar.from(dokkaOutputDir)
        }
    }
}

allprojects {
    afterEvaluate {
        tasks.withType<AbstractTestTask>() {
            testLogging {
                events("passed", "skipped", "failed", "standard_out", "standard_error")
                showExceptions = true
                showStackTraces = true
            }
        }
    }
}
