plugins {
    kotlin("multiplatform")
    if (System.getProperty("includeAndroid")?.toBoolean() == true) {
        id("com.android.library")
    }
}

kotlin {
    explicitApi()

    val includeAndroid = System.getProperty("includeAndroid")?.toBoolean() ?: true

    val commonMain by sourceSets.getting {
        dependencies {
            implementation(rootProject)
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
            implementation(project(":jni:jvm:all"))
        }
        compilations["test"].dependencies {
            implementation(kotlin("test-junit"))
        }
    }

    if (includeAndroid) {
        androidTarget {
            compilations.all {
                kotlinOptions.jvmTarget = "1.8"
            }
            sourceSets["androidMain"].dependencies {
                implementation(project(":jni:android"))
            }
            sourceSets["androidUnitTest"].dependencies {
                implementation(kotlin("test-junit"))
                implementation("androidx.test.ext:junit:1.1.2")
                implementation("androidx.test.espresso:espresso-core:3.3.0")
            }
        }
    }

    linuxX64()
    iosX64()
    iosArm64()
    iosSimulatorArm64()
}

val includeAndroid = System.getProperty("includeAndroid")?.toBoolean() ?: true
if (includeAndroid) {
    extensions.configure<com.android.build.gradle.LibraryExtension>("android") {
        defaultConfig {
            compileSdk = 30
            minSdk = 21
            testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        }

        compileOptions {
            sourceCompatibility = JavaVersion.VERSION_1_8
            targetCompatibility = JavaVersion.VERSION_1_8
        }

        sourceSets["main"].manifest.srcFile("src/androidMain/AndroidManifest.xml")

        afterEvaluate {
            tasks.withType<com.android.build.gradle.tasks.factory.AndroidUnitTest>().all {
                enabled = false
            }
        }
    }
}