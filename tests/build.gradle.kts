plugins {
    kotlin("multiplatform")
    id("com.android.library")
}

kotlin {
    explicitApi()

    val commonMain by sourceSets.getting {
        dependencies {
            implementation(kotlin("stdlib-common"))
            implementation(rootProject)
        }
    }
    val commonTest by sourceSets.getting {
        dependencies {
            implementation(kotlin("test-annotations-common"))
        }
    }

    jvm {
        compilations.all {
            kotlinOptions.jvmTarget = "1.8"
        }
        compilations["main"].dependencies {
            implementation(kotlin("stdlib-jdk8"))
            implementation(project(":jni:jvm:all"))
        }
        compilations["test"].dependencies {
            implementation(kotlin("test-junit"))
        }
    }

    android {
        compilations.all {
            kotlinOptions.jvmTarget = "1.8"
        }
        sourceSets["androidMain"].dependencies {
            implementation(kotlin("stdlib-jdk8"))
            implementation(project(":jni:android"))
        }
        sourceSets["androidTest"].dependencies {
            implementation(kotlin("test-junit"))
            implementation("androidx.test.ext:junit:1.1.1")
            implementation("androidx.test.espresso:espresso-core:3.2.0")
        }
    }

    linuxX64("linux")

    ios()
}

android {
    defaultConfig {
        compileSdkVersion(30)
        minSdkVersion(21)
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
