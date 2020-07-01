plugins {
    kotlin("multiplatform") // version "1.4-M2-mt"
    id("com.android.library")
    `maven-publish`
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
        (tasks[compilations["main"].processResourcesTaskName] as ProcessResources).apply {
            dependsOn("copyJni")
            from(buildDir.resolve("jniResources"))
        }
        compilations["main"].dependencies {
            implementation(kotlin("stdlib-jdk8"))
        }
        compilations["test"].dependencies {
            implementation(kotlin("test-junit"))
        }
    }

    android {
        publishLibraryVariants("release", "debug")
        compilations.all {
            kotlinOptions.jvmTarget = "1.8"
        }
        sourceSets["androidMain"].dependencies {
            implementation(kotlin("stdlib-jdk8"))
        }
        sourceSets["androidTest"].dependencies {
            implementation(kotlin("test-junit"))
            implementation("androidx.test.ext:junit:1.1.1")
            implementation("androidx.test.espresso:espresso-core:3.2.0")
        }
    }

    sourceSets.all {
        languageSettings.useExperimentalAnnotation("kotlin.RequiresOptIn")
    }
}

android {
    defaultConfig {
        compileSdkVersion(30)
        minSdkVersion(21)
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        externalNativeBuild {
            cmake {}
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    externalNativeBuild {
        cmake {
            setPath("src/androidMain/CMakeLists.txt")
        }
    }
    ndkVersion = "21.3.6528147"

    sourceSets["main"].manifest.srcFile("src/androidMain/AndroidManifest.xml")

    afterEvaluate {
        tasks.withType<com.android.build.gradle.tasks.factory.AndroidUnitTest>().all {
            enabled = false
        }
    }
}

val copyJni by tasks.creating(Sync::class) {
    dependsOn(":native:buildSecp256k1Jvm")
    from(rootDir.resolve("native/build/linux/libsecp256k1-jni.so")) { rename { "libsecp256k1-jni-linux-x86_64.so" } }
    from(rootDir.resolve("native/build/darwin/libsecp256k1-jni.dylib")) { rename { "libsecp256k1-jni-darwin-x86_64.dylib" } }
    from(rootDir.resolve("native/build/mingw/secp256k1-jni.dll")) { rename { "secp256k1-jni-mingw-x86_64.dll" } }
    into(buildDir.resolve("jniResources/fr/acinq/secp256k1/jni/native"))
}

afterEvaluate {
    configure(listOf("Debug", "Release").map { tasks["externalNativeBuild$it"] }) {
        dependsOn(":native:buildSecp256k1Android")
    }
}
