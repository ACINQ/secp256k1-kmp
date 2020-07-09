pluginManagement {
    repositories {
        google()
        maven("https://dl.bintray.com/kotlin/kotlin-eap")
        gradlePluginPortal()
        jcenter()
    }
}
rootProject.name = "secp256k1"

include(
    ":native",
    ":jni",
    ":jni:android",
    ":jni:jvm",
    ":jni:jvm:darwin",
    ":jni:jvm:linux",
    ":jni:jvm:mingw",
    ":jni:jvm:all",
    ":tests"
)