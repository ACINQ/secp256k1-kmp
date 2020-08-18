pluginManagement {
    repositories {
        google()
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