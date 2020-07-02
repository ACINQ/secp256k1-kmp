pluginManagement {
    repositories {
        google()
        maven("https://dl.bintray.com/kotlin/kotlin-eap")
        gradlePluginPortal()
        jcenter()
    }
}
rootProject.name = "secp256k1-kmp"

include(
    ":native",
    ":jni",
    ":jni:android",
    ":jni:jvm",
    ":tests"
)