# Keep JNI loader used via reflection on Android; prevents R8 stripping.
# Intentionally broader than Android’s guidance: this is a tiny JNI wrapper and
# APK size is dominated by native libs, so simplicity/maintainability wins.
-keep class fr.acinq.secp256k1.jni.** { *; }
