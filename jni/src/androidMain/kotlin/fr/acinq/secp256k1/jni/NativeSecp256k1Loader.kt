package fr.acinq.secp256k1.jni

public actual object NativeSecp256k1Loader {

    @JvmStatic
    @Synchronized
    @Throws(Exception::class)
    actual fun load() {
        System.loadLibrary("secp256k1-jni")
    }

}
