package fr.acinq.secp256k1.jni

import fr.acinq.secp256k1.Secp256k1
import fr.acinq.secp256k1.NativeSecp256k1

public object NativeSecp256k1Loader {

    @JvmStatic
    @Synchronized
    @Throws(Exception::class)
    fun load(): Secp256k1 {
        System.loadLibrary("secp256k1-jni")
        return NativeSecp256k1
    }

}
