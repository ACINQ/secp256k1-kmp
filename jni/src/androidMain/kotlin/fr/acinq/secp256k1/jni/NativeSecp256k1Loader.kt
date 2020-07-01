package fr.acinq.secp256k1.jni

import fr.acinq.secp256k1.Secp256k1
import org.bitcoin.NativeSecp256k1

public actual object NativeSecp256k1Loader {

    @JvmStatic
    @Synchronized
    @Throws(Exception::class)
    actual fun load(): Secp256k1 {
        System.loadLibrary("secp256k1-jni")
        return NativeSecp256k1
    }

}
