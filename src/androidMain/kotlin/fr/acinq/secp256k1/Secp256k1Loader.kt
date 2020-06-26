package fr.acinq.secp256k1

import java.io.*
import java.util.*

internal actual object Secp256k1Loader {

    @JvmStatic
    @Synchronized
    @Throws(Exception::class)
    actual fun initialize() {
        System.loadLibrary("secp256k1-jni")
    }

}
