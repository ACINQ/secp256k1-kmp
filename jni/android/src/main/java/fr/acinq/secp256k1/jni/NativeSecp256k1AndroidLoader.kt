package fr.acinq.secp256k1.jni

import android.util.Log
import fr.acinq.secp256k1.Secp256k1
import fr.acinq.secp256k1.NativeSecp256k1
import java.util.*

public object NativeSecp256k1AndroidLoader {
    @JvmStatic
    @Synchronized
    @Throws(Exception::class)
    public fun load(): Secp256k1 {
        try {
            System.loadLibrary("secp256k1-jni")
            return NativeSecp256k1
        } catch (ex: UnsatisfiedLinkError) {
            // Purposefully not using Android Log
            println("Could not load Android Secp256k1. Trying to extract JVM platform specific version.")
            try {
                val cls = Class.forName("fr.acinq.secp256k1.jni.NativeSecp256k1JvmLoader")
                val load = cls.getMethod("load")
                return load.invoke(null) as Secp256k1
            } catch (_: ClassNotFoundException) {
                throw ex
            }

        }
    }
}
