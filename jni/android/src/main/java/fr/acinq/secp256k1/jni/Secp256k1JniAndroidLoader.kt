package fr.acinq.secp256k1.jni

import android.util.Log
import fr.acinq.secp256k1.Secp256k1
import fr.acinq.secp256k1.Secp256k1Jni
import java.util.*

public object Secp256k1JniAndroidLoader {
    @JvmStatic
    @Synchronized
    @Throws(Exception::class)
    public fun load(): Secp256k1 {
        try {
            System.loadLibrary("secp256k1-jni")
            return Secp256k1Jni
        } catch (ex: UnsatisfiedLinkError) {
            // Purposefully not using Android Log
            println("Could not load Android Secp256k1. Trying to extract JVM platform specific version.")
            try {
                val cls = Class.forName("fr.acinq.secp256k1.jni.Secp256k1JniJvmLoader")
                val load = cls.getMethod("load")
                return load.invoke(null) as Secp256k1
            } catch (_: ClassNotFoundException) {
                throw ex
            }

        }
    }
}
