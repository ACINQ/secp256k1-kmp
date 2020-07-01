package fr.acinq.secp256k1.jni

import fr.acinq.secp256k1.Secp256k1


public expect object NativeSecp256k1Loader {

    public fun load(): Secp256k1

}
