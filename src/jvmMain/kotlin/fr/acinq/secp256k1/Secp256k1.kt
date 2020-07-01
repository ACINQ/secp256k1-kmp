/*
 * Copyright 2020 ACINQ SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.acinq.secp256k1

import org.bitcoin.NativeSecp256k1
import java.lang.IllegalStateException

public actual object Secp256k1 {

    init {
        try {
            val cls = Class.forName("fr.acinq.secp256k1.jni.NativeSecp256k1Loader")
            val load = cls.getMethod("load")
            load.invoke(null)
        } catch (ex: ClassNotFoundException) {
            throw IllegalStateException("Could not load native Secp256k1 JNI library. Have you added the JNI dependency?", ex)
        }
    }

    public actual fun verify(data: ByteArray, signature: ByteArray, pub: ByteArray): Boolean = NativeSecp256k1.verify(data, signature, pub)

    public actual fun sign(data: ByteArray, sec: ByteArray, format: SigFormat): ByteArray = NativeSecp256k1.sign(data, sec, format == SigFormat.COMPACT)

    public actual fun signatureNormalize(sig: ByteArray, format: SigFormat): Pair<ByteArray, Boolean> = NativeSecp256k1.signatureNormalize(sig, format == SigFormat.COMPACT)

    public actual fun secKeyVerify(seckey: ByteArray): Boolean = NativeSecp256k1.secKeyVerify(seckey)

    public actual fun computePubkey(seckey: ByteArray, format: PubKeyFormat): ByteArray = NativeSecp256k1.computePubkey(seckey, format == PubKeyFormat.COMPRESSED)

    public actual fun parsePubkey(pubkey: ByteArray, format: PubKeyFormat): ByteArray = NativeSecp256k1.parsePubkey(pubkey, format == PubKeyFormat.COMPRESSED)

    public actual fun cleanup(): Unit = NativeSecp256k1.cleanup()

    public actual fun privKeyNegate(privkey: ByteArray): ByteArray = NativeSecp256k1.privKeyNegate(privkey)

    public actual fun privKeyTweakMul(privkey: ByteArray, tweak: ByteArray): ByteArray = NativeSecp256k1.privKeyTweakMul(privkey, tweak)

    public actual fun privKeyTweakAdd(privkey: ByteArray, tweak: ByteArray): ByteArray = NativeSecp256k1.privKeyTweakAdd(privkey, tweak)

    public actual fun pubKeyNegate(pubkey: ByteArray): ByteArray = NativeSecp256k1.pubKeyNegate(pubkey)

    public actual fun pubKeyTweakAdd(pubkey: ByteArray, tweak: ByteArray): ByteArray = NativeSecp256k1.pubKeyTweakAdd(pubkey, tweak)

    public actual fun pubKeyTweakMul(pubkey: ByteArray, tweak: ByteArray): ByteArray = NativeSecp256k1.pubKeyTweakMul(pubkey, tweak)

    public actual fun pubKeyAdd(pubkey1: ByteArray, pubkey2: ByteArray): ByteArray = NativeSecp256k1.pubKeyAdd(pubkey1, pubkey2)

    public actual fun createECDHSecret(seckey: ByteArray, pubkey: ByteArray): ByteArray = NativeSecp256k1.createECDHSecret(seckey, pubkey)

    public actual fun ecdsaRecover(sig: ByteArray, message: ByteArray, recid: Int, format: PubKeyFormat): ByteArray = NativeSecp256k1.ecdsaRecover(sig, message, recid, format == PubKeyFormat.COMPRESSED)

    public actual fun randomize(seed: ByteArray): Boolean = NativeSecp256k1.randomize(seed)

}
