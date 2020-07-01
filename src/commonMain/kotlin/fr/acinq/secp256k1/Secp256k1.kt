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

import kotlin.jvm.JvmStatic

public enum class SigFormat(public val maxSize: Int) { COMPACT(64), DER(72) }

public enum class PubKeyFormat(public val maxSize: Int) { COMPRESSED(33), UNCOMPRESSED(65) }

public interface Secp256k1 {

    public fun verify(data: ByteArray, signature: ByteArray, pub: ByteArray): Boolean

    public fun sign(data: ByteArray, sec: ByteArray, format: SigFormat): ByteArray

    public fun signatureNormalize(sig: ByteArray, format: SigFormat): Pair<ByteArray, Boolean>

    public fun secKeyVerify(seckey: ByteArray): Boolean

    public fun computePubkey(seckey: ByteArray, format: PubKeyFormat): ByteArray

    public fun parsePubkey(pubkey: ByteArray, format: PubKeyFormat): ByteArray

    public fun cleanup()

    public fun privKeyNegate(privkey: ByteArray): ByteArray

    public fun privKeyTweakMul(privkey: ByteArray, tweak: ByteArray): ByteArray

    public fun privKeyTweakAdd(privkey: ByteArray, tweak: ByteArray): ByteArray

    public fun pubKeyNegate(pubkey: ByteArray): ByteArray

    public fun pubKeyTweakAdd(pubkey: ByteArray, tweak: ByteArray): ByteArray

    public fun pubKeyTweakMul(pubkey: ByteArray, tweak: ByteArray): ByteArray

    public fun pubKeyAdd(pubkey1: ByteArray, pubkey2: ByteArray): ByteArray

    public fun createECDHSecret(seckey: ByteArray, pubkey: ByteArray): ByteArray

    public fun ecdsaRecover(sig: ByteArray, message: ByteArray, recid: Int, format: PubKeyFormat): ByteArray

    public fun randomize(seed: ByteArray): Boolean

    public companion object : Secp256k1 by getSecpk256k1() {
        @JvmStatic public fun get(): Secp256k1 = this
    }
}

internal expect fun getSecpk256k1(): Secp256k1
