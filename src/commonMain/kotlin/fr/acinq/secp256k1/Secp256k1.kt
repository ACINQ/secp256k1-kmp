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

public enum class SigFormat(internal val size: Int) { COMPACT(64), DER(72) }

public enum class PubKeyFormat(internal val size: Int) { COMPRESSED(33), UNCOMPRESSED(65) }

public expect object Secp256k1 {

    @JvmStatic
    public fun verify(data: ByteArray, signature: ByteArray, pub: ByteArray): Boolean

    @JvmStatic
    public fun sign(data: ByteArray, sec: ByteArray, format: SigFormat): ByteArray

    @JvmStatic
    public fun signatureNormalize(sig: ByteArray, format: SigFormat): Pair<ByteArray, Boolean>

    @JvmStatic
    public fun secKeyVerify(seckey: ByteArray): Boolean

    @JvmStatic
    public fun computePubkey(seckey: ByteArray, format: PubKeyFormat): ByteArray

    @JvmStatic
    public fun parsePubkey(pubkey: ByteArray, format: PubKeyFormat): ByteArray

    @JvmStatic
    public fun cleanup()

    @JvmStatic
    public fun privKeyNegate(privkey: ByteArray): ByteArray

    @JvmStatic
    public fun privKeyTweakMul(privkey: ByteArray, tweak: ByteArray): ByteArray

    @JvmStatic
    public fun privKeyTweakAdd(privkey: ByteArray, tweak: ByteArray): ByteArray

    @JvmStatic
    public fun pubKeyNegate(pubkey: ByteArray): ByteArray

    @JvmStatic
    public fun pubKeyTweakAdd(pubkey: ByteArray, tweak: ByteArray): ByteArray

    @JvmStatic
    public fun pubKeyTweakMul(pubkey: ByteArray, tweak: ByteArray): ByteArray

    @JvmStatic
    public fun pubKeyAdd(pubkey1: ByteArray, pubkey2: ByteArray): ByteArray

    @JvmStatic
    public fun createECDHSecret(seckey: ByteArray, pubkey: ByteArray): ByteArray

    @JvmStatic
    public fun ecdsaRecover(sig: ByteArray, message: ByteArray, recid: Int, format: PubKeyFormat): ByteArray

    @JvmStatic
    public fun randomize(seed: ByteArray): Boolean
}