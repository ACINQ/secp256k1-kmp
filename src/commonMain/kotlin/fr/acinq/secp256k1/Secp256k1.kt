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

public interface Secp256k1 {

    public fun verify(signature: ByteArray, data: ByteArray, pub: ByteArray): Boolean

    public fun sign(data: ByteArray, sec: ByteArray): ByteArray

    public fun signatureNormalize(sig: ByteArray): Pair<ByteArray, Boolean>

    public fun pubkeyCreate(seckey: ByteArray): ByteArray

    public fun pubkeyParse(pubkey: ByteArray): ByteArray

    public fun cleanup()

    public fun privKeyNegate(privkey: ByteArray): ByteArray

    public fun privKeyTweakMul(privkey: ByteArray, tweak: ByteArray): ByteArray

    public fun privKeyTweakAdd(privkey: ByteArray, tweak: ByteArray): ByteArray

    public fun pubKeyNegate(pubkey: ByteArray): ByteArray

    public fun pubKeyTweakAdd(pubkey: ByteArray, tweak: ByteArray): ByteArray

    public fun pubKeyTweakMul(pubkey: ByteArray, tweak: ByteArray): ByteArray

    public fun pubKeyAdd(pubkey1: ByteArray, pubkey2: ByteArray): ByteArray

    public fun ecdh(seckey: ByteArray, pubkey: ByteArray): ByteArray

    public fun ecdsaRecover(sig: ByteArray, message: ByteArray, recid: Int): ByteArray

    public companion object : Secp256k1 by getSecpk256k1() {
        @JvmStatic public fun get(): Secp256k1 = this
    }
}

internal expect fun getSecpk256k1(): Secp256k1

public class Secp256k1Exception : Exception {
    public constructor() : super() {}
    public constructor(message: String?) : super(message) {}
}