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

    /**
     * Verify an ECDSA signature.
     *
     * @param signature signature using either compact encoding (64 bytes) or der-encoding.
     * @param message message signed.
     * @param pubkey signer's public key.
     */
    public fun verify(signature: ByteArray, message: ByteArray, pubkey: ByteArray): Boolean

    /**
     * Create a normalized ECDSA signature.
     *
     * @param message message to sign.
     * @param privkey signer's private key.
     */
    public fun sign(message: ByteArray, privkey: ByteArray): ByteArray

    /**
     * Verify a Schnorr signature.
     *
     * @param signature 64 bytes signature.
     * @param data message signed.
     * @param pub signer's x-only public key (32 bytes).
     */
    public fun verifySchnorr(signature: ByteArray, data: ByteArray, pub: ByteArray): Boolean

    /**
     * Create a Schnorr signature.
     *
     * @param data message to sign.
     * @param sec signer's private key.
     * @param auxrand32 32 bytes of fresh randomness (optional).
     */
    public fun signSchnorr(data: ByteArray, sec: ByteArray, auxrand32: ByteArray?): ByteArray

   /**
     * Convert an ECDSA signature to a normalized lower-S form (bitcoin standardness rule).
     * Returns the normalized signature and a boolean set to true if the input signature was not normalized.
     *
     * @param sig signature that should be normalized.
     */
    public fun signatureNormalize(sig: ByteArray): Pair<ByteArray, Boolean>

    /**
     * Verify the validity of a private key.
     */
    public fun secKeyVerify(privkey: ByteArray): Boolean

    /**
     * Get the public key corresponding to the given private key.
     * Returns the uncompressed public key (65 bytes).
     */
    public fun pubkeyCreate(privkey: ByteArray): ByteArray

    /**
     * Parse a serialized public key.
     * Returns the uncompressed public key (65 bytes).
     */
    public fun pubkeyParse(pubkey: ByteArray): ByteArray

    /**
     * Negate the given private key.
     */
    public fun privKeyNegate(privkey: ByteArray): ByteArray

    /**
     * Tweak a private key by adding tweak to it.
     */
    public fun privKeyTweakAdd(privkey: ByteArray, tweak: ByteArray): ByteArray

    /**
     * Tweak a private key by multiplying it by a tweak.
     */
    public fun privKeyTweakMul(privkey: ByteArray, tweak: ByteArray): ByteArray

    /**
     * Negate the given public key.
     * Returns the uncompressed public key (65 bytes).
     */
    public fun pubKeyNegate(pubkey: ByteArray): ByteArray

    /**
     * Tweak a public key by adding tweak times the generator to it.
     * Returns the uncompressed public key (65 bytes).
     */
    public fun pubKeyTweakAdd(pubkey: ByteArray, tweak: ByteArray): ByteArray

    /**
     * Tweak a public key by multiplying it by a tweak value.
     * Returns the uncompressed public key (65 bytes).
     */
    public fun pubKeyTweakMul(pubkey: ByteArray, tweak: ByteArray): ByteArray

    /**
     * Add a number of public keys together.
     * Returns the uncompressed public key (65 bytes).
     */
    public fun pubKeyCombine(pubkeys: Array<ByteArray>): ByteArray

    /**
     * Compute an elliptic curve Diffie-Hellman secret.
     */
    public fun ecdh(privkey: ByteArray, pubkey: ByteArray): ByteArray

    /**
     * Recover a public key from an ECDSA signature.
     *
     * @param sig ecdsa compact signature (64 bytes).
     * @param message message signed.
     * @param recid recoveryId (should have been provided with the signature to allow recovery).
     */
    public fun ecdsaRecover(sig: ByteArray, message: ByteArray, recid: Int): ByteArray

    /**
     * Convert a compact ECDSA signature (64 bytes) to a der-encoded ECDSA signature.
     */
    public fun compact2der(sig: ByteArray): ByteArray

    /**
     * Serialize a public key to compact form (33 bytes).
     */
    public fun pubKeyCompress(pubkey: ByteArray): ByteArray {
        return when {
            pubkey.size == 33 && (pubkey[0] == 2.toByte() || pubkey[0] == 3.toByte()) -> pubkey
            pubkey.size == 65 && pubkey[0] == 4.toByte() -> {
                val compressed = pubkey.copyOf(33)
                compressed[0] = if (pubkey.last() % 2 == 0) 2.toByte() else 3.toByte()
                compressed
            }
            else -> throw Secp256k1Exception("invalid public key")
        }
    }

    /**
     * Delete the secp256k1 context from dynamic memory.
     */
    public fun cleanup()

    public companion object : Secp256k1 by getSecpk256k1() {
        @JvmStatic
        public fun get(): Secp256k1 = this
    }
}

internal expect fun getSecpk256k1(): Secp256k1

public class Secp256k1Exception : RuntimeException {
    public constructor() : super()
    public constructor(message: String?) : super(message)
}