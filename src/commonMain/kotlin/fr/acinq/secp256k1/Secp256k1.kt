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
     * Generate a secret nonce to be used in a musig2 signing session.
     * This nonce must never be persisted or reused across signing sessions.
     * All optional arguments exist to enrich the quality of the randomness used, which is critical for security.
     *
     * @param sessionRandom32 unique 32-byte random data that must not be reused to generate other nonces
     * @param privkey (optional) signer's private key.
     * @param pubkey signer's public key
     * @param msg32 (optional) 32-byte message that will be signed, if already known.
     * @param keyaggCache (optional) key aggregation cache data from the signing session.
     * @param extraInput32 (optional) additional 32-byte random data.
     * @return serialized version of the secret nonce and the corresponding public nonce.
     */
    public fun musigNonceGen(sessionRandom32: ByteArray, privkey: ByteArray?, pubkey: ByteArray, msg32: ByteArray?, keyaggCache: ByteArray?, extraInput32: ByteArray?): ByteArray

    /**
     * Alternative counter-based method for generating nonce.
     * This nonce must never be persisted or reused across signing sessions.
     * All optional arguments exist to enrich the quality of the randomness used, which is critical for security.
     *
     * @param nonRepeatingCounter non-repeating counter that must never be reused with the same private key
     * @param privkey signer's private key.
     * @param msg32 (optional) 32-byte message that will be signed, if already known.
     * @param keyaggCache (optional) key aggregation cache data from the signing session.
     * @param extraInput32 (optional) additional 32-byte random data.
     * @return serialized version of the secret nonce and the corresponding public nonce.
     */
    public fun musigNonceGenCounter(nonRepeatingCounter: ULong, privkey: ByteArray, msg32: ByteArray?, keyaggCache: ByteArray?, extraInput32: ByteArray?): ByteArray

    /**
     * Aggregate public nonces from all participants of a signing session.
     *
     * @param pubnonces public nonces (one per participant).
     * @return 66-byte aggregate public nonce (two public keys) or throws an exception is a nonce is invalid.
     */
    public fun musigNonceAgg(pubnonces: Array<ByteArray>): ByteArray

    /**
     * Aggregate public keys from all participants of a signing session.
     *
     * @param pubkeys public keys of all participants in the signing session.
     * @param keyaggCache (optional) key aggregation cache data from the signing session. If an empty byte array is
     * provided, it will be filled with key aggregation data that can be used for the next steps of the signing process.
     * @return 32-byte x-only public key.
     */
    public fun musigPubkeyAgg(pubkeys: Array<ByteArray>, keyaggCache: ByteArray?): ByteArray

    /**
     * Tweak the aggregated public key of a signing session.
     *
     * @param keyaggCache key aggregation cache filled by [musigPubkeyAgg].
     * @param tweak32 private key tweak to apply.
     * @return P + tweak32 * G (where P is the aggregated public key from [keyaggCache]). The key aggregation cache will
     * be updated with the tweaked public key.
     */
    public fun musigPubkeyTweakAdd(keyaggCache: ByteArray, tweak32: ByteArray): ByteArray

    /**
     * Tweak the aggregated public key of a signing session, treating it as an x-only public key (e.g. when using taproot).
     *
     * @param keyaggCache key aggregation cache filled by [musigPubkeyAgg].
     * @param tweak32 private key tweak to apply.
     * @return with_even_y(P) + tweak32 * G (where P is the aggregated public key from [keyaggCache]). The key aggregation
     * cache will be updated with the tweaked public key.
     */
    public fun musigPubkeyXonlyTweakAdd(keyaggCache: ByteArray, tweak32: ByteArray): ByteArray

    /**
     * Create a signing session context based on the public information from all participants.
     *
     * @param aggnonce aggregated public nonce (see [musigNonceAgg]).
     * @param msg32 32-byte message that will be signed.
     * @param keyaggCache aggregated public key cache filled by calling [musigPubkeyAgg] with the public keys of all participants.
     * @return signing session context that can be used to create partial signatures and aggregate them.
     */
    public fun musigNonceProcess(aggnonce: ByteArray, msg32: ByteArray, keyaggCache: ByteArray): ByteArray

    /**
     * Check that a secret nonce was generated with a public key that matches the private key used for signing.
     * @param secretnonce secret nonce.
     * @param pubkey public key for the private key that will be used, with the secret nonce, to generate a partial signature.
     * @return false if the secret nonce does not match the public key.
     */
    public fun musigNonceValidate(secretnonce: ByteArray, pubkey: ByteArray): Boolean {
        if (secretnonce.size != MUSIG2_SECRET_NONCE_SIZE) return false
        if (pubkey.size != 33 && pubkey.size != 65) return false
        val pk = Secp256k1.pubkeyParse(pubkey)
        // this is a bit hackish but the secp256k1 library does not export methods to do this cleanly
        val x = secretnonce.copyOfRange(68, 68 + 32)
        x.reverse()
        val y = secretnonce.copyOfRange(68 + 32, 68 + 32 + 32)
        y.reverse()
        val pkx = pk.copyOfRange(1, 1 + 32)
        val pky = pk.copyOfRange(33, 33 + 32)
        return x.contentEquals(pkx) && y.contentEquals(pky)
    }

    /**
     * Create a partial signature.
     *
     * @param secnonce signer's secret nonce (see [musigNonceGen]).
     * @param privkey signer's private key.
     * @param keyaggCache aggregated public key cache filled by calling [musigPubkeyAgg] with the public keys of all participants.
     * @param session signing session context (see [musigNonceProcess]).
     * @return 32-byte partial signature.
     */
    public fun musigPartialSign(secnonce: ByteArray, privkey: ByteArray, keyaggCache: ByteArray, session: ByteArray): ByteArray

    /**
     * Verify the partial signature from one of the signing session's participants.
     *
     * @param psig 32-byte partial signature.
     * @param pubnonce individual public nonce of the signing participant.
     * @param pubkey individual public key of the signing participant.
     * @param keyaggCache aggregated public key cache filled by calling [musigPubkeyAgg] with the public keys of all participants.
     * @param session signing session context (see [musigNonceProcess]).
     * @return result code (1 if the partial signature is valid, 0 otherwise).
     */
    public fun musigPartialSigVerify(psig: ByteArray, pubnonce: ByteArray, pubkey: ByteArray, keyaggCache: ByteArray, session: ByteArray): Int

    /**
     * Aggregate partial signatures from all participants into a single schnorr signature. If some of the partial
     * signatures are invalid, this function will return an invalid aggregated signature without raising an error.
     * It is recommended to use [musigPartialSigVerify] to verify partial signatures first.
     *
     * @param session signing session context (see [musigNonceProcess]).
     * @param psigs list of 32-byte partial signatures.
     * @return 64-byte aggregated schnorr signature.
     */
    public fun musigPartialSigAgg(session: ByteArray, psigs: Array<ByteArray>): ByteArray

    /**
     * Delete the secp256k1 context from dynamic memory.
     */
    public fun cleanup()

    public companion object : Secp256k1 by getSecpk256k1() {
        @JvmStatic
        public fun get(): Secp256k1 = this

        // @formatter:off
        public const val MUSIG2_SECRET_NONCE_SIZE: Int = 132
        public const val MUSIG2_PUBLIC_NONCE_SIZE: Int = 66
        public const val MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE: Int = 197
        public const val MUSIG2_PUBLIC_SESSION_SIZE: Int = 133
        // @formatter:on
    }
}

internal expect fun getSecpk256k1(): Secp256k1

public class Secp256k1Exception : RuntimeException {
    public constructor() : super()
    public constructor(message: String?) : super(message)
}