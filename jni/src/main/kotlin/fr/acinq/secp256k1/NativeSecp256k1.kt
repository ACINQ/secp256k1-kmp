/*
 * Copyright 2013 Google Inc.
 * Copyright 2014-2016 the libsecp256k1 contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.acinq.secp256k1

public object NativeSecp256k1 : Secp256k1 {
    override fun verify(signature: ByteArray, message: ByteArray, pubkey: ByteArray): Boolean {
        require(signature.size == 64) { "signature must be 64 bytes" }
        require(message.size == 32) { "message must be 32 bytes" }
        require(pubkey.size == 33 || pubkey.size == 65) { "public key must be 33 or 65 bytes" }
        return Secp256k1CFunctions.secp256k1_ecdsa_verify(Secp256k1Context.getContext(), signature, message, pubkey) == 1
    }

    override fun sign(message: ByteArray, privkey: ByteArray, ndata: ByteArray?): ByteArray {
        require(privkey.size == 32) { "private key must be 32 bytes" }
        require(message.size == 32) { "message must be 32 bytes" }
        ndata?.let { require(it.size == 32) { "ndata must be 32 bytes" } }
        return Secp256k1CFunctions.secp256k1_ecdsa_sign(Secp256k1Context.getContext(), message, privkey, ndata)
    }

    override fun signatureNormalize(sig: ByteArray): Pair<ByteArray, Boolean> {
        require(sig.size == 64) { "signature must be 64 bytes" }
        val sigout = ByteArray(64)
        val result = Secp256k1CFunctions.secp256k1_ecdsa_signature_normalize(Secp256k1Context.getContext(), sig, sigout)
        return Pair(sigout, result == 1)
    }

    override fun secKeyVerify(privkey: ByteArray): Boolean {
        if (privkey.size != 32) return false
        return Secp256k1CFunctions.secp256k1_ec_seckey_verify(Secp256k1Context.getContext(), privkey) == 1
    }

    override fun pubkeyCreate(privkey: ByteArray): ByteArray {
        require(privkey.size == 32) { "private key must be 32 bytes" }
        return Secp256k1CFunctions.secp256k1_ec_pubkey_create(Secp256k1Context.getContext(), privkey)
    }

    override fun pubkeyParse(pubkey: ByteArray): ByteArray {
        require(pubkey.size == 33 || pubkey.size == 65) { "public key must be 33 or 65 bytes" }
        return Secp256k1CFunctions.secp256k1_ec_pubkey_parse(Secp256k1Context.getContext(), pubkey)
    }

    override fun privKeyNegate(privkey: ByteArray): ByteArray {
        require(privkey.size == 32) { "private key must be 32 bytes" }
        return Secp256k1CFunctions.secp256k1_ec_seckey_negate(Secp256k1Context.getContext(), privkey)
    }

    override fun privKeyTweakAdd(privkey: ByteArray, tweak: ByteArray): ByteArray {
        require(privkey.size == 32) { "private key must be 32 bytes" }
        require(tweak.size == 32) { "tweak must be 32 bytes" }
        return Secp256k1CFunctions.secp256k1_ec_seckey_tweak_add(Secp256k1Context.getContext(), privkey, tweak)
    }

    override fun privKeyTweakMul(privkey: ByteArray, tweak: ByteArray): ByteArray {
        require(privkey.size == 32) { "private key must be 32 bytes" }
        require(tweak.size == 32) { "tweak must be 32 bytes" }
        return Secp256k1CFunctions.secp256k1_ec_seckey_tweak_mul(Secp256k1Context.getContext(), privkey, tweak)
    }

    override fun pubKeyNegate(pubkey: ByteArray): ByteArray {
        require(pubkey.size == 33 || pubkey.size == 65) { "public key must be 33 or 65 bytes" }
        return Secp256k1CFunctions.secp256k1_ec_pubkey_negate(Secp256k1Context.getContext(), pubkey)
    }

    override fun pubKeyTweakAdd(pubkey: ByteArray, tweak: ByteArray): ByteArray {
        require(pubkey.size == 33 || pubkey.size == 65) { "public key must be 33 or 65 bytes" }
        require(tweak.size == 32) { "tweak must be 32 bytes" }
        return Secp256k1CFunctions.secp256k1_ec_pubkey_tweak_add(Secp256k1Context.getContext(), pubkey, tweak)
    }

    override fun pubKeyTweakMul(pubkey: ByteArray, tweak: ByteArray): ByteArray {
        require(pubkey.size == 33 || pubkey.size == 65) { "public key must be 33 or 65 bytes" }
        require(tweak.size == 32) { "tweak must be 32 bytes" }
        return Secp256k1CFunctions.secp256k1_ec_pubkey_tweak_mul(Secp256k1Context.getContext(), pubkey, tweak)
    }

    override fun pubKeyCombine(pubkeys: Array<ByteArray>): ByteArray {
        require(pubkeys.isNotEmpty()) { "pubkeys must not be empty" }
        pubkeys.forEach { require(it.size == 33 || it.size == 65) { "public key must be 33 or 65 bytes" } }
        return Secp256k1CFunctions.secp256k1_ec_pubkey_combine(Secp256k1Context.getContext(), pubkeys)
    }

    override fun ecdh(privkey: ByteArray, pubkey: ByteArray): ByteArray {
        require(privkey.size == 32) { "private key must be 32 bytes" }
        require(pubkey.size == 33 || pubkey.size == 65) { "public key must be 33 or 65 bytes" }
        return Secp256k1CFunctions.secp256k1_ecdh(Secp256k1Context.getContext(), privkey, pubkey)
    }

    override fun ecdsaRecover(sig: ByteArray, message: ByteArray, recid: Int): ByteArray {
        require(sig.size == 64) { "signature must be 64 bytes" }
        require(message.size == 32) { "message must be 32 bytes" }
        require(recid in 0..3) { "recovery id must be in 0..3" }
        return Secp256k1CFunctions.secp256k1_ecdsa_recover(Secp256k1Context.getContext(), sig, message, recid)
    }

    override fun compact2der(sig: ByteArray): ByteArray {
        require(sig.size == 64) { "signature must be 64 bytes" }
        return Secp256k1CFunctions.secp256k1_compact_to_der(Secp256k1Context.getContext(), sig)
    }

    override fun der2compact(sig: ByteArray): ByteArray {
        require(sig.size in 8..73) { "invalid DER signature size" }
        return Secp256k1CFunctions.secp256k1_der_to_compact(Secp256k1Context.getContext(), sig)
    }

    override fun verifySchnorr(signature: ByteArray, data: ByteArray, pub: ByteArray): Boolean {
        require(signature.size == 64) { "signature must be 64 bytes" }
        require(data.size == 32) { "data must be 32 bytes" }
        require(pub.size == 32) { "x-only public key must be 32 bytes" }
        return Secp256k1CFunctions.secp256k1_schnorrsig_verify(Secp256k1Context.getContext(), signature, data, pub) == 1
    }

    override fun signSchnorr(data: ByteArray, sec: ByteArray, auxrand32: ByteArray?): ByteArray {
        require(sec.size == 32) { "secret key must be 32 bytes" }
        require(data.size == 32) { "data must be 32 bytes" }
        auxrand32?.let { require(it.size == 32) { "auxiliary random data must be 32 bytes" } }
        return Secp256k1CFunctions.secp256k1_schnorrsig_sign(Secp256k1Context.getContext(), data, sec, auxrand32)
    }

    override fun musigNonceGen(sessionRandom32: ByteArray, privkey: ByteArray?, pubkey: ByteArray, msg32: ByteArray?, keyaggCache: ByteArray?, extraInput32: ByteArray?): ByteArray {
        require(sessionRandom32.size == 32) { "session random must be 32 bytes" }
        privkey?.let { require(it.size == 32) { "private key must be 32 bytes" } }
        require(pubkey.size == 33 || pubkey.size == 65) { "public key must be 33 or 65 bytes" }
        msg32?.let { require(it.size == 32) { "message must be 32 bytes" } }
        keyaggCache?.let { require(it.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) { "invalid keyagg cache size" } }
        extraInput32?.let { require(it.size == 32) { "extra input must be 32 bytes" } }
        return Secp256k1CFunctions.secp256k1_musig_nonce_gen(Secp256k1Context.getContext(), sessionRandom32, privkey, pubkey, msg32, keyaggCache, extraInput32)
    }

    override fun musigNonceGenCounter(nonRepeatingCounter: ULong, privkey: ByteArray, msg32: ByteArray?, keyaggCache: ByteArray?, extraInput32: ByteArray?): ByteArray {
        require(privkey.size == 32) { "private key must be 32 bytes" }
        msg32?.let { require(it.size == 32) { "message must be 32 bytes" } }
        keyaggCache?.let { require(it.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) { "invalid keyagg cache size" } }
        extraInput32?.let { require(it.size == 32) { "extra input must be 32 bytes" } }
        return Secp256k1CFunctions.secp256k1_musig_nonce_gen_counter(Secp256k1Context.getContext(), nonRepeatingCounter.toLong(), privkey, msg32, keyaggCache, extraInput32)
    }

    override fun musigNonceAgg(pubnonces: Array<ByteArray>): ByteArray {
        require(pubnonces.isNotEmpty()) { "pubnonces must not be empty" }
        pubnonces.forEach { require(it.size == Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE) { "public nonce must be ${Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE} bytes" } }
        return Secp256k1CFunctions.secp256k1_musig_nonce_agg(Secp256k1Context.getContext(), pubnonces)
    }

    override fun musigPubkeyAgg(pubkeys: Array<ByteArray>, keyaggCache: ByteArray?): ByteArray {
        require(pubkeys.isNotEmpty()) { "pubkeys must not be empty" }
        pubkeys.forEach { require(it.size == 33 || it.size == 65) { "public key must be 33 or 65 bytes" } }
        keyaggCache?.let { require(it.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) { "invalid keyagg cache size" } }
        return Secp256k1CFunctions.secp256k1_musig_pubkey_agg(Secp256k1Context.getContext(), pubkeys, keyaggCache)
    }

    override fun musigPubkeyTweakAdd(keyaggCache: ByteArray, tweak32: ByteArray): ByteArray {
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) { "invalid keyagg cache size" }
        require(tweak32.size == 32) { "tweak must be 32 bytes" }
        return Secp256k1CFunctions.secp256k1_musig_pubkey_ec_tweak_add(Secp256k1Context.getContext(), keyaggCache, tweak32)
    }

    override fun musigPubkeyXonlyTweakAdd(keyaggCache: ByteArray, tweak32: ByteArray): ByteArray {
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) { "invalid keyagg cache size" }
        require(tweak32.size == 32) { "tweak must be 32 bytes" }
        return Secp256k1CFunctions.secp256k1_musig_pubkey_xonly_tweak_add(Secp256k1Context.getContext(), keyaggCache, tweak32)
    }

    override fun musigNonceProcess(aggnonce: ByteArray, msg32: ByteArray, keyaggCache: ByteArray): ByteArray {
        require(aggnonce.size == Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE) { "aggregate nonce must be ${Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE} bytes" }
        require(msg32.size == 32) { "message must be 32 bytes" }
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) { "invalid keyagg cache size" }
        return Secp256k1CFunctions.secp256k1_musig_nonce_process(Secp256k1Context.getContext(), aggnonce, msg32, keyaggCache)
    }

    override fun musigPartialSign(secnonce: ByteArray, privkey: ByteArray, keyaggCache: ByteArray, session: ByteArray): ByteArray {
        require(secnonce.size == Secp256k1.MUSIG2_SECRET_NONCE_SIZE) { "secret nonce must be ${Secp256k1.MUSIG2_SECRET_NONCE_SIZE} bytes" }
        require(privkey.size == 32) { "private key must be 32 bytes" }
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) { "invalid keyagg cache size" }
        require(session.size == Secp256k1.MUSIG2_PUBLIC_SESSION_SIZE) { "invalid session size" }
        require(musigNonceValidate(secnonce, pubkeyCreate(privkey)))
        return Secp256k1CFunctions.secp256k1_musig_partial_sign(Secp256k1Context.getContext(), secnonce, privkey, keyaggCache, session)
    }

    override fun musigPartialSigVerify(psig: ByteArray, pubnonce: ByteArray, pubkey: ByteArray, keyaggCache: ByteArray, session: ByteArray): Int {
        require(psig.size == 32) { "partial signature must be 32 bytes" }
        require(pubnonce.size == Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE) { "public nonce must be ${Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE} bytes" }
        require(pubkey.size == 33 || pubkey.size == 65) { "public key must be 33 or 65 bytes" }
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) { "invalid keyagg cache size" }
        require(session.size == Secp256k1.MUSIG2_PUBLIC_SESSION_SIZE) { "invalid session size" }
        return Secp256k1CFunctions.secp256k1_musig_partial_sig_verify(Secp256k1Context.getContext(), psig, pubnonce, pubkey, keyaggCache, session)
    }

    override fun musigPartialSigAgg(session: ByteArray, psigs: Array<ByteArray>): ByteArray {
        require(session.size == Secp256k1.MUSIG2_PUBLIC_SESSION_SIZE) { "invalid session size" }
        require(psigs.isNotEmpty()) { "partial signatures must not be empty" }
        psigs.forEach { require(it.size == 32) { "partial signature must be 32 bytes" } }
        return Secp256k1CFunctions.secp256k1_musig_partial_sig_agg(Secp256k1Context.getContext(), session, psigs)
    }

    override fun cleanup() {
        return Secp256k1CFunctions.secp256k1_context_destroy(Secp256k1Context.getContext())
    }
}
