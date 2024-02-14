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
        return Secp256k1CFunctions.secp256k1_ecdsa_verify(Secp256k1Context.getContext(), signature, message, pubkey) == 1
    }

    override fun sign(message: ByteArray, privkey: ByteArray): ByteArray {
        return Secp256k1CFunctions.secp256k1_ecdsa_sign(Secp256k1Context.getContext(), message, privkey)
    }

    override fun signatureNormalize(sig: ByteArray): Pair<ByteArray, Boolean> {
        val sigout = ByteArray(64)
        val result = Secp256k1CFunctions.secp256k1_ecdsa_signature_normalize(Secp256k1Context.getContext(), sig, sigout)
        return Pair(sigout, result == 1)
    }

    override fun secKeyVerify(privkey: ByteArray): Boolean {
        return Secp256k1CFunctions.secp256k1_ec_seckey_verify(Secp256k1Context.getContext(), privkey) == 1
    }

    override fun pubkeyCreate(privkey: ByteArray): ByteArray {
        return Secp256k1CFunctions.secp256k1_ec_pubkey_create(Secp256k1Context.getContext(), privkey)
    }

    override fun pubkeyParse(pubkey: ByteArray): ByteArray {
        return Secp256k1CFunctions.secp256k1_ec_pubkey_parse(Secp256k1Context.getContext(), pubkey)
    }

    override fun privKeyNegate(privkey: ByteArray): ByteArray {
        return Secp256k1CFunctions.secp256k1_ec_privkey_negate(Secp256k1Context.getContext(), privkey)
    }

    override fun privKeyTweakAdd(privkey: ByteArray, tweak: ByteArray): ByteArray {
        return Secp256k1CFunctions.secp256k1_ec_privkey_tweak_add(Secp256k1Context.getContext(), privkey, tweak)
    }

    override fun privKeyTweakMul(privkey: ByteArray, tweak: ByteArray): ByteArray {
        return Secp256k1CFunctions.secp256k1_ec_privkey_tweak_mul(Secp256k1Context.getContext(), privkey, tweak)
    }

    override fun pubKeyNegate(pubkey: ByteArray): ByteArray {
        return Secp256k1CFunctions.secp256k1_ec_pubkey_negate(Secp256k1Context.getContext(), pubkey)
    }

    override fun pubKeyTweakAdd(pubkey: ByteArray, tweak: ByteArray): ByteArray {
        return Secp256k1CFunctions.secp256k1_ec_pubkey_tweak_add(Secp256k1Context.getContext(), pubkey, tweak)
    }

    override fun pubKeyTweakMul(pubkey: ByteArray, tweak: ByteArray): ByteArray {
        return Secp256k1CFunctions.secp256k1_ec_pubkey_tweak_mul(Secp256k1Context.getContext(), pubkey, tweak)
    }

    override fun pubKeyCombine(pubkeys: Array<ByteArray>): ByteArray {
        return Secp256k1CFunctions.secp256k1_ec_pubkey_combine(Secp256k1Context.getContext(), pubkeys)
    }

    override fun ecdh(privkey: ByteArray, pubkey: ByteArray): ByteArray {
        return Secp256k1CFunctions.secp256k1_ecdh(Secp256k1Context.getContext(), privkey, pubkey)
    }

    override fun ecdsaRecover(sig: ByteArray, message: ByteArray, recid: Int): ByteArray {
        return Secp256k1CFunctions.secp256k1_ecdsa_recover(Secp256k1Context.getContext(), sig, message, recid)
    }

    override fun compact2der(sig: ByteArray): ByteArray {
        return Secp256k1CFunctions.secp256k1_compact_to_der(Secp256k1Context.getContext(), sig)
    }

    override fun verifySchnorr(signature: ByteArray, data: ByteArray, pub: ByteArray): Boolean {
        return Secp256k1CFunctions.secp256k1_schnorrsig_verify(Secp256k1Context.getContext(), signature, data, pub) == 1
    }

    override fun signSchnorr(data: ByteArray, sec: ByteArray, auxrand32: ByteArray?): ByteArray {
        return Secp256k1CFunctions.secp256k1_schnorrsig_sign(Secp256k1Context.getContext(), data, sec, auxrand32)
    }

    override fun musigNonceGen(sessionId32: ByteArray, privkey: ByteArray?, aggpubkey: ByteArray, msg32: ByteArray?, keyaggCache: ByteArray?, extraInput32: ByteArray?): ByteArray {
        return Secp256k1CFunctions.secp256k1_musig_nonce_gen(Secp256k1Context.getContext(), sessionId32, privkey, aggpubkey, msg32, keyaggCache, extraInput32)
    }

    override fun musigNonceAgg(pubnonces: Array<ByteArray>): ByteArray {
        return Secp256k1CFunctions.secp256k1_musig_nonce_agg(Secp256k1Context.getContext(), pubnonces)
    }

    override fun musigPubkeyAgg(pubkeys: Array<ByteArray>, keyaggCache: ByteArray?): ByteArray {
        return Secp256k1CFunctions.secp256k1_musig_pubkey_agg(Secp256k1Context.getContext(), pubkeys, keyaggCache)
    }

    override fun musigPubkeyTweakAdd(keyaggCache: ByteArray, tweak32: ByteArray): ByteArray {
        return Secp256k1CFunctions.secp256k1_musig_pubkey_ec_tweak_add(Secp256k1Context.getContext(), keyaggCache, tweak32)
    }

    override fun musigPubkeyXonlyTweakAdd(keyaggCache: ByteArray, tweak32: ByteArray): ByteArray {
        return Secp256k1CFunctions.secp256k1_musig_pubkey_xonly_tweak_add(Secp256k1Context.getContext(), keyaggCache, tweak32)
    }

    override fun musigNonceProcess(aggnonce: ByteArray, msg32: ByteArray, keyaggCache: ByteArray): ByteArray {
        return Secp256k1CFunctions.secp256k1_musig_nonce_process(Secp256k1Context.getContext(), aggnonce, msg32, keyaggCache)
    }

    override fun musigPartialSign(secnonce: ByteArray, privkey: ByteArray, keyaggCache: ByteArray, session: ByteArray): ByteArray {
        return Secp256k1CFunctions.secp256k1_musig_partial_sign(Secp256k1Context.getContext(), secnonce, privkey, keyaggCache, session)
    }

    override fun musigPartialSigVerify(psig: ByteArray, pubnonce: ByteArray, pubkey: ByteArray, keyaggCache: ByteArray, session: ByteArray): Int {
        return Secp256k1CFunctions.secp256k1_musig_partial_sig_verify(Secp256k1Context.getContext(), psig, pubnonce, pubkey, keyaggCache, session)
    }

    override fun musigPartialSigAgg(session: ByteArray, psigs: Array<ByteArray>): ByteArray {
        return Secp256k1CFunctions.secp256k1_musig_partial_sig_agg(Secp256k1Context.getContext(), session, psigs)
    }

    override fun cleanup() {
        return Secp256k1CFunctions.secp256k1_context_destroy(Secp256k1Context.getContext())
    }
}
