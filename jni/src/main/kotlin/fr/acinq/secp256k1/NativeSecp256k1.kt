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

    override fun pubKeyCombine(vararg pubkeys: ByteArray): ByteArray {
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

    override fun cleanup() {
        return Secp256k1CFunctions.secp256k1_context_destroy(Secp256k1Context.getContext())
    }
}
