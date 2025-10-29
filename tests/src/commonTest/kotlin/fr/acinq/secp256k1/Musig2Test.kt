package fr.acinq.secp256k1

import kotlinx.serialization.json.*
import kotlin.test.*

class Musig2Test {
    @Test
    fun aggregatePublicKeys() {
        val tests = readResourceAsJson("musig2/key_agg_vectors.json")
        val pubkeys = tests.jsonObject["pubkeys"]!!.jsonArray.map { Hex.decode(it.jsonPrimitive.content) }
        val tweaks = tests.jsonObject["tweaks"]!!.jsonArray.map { Hex.decode(it.jsonPrimitive.content) }

        tests.jsonObject["valid_test_cases"]!!.jsonArray.forEach {
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val expected = Hex.decode(it.jsonObject["expected"]!!.jsonPrimitive.content)
            val keyAggCache = ByteArray(Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
            val aggkey = Secp256k1.musigPubkeyAgg(keyIndices.map { pubkeys[it] }.toTypedArray(), keyAggCache)
            assertContentEquals(expected, aggkey)
        }
        tests.jsonObject["error_test_cases"]!!.jsonArray.forEach {
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val tweakIndex = it.jsonObject["tweak_indices"]!!.jsonArray.map { it.jsonPrimitive.int }.firstOrNull()
            val isXonly = it.jsonObject["is_xonly"]!!.jsonArray.map { it.jsonPrimitive.boolean }
            when (tweakIndex) {
                null -> {
                    // One of the public keys is invalid, so key aggregation will fail.
                    // Callers must verify that public keys are valid before aggregating them.
                    assertFails {
                        val keyAggCache = ByteArray(Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
                        Secp256k1.musigPubkeyAgg(keyIndices.map { pubkeys[it] }.toTypedArray(), keyAggCache)
                    }
                }

                else -> {
                    // The tweak cannot be applied, it would result in an invalid public key.
                    assertFails {
                        val keyAggCache = ByteArray(Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
                        Secp256k1.musigPubkeyAgg(keyIndices.map { pubkeys[it] }.toTypedArray(), keyAggCache)
                        if (isXonly[0])
                            Secp256k1.musigPubkeyXonlyTweakAdd(keyAggCache, tweaks[tweakIndex])
                        else
                            Secp256k1.musigPubkeyTweakAdd(keyAggCache, tweaks[tweakIndex])
                    }
                }
            }
        }
    }

    /** Secret nonces in test vectors use a custom encoding. */
    private fun deserializeSecretNonce(hex: String): ByteArray {
        val serialized = Hex.decode(hex)
        require(serialized.size == 97) { "secret nonce from test vector should be serialized using 97 bytes" }
        // In test vectors, secret nonces are serialized as: <scalar_1> <scalar_2> <compressed_public_key>
        val compressedPublicKey = serialized.takeLast(33).toByteArray()
        // We expect secret nonces serialized as: <magic> <scalar_1> <scalar_2> <public_key_x> <public_key_y>
        // Where we use a different endianness for the public key coordinates than the test vectors.
        val uncompressedPublicKey = Secp256k1.pubkeyParse(compressedPublicKey)
        val publicKeyX = uncompressedPublicKey.drop(1).take(32).reversed().toByteArray()
        val publicKeyY = uncompressedPublicKey.takeLast(32).reversed().toByteArray()
        val magic = Hex.decode("220EDCF1")
        return magic + serialized.take(64) + publicKeyX + publicKeyY
    }

    @Test
    fun generateSecretNonce() {
        val tests = readResourceAsJson("musig2/nonce_gen_vectors.json")
        tests.jsonObject["test_cases"]!!.jsonArray.forEach {
            val randprime = Hex.decode(it.jsonObject["rand_"]!!.jsonPrimitive.content)
            val sk = it.jsonObject["sk"]?.jsonPrimitive?.contentOrNull?.let { Hex.decode(it) }
            val pk = Hex.decode(it.jsonObject["pk"]!!.jsonPrimitive.content)
            val keyagg = it.jsonObject["aggpk"]?.jsonPrimitive?.contentOrNull?.let {
                // The test vectors directly provide an aggregated public key: we must manually create the corresponding
                // key aggregation cache to correctly test.
                val agg = ByteArray(1) { 2.toByte() } + Hex.decode(it)
                val magic = Hex.decode("f4adbbdf")
                magic + Secp256k1.pubkeyParse(agg).drop(1) + ByteArray(129) { 0x00 }
            }
            val msg = it.jsonObject["msg"]?.jsonPrimitive?.contentOrNull?.let { Hex.decode(it) }
            val extraInput = it.jsonObject["extra_in"]?.jsonPrimitive?.contentOrNull?.let { Hex.decode(it) }
            val expectedSecnonce = deserializeSecretNonce(it.jsonObject["expected_secnonce"]!!.jsonPrimitive.content)
            val expectedPubnonce = Hex.decode(it.jsonObject["expected_pubnonce"]!!.jsonPrimitive.content)
            // secp256k1 only supports signing 32-byte messages (when provided), which excludes some of the test vectors.
            if (msg == null || msg.size == 32) {
                val nonce = Secp256k1.musigNonceGen(randprime, sk, pk, msg, keyagg, extraInput)
                val secnonce = nonce.copyOfRange(0, Secp256k1.MUSIG2_SECRET_NONCE_SIZE)
                val pubnonce = nonce.copyOfRange(Secp256k1.MUSIG2_SECRET_NONCE_SIZE, Secp256k1.MUSIG2_SECRET_NONCE_SIZE + Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE)
                assertContentEquals(expectedPubnonce, pubnonce)
                assertContentEquals(expectedSecnonce, secnonce)
            }
        }
    }

    @Test
    fun generateSecretNonceFromCounter() {
        val sk = Hex.decode("EEC1CB7D1B7254C5CAB0D9C61AB02E643D464A59FE6C96A7EFE871F07C5AEF54")
        val nonce = Secp256k1.musigNonceGenCounter(0UL, sk, null, null, null)
        val secnonce = nonce.copyOfRange(0, Secp256k1.MUSIG2_SECRET_NONCE_SIZE)
        val pubnonce = nonce.copyOfRange(Secp256k1.MUSIG2_SECRET_NONCE_SIZE, Secp256k1.MUSIG2_SECRET_NONCE_SIZE + Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE)
        assertContentEquals(secnonce.copyOfRange(4, 4 + 64), Hex.decode("842F1380CD17A198FC3DAD3B7DA7492941F46976F2702FF7C66F24F472036AF1DA3F952DDE4A2DA6B6325707CE87A4E3616D06FC5F81A9C99386D20A99CECF99"))
        assertContentEquals(pubnonce, Hex.decode("03A5B9B6907942EACDDA49A366016EC2E62404A1BF4AB6D4DB82067BC3ADF086D7033205DB9EB34D5C7CE02848CAC68A83ED73E3883477F563F23CE9A11A7721EC64"))
    }

    @Test
    fun aggregateNonces() {
        val tests = readResourceAsJson("musig2/nonce_agg_vectors.json")
        val nonces = tests.jsonObject["pnonces"]!!.jsonArray.map { Hex.decode(it.jsonPrimitive.content) }
        tests.jsonObject["valid_test_cases"]!!.jsonArray.forEach {
            val nonceIndices = it.jsonObject["pnonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val expected = Hex.decode(it.jsonObject["expected"]!!.jsonPrimitive.content)
            val agg = Secp256k1.musigNonceAgg(nonceIndices.map { nonces[it] }.toTypedArray())
            assertNotNull(agg)
            assertContentEquals(expected, agg)
        }
        tests.jsonObject["error_test_cases"]!!.jsonArray.forEach {
            val nonceIndices = it.jsonObject["pnonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            assertFails {
                Secp256k1.musigNonceAgg(nonceIndices.map { nonces[it] }.toTypedArray())
            }
        }
    }

    @Test
    fun sign() {
        val tests = readResourceAsJson("musig2/sign_verify_vectors.json")
        val sk = Hex.decode(tests.jsonObject["sk"]!!.jsonPrimitive.content)
        val pubkeys = tests.jsonObject["pubkeys"]!!.jsonArray.map { Hex.decode(it.jsonPrimitive.content) }
        val secnonces = tests.jsonObject["secnonces"]!!.jsonArray.map { deserializeSecretNonce(it.jsonPrimitive.content) }
        val pnonces = tests.jsonObject["pnonces"]!!.jsonArray.map { Hex.decode(it.jsonPrimitive.content) }
        val aggnonces = tests.jsonObject["aggnonces"]!!.jsonArray.map { Hex.decode(it.jsonPrimitive.content) }
        val msgs = tests.jsonObject["msgs"]!!.jsonArray.map { Hex.decode(it.jsonPrimitive.content) }

        tests.jsonObject["valid_test_cases"]!!.jsonArray.forEach {
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val nonceIndices = it.jsonObject["nonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val expected = Hex.decode(it.jsonObject["expected"]!!.jsonPrimitive.content)
            val signerIndex = it.jsonObject["signer_index"]!!.jsonPrimitive.int
            val messageIndex = it.jsonObject["msg_index"]!!.jsonPrimitive.int
            val aggnonce = Secp256k1.musigNonceAgg(nonceIndices.map { pnonces[it] }.toTypedArray())
            assertNotNull(aggnonce)
            assertContentEquals(aggnonces[it.jsonObject["aggnonce_index"]!!.jsonPrimitive.int], aggnonce)
            val keyagg = ByteArray(Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
            Secp256k1.musigPubkeyAgg(keyIndices.map { pubkeys[it] }.toTypedArray(), keyagg)
            // We only support signing 32-byte messages.
            if (msgs[messageIndex].size == 32) {
                val session = Secp256k1.musigNonceProcess(aggnonce, msgs[messageIndex], keyagg)
                assertNotNull(session)
                val psig = Secp256k1.musigPartialSign(secnonces[keyIndices[signerIndex]], sk, keyagg, session)
                assertContentEquals(expected, psig)
                assertEquals(1, Secp256k1.musigPartialSigVerify(psig, pnonces[nonceIndices[signerIndex]], pubkeys[keyIndices[signerIndex]], keyagg, session))
            }
        }
        tests.jsonObject["verify_fail_test_cases"]!!.jsonArray.forEach {
            val psig = Hex.decode(it.jsonObject["sig"]!!.jsonPrimitive.content)
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val nonceIndices = it.jsonObject["nonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val signerIndex = it.jsonObject["signer_index"]!!.jsonPrimitive.int
            val messageIndex = it.jsonObject["msg_index"]!!.jsonPrimitive.int
            if (msgs[messageIndex].size == 32) {
                val aggnonce = Secp256k1.musigNonceAgg(nonceIndices.map { pnonces[it] }.toTypedArray())
                assertNotNull(aggnonce)
                val keyagg = ByteArray(Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
                Secp256k1.musigPubkeyAgg(keyIndices.map { pubkeys[it] }.toTypedArray(), keyagg)
                val session = Secp256k1.musigNonceProcess(aggnonce, msgs[messageIndex], keyagg)
                assertNotNull(session)
                assertFails {
                    require(Secp256k1.musigPartialSigVerify(psig, pnonces[nonceIndices[signerIndex]], pubkeys[keyIndices[signerIndex]], keyagg, session) == 1)
                }
            }
        }
    }

    @Test
    fun aggregateSignatures() {
        val tests = readResourceAsJson("musig2/sig_agg_vectors.json")
        val pubkeys = tests.jsonObject["pubkeys"]!!.jsonArray.map { Hex.decode(it.jsonPrimitive.content) }
        val pnonces = tests.jsonObject["pnonces"]!!.jsonArray.map { Hex.decode(it.jsonPrimitive.content) }
        val tweaks = tests.jsonObject["tweaks"]!!.jsonArray.map { Hex.decode(it.jsonPrimitive.content) }
        val psigs = tests.jsonObject["psigs"]!!.jsonArray.map { Hex.decode(it.jsonPrimitive.content) }
        val msg = Hex.decode(tests.jsonObject["msg"]!!.jsonPrimitive.content)

        tests.jsonObject["valid_test_cases"]!!.jsonArray.forEach {
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val nonceIndices = it.jsonObject["nonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val psigIndices = it.jsonObject["psig_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val expected = Hex.decode(it.jsonObject["expected"]!!.jsonPrimitive.content)
            val aggnonce = Secp256k1.musigNonceAgg(nonceIndices.map { pnonces[it] }.toTypedArray())
            assertNotNull(aggnonce)
            val tweakIndices = it.jsonObject["tweak_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val isXonly = it.jsonObject["is_xonly"]!!.jsonArray.map { it.jsonPrimitive.boolean }
            assertContentEquals(Hex.decode(it.jsonObject["aggnonce"]!!.jsonPrimitive.content), aggnonce)
            val keyagg = ByteArray(Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
            Secp256k1.musigPubkeyAgg(keyIndices.map { pubkeys[it] }.toTypedArray(), keyagg)
            tweakIndices
                .zip(isXonly)
                .map { tweaks[it.first] to it.second }
                .forEach {
                    if (it.second)
                        Secp256k1.musigPubkeyXonlyTweakAdd(keyagg, it.first)
                    else
                        Secp256k1.musigPubkeyTweakAdd(keyagg, it.first)
                }
            val session = Secp256k1.musigNonceProcess(aggnonce, msg, keyagg)
            val aggsig = Secp256k1.musigPartialSigAgg(session, psigIndices.map { psigs[it] }.toTypedArray())
            assertContentEquals(expected, aggsig)
        }
        tests.jsonObject["error_test_cases"]!!.jsonArray.forEach {
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val nonceIndices = it.jsonObject["nonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val psigIndices = it.jsonObject["psig_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val aggnonce = Secp256k1.musigNonceAgg(nonceIndices.map { pnonces[it] }.toTypedArray())
            assertNotNull(aggnonce)
            val tweakIndices = it.jsonObject["tweak_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val isXonly = it.jsonObject["is_xonly"]!!.jsonArray.map { it.jsonPrimitive.boolean }
            assertContentEquals(Hex.decode(it.jsonObject["aggnonce"]!!.jsonPrimitive.content), aggnonce)
            val keyagg = ByteArray(Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
            Secp256k1.musigPubkeyAgg(keyIndices.map { pubkeys[it] }.toTypedArray(), keyagg)
            tweakIndices
                .zip(isXonly)
                .map { tweaks[it.first] to it.second }
                .forEach {
                    if (it.second)
                        Secp256k1.musigPubkeyXonlyTweakAdd(keyagg, it.first)
                    else
                        Secp256k1.musigPubkeyTweakAdd(keyagg, it.first)
                }
            val session = Secp256k1.musigNonceProcess(aggnonce, msg, keyagg)
            assertFails {
                Secp256k1.musigPartialSigAgg(session, psigIndices.map { psigs[it] }.toTypedArray())
            }
        }
    }

    @Test
    fun tweakTests() {
        val tests = readResourceAsJson("musig2/tweak_vectors.json")
        val sk = Hex.decode(tests.jsonObject["sk"]!!.jsonPrimitive.content)
        val pubkeys = tests.jsonObject["pubkeys"]!!.jsonArray.map { Hex.decode(it.jsonPrimitive.content) }
        val pnonces = tests.jsonObject["pnonces"]!!.jsonArray.map { Hex.decode(it.jsonPrimitive.content) }
        val tweaks = tests.jsonObject["tweaks"]!!.jsonArray.map { Hex.decode(it.jsonPrimitive.content) }
        val msg = Hex.decode(tests.jsonObject["msg"]!!.jsonPrimitive.content)

        val secnonce = deserializeSecretNonce(tests.jsonObject["secnonce"]!!.jsonPrimitive.content)
        val aggnonce = Hex.decode(tests.jsonObject["aggnonce"]!!.jsonPrimitive.content)

        assertContentEquals(aggnonce, Secp256k1.musigNonceAgg(arrayOf(pnonces[0], pnonces[1], pnonces[2])))

        tests.jsonObject["valid_test_cases"]!!.jsonArray.forEach {
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val nonceIndices = it.jsonObject["nonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val expected = Hex.decode(it.jsonObject["expected"]!!.jsonPrimitive.content)
            assertContentEquals(aggnonce, Secp256k1.musigNonceAgg(nonceIndices.map { pnonces[it] }.toTypedArray()))
            val tweakIndices = it.jsonObject["tweak_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val isXonly = it.jsonObject["is_xonly"]!!.jsonArray.map { it.jsonPrimitive.boolean }
            val signerIndex = it.jsonObject["signer_index"]!!.jsonPrimitive.int
            val keyagg = ByteArray(Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
            Secp256k1.musigPubkeyAgg(keyIndices.map { pubkeys[it] }.toTypedArray(), keyagg)
            tweakIndices
                .zip(isXonly)
                .map { tweaks[it.first] to it.second }
                .forEach {
                    if (it.second)
                        Secp256k1.musigPubkeyXonlyTweakAdd(keyagg, it.first)
                    else
                        Secp256k1.musigPubkeyTweakAdd(keyagg, it.first)
                }
            val session = Secp256k1.musigNonceProcess(aggnonce, msg, keyagg)
            assertNotNull(session)
            val psig = Secp256k1.musigPartialSign(secnonce, sk, keyagg, session)
            assertContentEquals(expected, psig)
            assertEquals(1, Secp256k1.musigPartialSigVerify(psig, pnonces[nonceIndices[signerIndex]], pubkeys[keyIndices[signerIndex]], keyagg, session))
        }
        tests.jsonObject["error_test_cases"]!!.jsonArray.forEach {
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val nonceIndices = it.jsonObject["nonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            assertContentEquals(aggnonce, Secp256k1.musigNonceAgg(nonceIndices.map { pnonces[it] }.toTypedArray()))
            val tweakIndices = it.jsonObject["tweak_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            assertEquals(1, tweakIndices.size)
            val tweak = tweaks[tweakIndices.first()]
            val isXonly = it.jsonObject["is_xonly"]!!.jsonArray.map { it.jsonPrimitive.boolean }.first()
            val keyagg = ByteArray(Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
            Secp256k1.musigPubkeyAgg(keyIndices.map { pubkeys[it] }.toTypedArray(), keyagg)
            assertFails {
                if (isXonly)
                    Secp256k1.musigPubkeyXonlyTweakAdd(keyagg, tweak)
                else
                    Secp256k1.musigPubkeyTweakAdd(keyagg, tweak)
            }
        }
    }
}