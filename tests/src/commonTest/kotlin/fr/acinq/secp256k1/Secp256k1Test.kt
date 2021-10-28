package fr.acinq.secp256k1

import kotlin.random.Random
import kotlin.test.*

class Secp256k1Test {

    @Test
    fun verifyValidPrivateKey() {
        val priv = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".lowercase())
        assertTrue(Secp256k1.secKeyVerify(priv))
    }

    @Test
    fun verifyInvalidPrivateKey() {
        val invalidSize = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A106353001")
        assertFalse(Secp256k1.secKeyVerify(invalidSize))
        val greaterThanCurveOrder = Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141".lowercase())
        assertFalse(Secp256k1.secKeyVerify(greaterThanCurveOrder))
        val zero = Hex.decode("0000000000000000000000000000000000000000000000000000000000000000".lowercase())
        assertFalse(Secp256k1.secKeyVerify(zero))
    }

    @Test
    fun createValidPublicKey() {
        val priv = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".lowercase())
        val pub = Secp256k1.pubkeyCreate(priv)
        assertEquals(
            "04C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D2103ED494718C697AC9AEBCFD19612E224DB46661011863ED2FC54E71861E2A6",
            Hex.encode(pub).uppercase(),
        )
    }

    @Test
    fun createInvalidPublicKey() {
        val priv = Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".lowercase())
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.pubkeyCreate(priv)
        }
    }

    @Test
    fun compressPublicKey() {
        val pub = Hex.decode("04C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D2103ED494718C697AC9AEBCFD19612E224DB46661011863ED2FC54E71861E2A6")
        val compressed = Secp256k1.pubKeyCompress(pub)
        assertEquals("02C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D", Hex.encode(compressed).uppercase())
    }

    @Test
    fun negatePublicKey() {
        val priv = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".lowercase())
        val pub = Secp256k1.pubkeyCreate(priv)
        assertEquals(
            "04C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D2103ED494718C697AC9AEBCFD19612E224DB46661011863ED2FC54E71861E2A6",
            Hex.encode(pub).uppercase(),
        )
        val npub = Secp256k1.pubKeyNegate(pub)
        assertEquals(
            "04C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2DDEFC12B6B8E73968536514302E69ED1DDB24B999EFEE79C12D03AB17E79E1989",
            Hex.encode(npub).uppercase(),
        )
    }

    @Test
    fun parsePublicKey() {
        val pub = Hex.decode("02C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D".lowercase())
        val parsed = Secp256k1.pubkeyParse(pub)
        assertEquals(
            "04C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D2103ED494718C697AC9AEBCFD19612E224DB46661011863ED2FC54E71861E2A6",
            Hex.encode(parsed).uppercase(),
        )
    }

    @Test
    fun parseInvalidPublicKey() {
        val pub = Hex.decode("02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".lowercase())
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.pubkeyParse(pub)
        }
    }

    @Test
    fun combinePublicKeys() {
        val pub1 = Hex.decode("041b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f70beaf8f588b541507fed6a642c5ab42dfdf8120a7f639de5122d47a69a8e8d1".lowercase())
        val pub2 = Hex.decode("044d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d07662a3eada2d0fe208b6d257ceb0f064284662e857f57b66b54c198bd310ded36d0".lowercase())
        val pub3 = Secp256k1.pubKeyCombine(arrayOf(pub1, pub2))
        assertEquals(
            "04531FE6068134503D2723133227C867AC8FA6C83C537E9A44C3C5BDBDCB1FE3379E92C265E71E481BA82A84675A47AC705A200FCD524E92D93B0E7386F26A5458",
            Hex.encode(pub3).uppercase(),
        )
    }

    @Test
    fun createEcdsaSignature() {
        val message = Hex.decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90".lowercase()) //sha256hash of "testing"
        val priv = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".lowercase())
        val sig = Secp256k1.sign(message, priv)
        assertEquals(
            "182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A21C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9",
            Hex.encode(sig).uppercase(),
        )
    }

    @Test
    fun normalizeEcdsaSignature() {
        val sig = Hex.decode("30440220182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A202201C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9".lowercase())
        val (normalized, wasNotNormalized) = Secp256k1.signatureNormalize(sig)
        assertFalse(wasNotNormalized)
        assertEquals(
            "182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A21C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9",
            Hex.encode(normalized).uppercase(),
        )
    }

    @Test
    fun failToCreateEcdsaSignature() {
        val message = Hex.decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90".lowercase()) //sha256hash of "testing"
        val priv = Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".lowercase())
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.sign(message, priv)
        }
    }

    @Test
    fun createCompactEcdsaSignature() {
        val message = Hex.decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90".lowercase()) //sha256hash of "testing"
        val priv = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".lowercase())
        val sig = Secp256k1.sign(message, priv)
        assertEquals(
            "182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A21C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9",
            Hex.encode(sig).uppercase(),
        )
    }

    @Test
    fun verifyValidEcdsaSignatures() {
        val message = Hex.decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90".lowercase()) //sha256hash of "testing"
        val sig = Hex.decode("3044022079BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980220294F14E883B3F525B5367756C2A11EF6CF84B730B36C17CB0C56F0AAB2C98589".lowercase())
        val pub = Hex.decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40".lowercase())
        assertTrue(Secp256k1.verify(sig, message, pub))
        val sigCompact = Hex.decode("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798294F14E883B3F525B5367756C2A11EF6CF84B730B36C17CB0C56F0AAB2C98589".lowercase())
        assertTrue(Secp256k1.verify(sigCompact, message, pub))
    }

    @Test
    fun verifyInvalidEcdsaSignatures() {
        val message = Hex.decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A91".lowercase()) //sha256hash of "testing"
        val sig = Hex.decode("3044022079BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980220294F14E883B3F525B5367756C2A11EF6CF84B730B36C17CB0C56F0AAB2C98589".lowercase())
        val pub = Hex.decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40".lowercase())
        assertFalse(Secp256k1.verify(sig, message, pub))
    }

    @Test
    fun negatePrivateKey() {
        val priv = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".lowercase())
        val npriv = Secp256k1.privKeyNegate(priv)
        assertEquals(
            "981A9A7DD677A622518DA068D66D5F824E5F22F084B8A0E2F195B5662F300C11",
            Hex.encode(npriv).uppercase(),
        )
        val nnpriv: ByteArray = Secp256k1.privKeyNegate(npriv)
        assertContentEquals(priv, nnpriv)
    }

    @Test
    fun addTweakToPrivateKey() {
        val priv = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".lowercase())
        val tweak = Hex.decode("3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3".lowercase())
        val tweakedPriv = Secp256k1.privKeyTweakAdd(priv, tweak)
        assertEquals(
            "A168571E189E6F9A7E2D657A4B53AE99B909F7E712D1C23CED28093CD57C88F3",
            Hex.encode(tweakedPriv).uppercase(),
        )
    }

    @Test
    fun multiplyPrivateKeyWithTweak() {
        val priv = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".lowercase())
        val tweak = Hex.decode("3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3".lowercase())
        val tweakedPriv = Secp256k1.privKeyTweakMul(priv, tweak)
        assertEquals(
            "97F8184235F101550F3C71C927507651BD3F1CDB4A5A33B8986ACF0DEE20FFFC",
            Hex.encode(tweakedPriv).uppercase(),
        )
    }

    @Test
    fun addTweakToPublicKey() {
        val pub = Hex.decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40".lowercase())
        val tweak = Hex.decode("3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3".lowercase())
        val tweakedPub = Secp256k1.pubKeyTweakAdd(pub, tweak)
        assertEquals(
            "0411C6790F4B663CCE607BAAE08C43557EDC1A4D11D88DFCB3D841D0C6A941AF525A268E2A863C148555C48FB5FBA368E88718A46E205FABC3DBA2CCFFAB0796EF",
            Hex.encode(tweakedPub).uppercase(),
        )
    }

    @Test
    fun multiplyPublicKeyWithTweak() {
        val pub = Hex.decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40".lowercase())
        val tweak = Hex.decode("3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3".lowercase())
        val tweakedPub = Secp256k1.pubKeyTweakMul(pub, tweak)
        assertEquals(
            "04E0FE6FE55EBCA626B98A807F6CAF654139E14E5E3698F01A9A658E21DC1D2791EC060D4F412A794D5370F672BC94B722640B5F76914151CFCA6E712CA48CC589",
            Hex.encode(tweakedPub).uppercase(),
        )
    }

    @Test
    fun createEcdhSecret() {
        val priv = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".lowercase())
        val pub = Hex.decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40".lowercase())
        val secret = Secp256k1.ecdh(priv, pub)
        assertEquals(
            "2A2A67007A926E6594AF3EB564FC74005B37A9C8AEF2033C4552051B5C87F043",
            Hex.encode(secret).uppercase(),
        )
    }

    @Test
    fun createSymmetricEcdhSecret() {
        val priv1 = Hex.decode("3580a881ac24eb00530a51235c42bcb65424ba121e2e7d910a70fa531a578d21")
        val pub1 = Secp256k1.pubkeyCreate(priv1)
        val priv2 = Hex.decode("f6a353f7a5de654501c3495acde7450293f74d09086c2b7c9a4e524248d0daac")
        val pub2 = Secp256k1.pubkeyCreate(priv2)
        val secret1 = Secp256k1.ecdh(priv1, pub2)
        val secret2 = Secp256k1.ecdh(priv2, pub1)
        assertContentEquals(secret1, secret2)
    }

    @Test
    fun recoverPublicKeyFromEcdsaSignature() {
        val message = Hex.decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90".lowercase()) //sha256hash of "testing"
        val priv = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".lowercase())
        val pub = Secp256k1.pubkeyCreate(priv)
        val sig = Secp256k1.sign(message, priv)
        val pub0 = Secp256k1.ecdsaRecover(sig, message, 0)
        val pub1 = Secp256k1.ecdsaRecover(sig, message, 1)
        assertTrue(pub.contentEquals(pub0) || pub.contentEquals(pub1))
    }

    @Test
    fun convertCompactEcdsaSignatureToDer() {
        val compact = Hex.decode("182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A21C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9".lowercase()) //sha256hash of "testing"
        val der = Secp256k1.compact2der(compact)
        assertEquals(
            "30440220182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A202201C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9",
            Hex.encode(der).uppercase(),
        )
    }

    @Test
    fun fuzzEcdsaSignVerify() {
        val random = Random.Default

        fun randomBytes(length: Int): ByteArray {
            val buffer = ByteArray(length)
            random.nextBytes(buffer)
            return buffer
        }

        repeat(200) {
            val priv = randomBytes(32)
            assertTrue(Secp256k1.secKeyVerify(priv))
            val pub = Secp256k1.pubkeyCreate(priv)
            val message = randomBytes(32)
            val sig = Secp256k1.sign(message, priv)
            assertTrue(Secp256k1.verify(sig, message, pub))
            val der = Secp256k1.compact2der(sig)
            assertTrue(Secp256k1.verify(der, message, pub))
        }
    }

}
