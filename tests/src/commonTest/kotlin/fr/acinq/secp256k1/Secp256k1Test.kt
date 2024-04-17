package fr.acinq.secp256k1

import kotlin.random.Random
import kotlin.test.*

class Secp256k1Test {

    val random = Random.Default

    fun randomBytes(length: Int): ByteArray {
        val buffer = ByteArray(length)
        random.nextBytes(buffer)
        return buffer
    }

    @Test
    fun verifyValidPrivateKey() {
        val priv = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".lowercase())
        assertTrue(Secp256k1.secKeyVerify(priv))
    }

    @Test
    fun verifyInvalidPrivateKey() {
        val invalidSize = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A106353001")
        assertFalse(Secp256k1.secKeyVerify(invalidSize))
        val curveOrder = Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141".lowercase())
        assertFalse(Secp256k1.secKeyVerify(curveOrder))
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
        assertFailsWith<Secp256k1Exception> { Secp256k1.pubkeyCreate(Hex.decode("0000000000000000000000000000000000000000000000000000000000000000".lowercase())) }
        assertFailsWith<Secp256k1Exception> { Secp256k1.pubkeyCreate(Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141".lowercase())) }
        assertFailsWith<Secp256k1Exception> { Secp256k1.pubkeyCreate(Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".lowercase())) }
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
        assertEquals(
            "02C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D",
            Hex.encode(Secp256k1.pubKeyCompress(pub)).uppercase()
        )
        val npub = Secp256k1.pubKeyNegate(pub)
        assertEquals(
            "04C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2DDEFC12B6B8E73968536514302E69ED1DDB24B999EFEE79C12D03AB17E79E1989",
            Hex.encode(npub).uppercase(),
        )
        assertEquals(
            "03C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D",
            Hex.encode(Secp256k1.pubKeyCompress(npub)).uppercase()
        )
        val nnpub = Secp256k1.pubKeyNegate(npub)
        assertContentEquals(pub, nnpub)
    }

    @Test
    fun parsePublicKey() {
        val pub = Hex.decode("02C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D".lowercase())
        val parsed1 = Secp256k1.pubkeyParse(pub)
        assertEquals(
            "04C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D2103ED494718C697AC9AEBCFD19612E224DB46661011863ED2FC54E71861E2A6",
            Hex.encode(parsed1).uppercase(),
        )
        val parsed2 = Secp256k1.pubkeyParse(parsed1)
        assertContentEquals(parsed1, parsed2)
    }

    @Test
    fun parseInvalidPublicKey() {
        // Not a valid curve point.
        assertFailsWith<Secp256k1Exception> { Secp256k1.pubkeyParse(Hex.decode("02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".lowercase())) }
        // Invalid first byte.
        assertFailsWith<Secp256k1Exception> { Secp256k1.pubkeyParse(Hex.decode("02C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D2103ED494718C697AC9AEBCFD19612E224DB46661011863ED2FC54E71861E2A6".lowercase())) }
        assertFailsWith<Secp256k1Exception> { Secp256k1.pubkeyParse(Hex.decode("03C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D2103ED494718C697AC9AEBCFD19612E224DB46661011863ED2FC54E71861E2A6".lowercase())) }
        assertFailsWith<Secp256k1Exception> { Secp256k1.pubkeyParse(Hex.decode("05C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D2103ED494718C697AC9AEBCFD19612E224DB46661011863ED2FC54E71861E2A6".lowercase())) }
        assertFailsWith<Secp256k1Exception> { Secp256k1.pubkeyParse(Hex.decode("01C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D".lowercase())) }
        assertFailsWith<Secp256k1Exception> { Secp256k1.pubkeyParse(Hex.decode("04C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D".lowercase())) }
    }

    @Test
    fun combinePublicKeys() {
        // Mixture of compressed and uncompressed public keys.
        val pub1 = Hex.decode("041b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f70beaf8f588b541507fed6a642c5ab42dfdf8120a7f639de5122d47a69a8e8d1")
        val pub2 = Hex.decode("044d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d07662a3eada2d0fe208b6d257ceb0f064284662e857f57b66b54c198bd310ded36d0")
        val pub3 = Hex.decode("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619")
        val pub4 = Secp256k1.pubKeyCombine(arrayOf(pub1, pub2, pub3))
        assertEquals(
            "042C0B7CF95324A07D05398B240174DC0C2BE444D96B159AA6C7F7B1E668680991AE31A9C671A36543F46CEA8FCE6984608AA316AA0472A7EED08847440218CB2F",
            Hex.encode(pub4).uppercase(),
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
        val normalizedDerSig = Hex.decode("30440220182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A202201C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9".lowercase())
        val (normalizedCompactSig1, wasNotNormalized1) = Secp256k1.signatureNormalize(normalizedDerSig)
        assertFalse(wasNotNormalized1)
        assertEquals(
            "182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A21C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9",
            Hex.encode(normalizedCompactSig1).uppercase(),
        )
        val notNormalizedDerSig = Hex.decode("30450220182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A2022100E3990C925DEE3F780C50774AF120B062E0080D86D8C721C6E32F10DBACA57A58".lowercase())
        val (normalizedCompactSig2, wasNotNormalized2) = Secp256k1.signatureNormalize(notNormalizedDerSig)
        assertTrue(wasNotNormalized2)
        assertEquals(
            "182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A21C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9",
            Hex.encode(normalizedCompactSig2).uppercase(),
        )
        val normalizedCompactSig = Hex.decode("182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A21C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9".lowercase())
        val (normalizedCompactSig3, wasNotNormalized3) = Secp256k1.signatureNormalize(normalizedCompactSig)
        assertFalse(wasNotNormalized3)
        assertEquals(
            "182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A21C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9",
            Hex.encode(normalizedCompactSig3).uppercase(),
        )
        val notNormalizedCompactSig = Hex.decode("182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A2E3990C925DEE3F780C50774AF120B062E0080D86D8C721C6E32F10DBACA57A58".lowercase())
        val (normalizedCompactSig4, wasNotNormalized4) = Secp256k1.signatureNormalize(notNormalizedCompactSig)
        assertTrue(wasNotNormalized4)
        assertEquals(
            "182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A21C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9",
            Hex.encode(normalizedCompactSig4).uppercase(),
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
    fun testSchnorrSignature() {
        val seckey = Hex.decode("0000000000000000000000000000000000000000000000000000000000000003")
        val msg = Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")
        val auxrand32 = Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")
        val sig = Secp256k1.signSchnorr(msg, seckey, auxrand32)
        assertEquals(
            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
            Hex.encode(sig).uppercase(),
        )
        val pubkey = Secp256k1.pubkeyCreate(seckey).drop(1).take(32).toByteArray()
        assertEquals(
            "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            Hex.encode(pubkey).uppercase()
        )
        assertTrue(Secp256k1.verifySchnorr(sig, msg, pubkey))
    }

    @Test
    fun testSchnorrTestVectors() {
        // BIP340 test vectors copied from https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
        val bip340TestVectors = """index,secret key,public key,aux_rand,message,signature,verification result,comment
0,0000000000000000000000000000000000000000000000000000000000000003,F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9,0000000000000000000000000000000000000000000000000000000000000000,0000000000000000000000000000000000000000000000000000000000000000,E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0,TRUE,
1,B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,0000000000000000000000000000000000000000000000000000000000000001,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A,TRUE,
2,C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9,DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8,C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906,7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C,5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7,TRUE,
3,0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710,25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517,FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3,TRUE,test fails if msg is reduced modulo p or n
4,,D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9,,4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703,00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4,TRUE,
5,,EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B,FALSE,public key not on the curve
6,,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2,FALSE,has_even_y(R) is false
7,,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD,FALSE,negated message
8,,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6,FALSE,negated s value
9,,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051,FALSE,sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 0
10,,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197,FALSE,sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 1
11,,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B,FALSE,sig[0:32] is not an X coordinate on the curve
12,,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B,FALSE,sig[0:32] is equal to field size
13,,DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,FALSE,sig[32:64] is equal to curve order
14,,FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30,,243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B,FALSE,public key is not a valid X coordinate because it exceeds the field size"""

        bip340TestVectors.split('\n').drop(1).forEach {
            val testData = it.split(',')
            val index = testData[0]
            val seckey = Hex.decode(testData[1])
            val pubkey = Hex.decode(testData[2])
            val auxrand = if (testData[3].isEmpty()) null else Hex.decode(testData[3])
            val msg = Hex.decode(testData[4])
            val sig = testData[5]
            val expected = when (testData[6]) {
                "FALSE" -> false
                else -> true
            }
            val comment = testData[7]

            if (seckey.isNotEmpty()) {
                val ourSig = Secp256k1.signSchnorr(msg, seckey, auxrand)
                assertEquals(Hex.encode(ourSig).uppercase(), sig)
            }
            val result = try {
                Secp256k1.verifySchnorr(Hex.decode(sig), msg, pubkey)
            } catch (t: Throwable) {
                false
            }
            assertEquals(expected, result, "test [$index, $comment] failed")
        }
    }

    @Test
    fun testMusig2GenerateNonce() {
        val privkey = Hex.decode("0000000000000000000000000000000000000000000000000000000000000003")
        val pubkey = Hex.decode("02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
        val sessionId = Hex.decode("0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F")
        val nonce = Secp256k1.musigNonceGen(sessionId, null, pubkey, null, null, null)
        val pubnonce = Hex.encode(nonce.copyOfRange(132, 132 + 66)).uppercase()
        assertEquals("02C96E7CB1E8AA5DAC64D872947914198F607D90ECDE5200DE52978AD5DED63C000299EC5117C2D29EDEE8A2092587C3909BE694D5CFF0667D6C02EA4059F7CD9786", pubnonce)
        assertNotEquals(nonce, Secp256k1.musigNonceGen(sessionId, privkey, pubkey, null, null, null))
        assertNotEquals(nonce, Secp256k1.musigNonceGen(sessionId, null, pubkey, sessionId, null, null))
    }

    @Test
    fun testMusig2AggregateNonce() {
        val nonces = listOf(
            "020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E66603BA47FBC1834437B3212E89A84D8425E7BF12E0245D98262268EBDCB385D50641",
            "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B833",
            "020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E6660279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60379BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            // The following nonces are invalid.
            "04FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B833",
            "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B831",
            "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A602FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30"
        ).map { Hex.decode(it) }
        val agg1 = Secp256k1.musigNonceAgg(arrayOf(nonces[0], nonces[1]))
        assertEquals("035FE1873B4F2967F52FEA4A06AD5A8ECCBE9D0FD73068012C894E2E87CCB5804B024725377345BDE0E9C33AF3C43C0A29A9249F2F2956FA8CFEB55C8573D0262DC8", Hex.encode(agg1).uppercase())

        val agg2 = Secp256k1.musigNonceAgg(arrayOf(nonces[2], nonces[3]))
        assertEquals("035FE1873B4F2967F52FEA4A06AD5A8ECCBE9D0FD73068012C894E2E87CCB5804B000000000000000000000000000000000000000000000000000000000000000000", Hex.encode(agg2).uppercase())

        assertFails {
            Secp256k1.musigNonceAgg(arrayOf(nonces[0], nonces[4]))
        }
        assertFails {
            Secp256k1.musigNonceAgg(arrayOf(nonces[5], nonces[1]))
        }
        assertFails {
            Secp256k1.musigNonceAgg(arrayOf(nonces[6], nonces[1]))
        }
    }

    @Test
    fun testMusig2AggregatePubkey() {
        val pubkeys = listOf(
            "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
            "020000000000000000000000000000000000000000000000000000000000000005",
            "02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
            "04F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"
        ).map { Hex.decode(it) }

        val agg1 = Secp256k1.musigPubkeyAgg(arrayOf(pubkeys[0], pubkeys[1], pubkeys[2]), null)
        assertEquals("90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C", Hex.encode(agg1).uppercase())

        // We provide an empty cache, which will be filled when aggregating public keys.
        val keyaggCache = ByteArray(Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
        val agg2 = Secp256k1.musigPubkeyAgg(arrayOf(pubkeys[0], pubkeys[1], pubkeys[2]), keyaggCache)
        assertEquals("90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C", Hex.encode(agg2).uppercase())
        assertTrue(keyaggCache.count { it.toInt() != 0 } > 100) // the cache has been filled with key aggregation data

        // We can reuse the key aggregation cache to speed up computation.
        val agg3 = Secp256k1.musigPubkeyAgg(arrayOf(pubkeys[0], pubkeys[1], pubkeys[2]), keyaggCache)
        assertEquals("90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C", Hex.encode(agg3).uppercase())

        val agg4 = Secp256k1.musigPubkeyAgg(arrayOf(pubkeys[2], pubkeys[1], pubkeys[0]), null)
        assertEquals("6204DE8B083426DC6EAF9502D27024D53FC826BF7D2012148A0575435DF54B2B", Hex.encode(agg4).uppercase())

        val agg5 = Secp256k1.musigPubkeyAgg(arrayOf(pubkeys[0], pubkeys[0], pubkeys[0]), null)
        assertEquals("B436E3BAD62B8CD409969A224731C193D051162D8C5AE8B109306127DA3AA935", Hex.encode(agg5).uppercase())

        val agg6 = Secp256k1.musigPubkeyAgg(arrayOf(pubkeys[0], pubkeys[0], pubkeys[1], pubkeys[1]), null)
        assertEquals("69BC22BFA5D106306E48A20679DE1D7389386124D07571D0D872686028C26A3E", Hex.encode(agg6).uppercase())

        // If we provide the key aggregation cache for a different session, it is ignored and overwritten.
        val agg7 = Secp256k1.musigPubkeyAgg(arrayOf(pubkeys[0], pubkeys[0], pubkeys[1], pubkeys[1]), keyaggCache)
        assertEquals("69BC22BFA5D106306E48A20679DE1D7389386124D07571D0D872686028C26A3E", Hex.encode(agg7).uppercase())

        // If we provide random data in the key aggregation cache, it is ignored and overwritten.
        val agg8 = Secp256k1.musigPubkeyAgg(arrayOf(pubkeys[0], pubkeys[0], pubkeys[1], pubkeys[1]), Random.nextBytes(Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE))
        assertEquals("69BC22BFA5D106306E48A20679DE1D7389386124D07571D0D872686028C26A3E", Hex.encode(agg8).uppercase())
    }

    @Test
    fun testMusig2TweakPubkeys() {
        val pubkeys = listOf(
            "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
            "024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766",
            "02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337"
        ).map { Hex.decode(it) }.toTypedArray()
        val cache = ByteArray(Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
        val agg1 = Secp256k1.musigPubkeyAgg(pubkeys, cache)
        assertEquals("b6d830642403fc82511aca5ff98a5e76fcef0f89bffc1aadbe78ee74cd5a5716", Hex.encode(agg1))
        val agg2 = Secp256k1.musigPubkeyTweakAdd(cache, Hex.decode("7468697320636f756c64206265206120424950333220747765616b2e2e2e2e00"))
        assertEquals("04791e4f22a21f19bd9798eceab92ad2ccc18f2d6660e91ae4c0709aaebf1aa9023701f468b0eddf8973495a5327f2169d9c6a50eb6a0f87c0fbee90a4067eb230", Hex.encode(agg2))
        val agg3 = Secp256k1.musigPubkeyXonlyTweakAdd(cache, Hex.decode("7468697320636f756c64206265206120746170726f6f7420747765616b2e2e00"))
        assertEquals("04537a081a8d32ff700ca86aaa77a423e9b8d1480938076b645c68ee39d263c93948026928799b2d942cb5851db397015b26b1759de1b9ab2c691ced64a2eef836", Hex.encode(agg3))
    }

    @Test
    fun testMusig2SigningSession() {
        val privkeys = listOf(randomBytes(32), randomBytes(32))
        val sessionId = randomBytes(32)
        val msg32 = randomBytes(32)
        val pubkeys = privkeys.map { Secp256k1.pubkeyCreate(it) }
        val nonces = pubkeys.map { Secp256k1.musigNonceGen(sessionId, null, it, null, null, null) }
        val testData = run {
            val builder = StringBuilder()
            builder.append("private keys\n")
            privkeys.forEach { builder.append(Hex.encode(it)).append("\n") }
            builder.append("sessionId ${Hex.encode(sessionId)}\n")
            builder.append("msg32 ${Hex.encode(msg32)}\n")
            builder.append("nonces\n")
            nonces.forEach { builder.append(Hex.encode(it)).append("\n") }
            builder.toString()
        }
        val secnonces = nonces.map { it.copyOfRange(0, 132) }
        val pubnonces = nonces.map { it.copyOfRange(132, 132 + 66) }
        val aggnonce = Secp256k1.musigNonceAgg(pubnonces.toTypedArray())

        val keyaggCaches = (0 until 2).map { ByteArray(Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) }
        val aggpubkey = Secp256k1.musigPubkeyAgg(pubkeys.toTypedArray(), keyaggCaches[0])
        assertContentEquals(aggpubkey, Secp256k1.musigPubkeyAgg(pubkeys.toTypedArray(), keyaggCaches[1]), testData)
        assertContentEquals(keyaggCaches[0], keyaggCaches[1], testData)

        val sessions = (0 until 2).map { Secp256k1.musigNonceProcess(aggnonce, msg32, keyaggCaches[it]) }
        val psigs = (0 until 2).map {
            val psig = Secp256k1.musigPartialSign(secnonces[it], privkeys[it], keyaggCaches[it], sessions[it])
            assertEquals(1, Secp256k1.musigPartialSigVerify(psig, pubnonces[it], pubkeys[it], keyaggCaches[it], sessions[it]), testData)
            assertEquals(0, Secp256k1.musigPartialSigVerify(Random.nextBytes(32), pubnonces[it], pubkeys[it], keyaggCaches[it], sessions[it]), testData)
            psig
        }

        // signing fails if the secret nonce does not match the private key's public key
        assertFails(testData) {
            Secp256k1.musigPartialSign(secnonces[1], privkeys[0], keyaggCaches[0], sessions[0])
        }

        assertFails(testData) {
            Secp256k1.musigPartialSign(secnonces[0], privkeys[1], keyaggCaches[1], sessions[1])
        }

        val sig = Secp256k1.musigPartialSigAgg(sessions[0], psigs.toTypedArray())
        assertContentEquals(sig, Secp256k1.musigPartialSigAgg(sessions[1], psigs.toTypedArray()), testData)
        assertTrue(Secp256k1.verifySchnorr(sig, msg32, aggpubkey), testData)

        val invalidSig1 = Secp256k1.musigPartialSigAgg(sessions[0], arrayOf(psigs[0], psigs[0]))
        assertFalse(Secp256k1.verifySchnorr(invalidSig1, msg32, aggpubkey), testData)
        val invalidSig2 = Secp256k1.musigPartialSigAgg(sessions[0], arrayOf(Random.nextBytes(32), Random.nextBytes(32)))
        assertFalse(Secp256k1.verifySchnorr(invalidSig2, msg32, aggpubkey), testData)
    }

    @Test
    fun testInvalidArguments() {
        assertFails {
            Secp256k1.pubkeyCreate(ByteArray(32))
        }
        assertFails {
            Secp256k1.pubkeyCreate(Hex.decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))
        }
        assertFails {
            Secp256k1.pubkeyParse(ByteArray(33))
        }
        assertFails {
            Secp256k1.pubkeyParse(Hex.decode("03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))
        }
        assertFails {
            Secp256k1.pubKeyCombine(arrayOf())
        }
        assertFails {
            Secp256k1.pubKeyCombine(arrayOf(ByteArray(0)))
        }
        assertFails {
            Secp256k1.signSchnorr(ByteArray(0), Hex.decode("0101010101010101010101010101010101010101010101010101010101010101"), null)
        }
        assertFails {
            Secp256k1.ecdsaRecover(
                Hex.decode("01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101"),
                Hex.decode("0202020202020202020202020202020202020202020202020202020202020202"),
                -1
            )
        }
    }

    @Test
    fun fuzzMusig2SigningSession() {
        repeat(1000) {
            testMusig2SigningSession()
        }
    }

    @Test
    fun fuzzEcdsaSignVerify() {
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
