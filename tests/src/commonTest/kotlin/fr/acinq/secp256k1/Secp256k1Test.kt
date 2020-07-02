package fr.acinq.secp256k1

import kotlin.test.*


/**
 * This class holds test cases defined for testing this library.
 */
class Secp256k1Test {
    //TODO improve comments/add more tests
    /**
     * This tests verify() for a valid signature
     */
    @Test
    fun testVerifyPos() {
        var result: Boolean
        val data: ByteArray = Hex.decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90".toLowerCase()) //sha256hash of "testing"
        val sig: ByteArray = Hex.decode("3044022079BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980220294F14E883B3F525B5367756C2A11EF6CF84B730B36C17CB0C56F0AAB2C98589".toLowerCase())
        val pub: ByteArray = Hex.decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40".toLowerCase())
        result = Secp256k1.verify(sig, data, pub)
        assertTrue(result, "testVerifyPos")
        val sigCompact: ByteArray = Hex.decode("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798294F14E883B3F525B5367756C2A11EF6CF84B730B36C17CB0C56F0AAB2C98589".toLowerCase())
        result = Secp256k1.verify(sigCompact, data, pub)
        assertTrue(result, "testVerifyPos")
    }

    /**
     * This tests verify() for a non-valid signature
     */
    @Test
    fun testVerifyNeg() {
        var result: Boolean
        val data: ByteArray = Hex.decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A91".toLowerCase()) //sha256hash of "testing"
        val sig: ByteArray = Hex.decode("3044022079BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980220294F14E883B3F525B5367756C2A11EF6CF84B730B36C17CB0C56F0AAB2C98589".toLowerCase())
        val pub: ByteArray = Hex.decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40".toLowerCase())
        result = Secp256k1.verify(sig, data, pub)
        //System.out.println(" TEST " + new BigInteger(1, resultbytes).toString(16));
        assertFalse(result, "testVerifyNeg")
    }

    /**
     * This tests public key create() for a valid secretkey
     */
    @Test
    fun testPubKeyCreatePos() {
        val sec: ByteArray = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".toLowerCase())
        val resultArr: ByteArray = Secp256k1.pubkeyCreate(sec)
        val pubkeyString: String = Hex.encode(resultArr).toUpperCase()
        assertEquals(
            "04C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D2103ED494718C697AC9AEBCFD19612E224DB46661011863ED2FC54E71861E2A6",
            pubkeyString,
            "testPubKeyCreatePos"
        )
    }

    /**
     * This tests public key create() for a invalid secretkey
     */
    @Test
    fun testPubKeyCreateNeg() {
        val sec: ByteArray = Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".toLowerCase())
        assertFails {
            val resultArr: ByteArray = Secp256k1.pubkeyCreate(sec)
            val pubkeyString: String = Hex.encode(resultArr).toUpperCase()
            assertEquals("", pubkeyString, "testPubKeyCreateNeg")
        }
    }

    @Test
    fun testPubKeyNegatePos() {
        val sec: ByteArray = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".toLowerCase())
        val pubkey: ByteArray = Secp256k1.pubkeyCreate(sec)
        val pubkeyString: String = Hex.encode(pubkey).toUpperCase()
        assertEquals(
            "04C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D2103ED494718C697AC9AEBCFD19612E224DB46661011863ED2FC54E71861E2A6",
            pubkeyString,
            "testPubKeyCreatePos"
        )
        val pubkey1: ByteArray = Secp256k1.pubKeyNegate(pubkey)
        val pubkeyString1: String = Hex.encode(pubkey1).toUpperCase()
        assertEquals(
            "04C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2DDEFC12B6B8E73968536514302E69ED1DDB24B999EFEE79C12D03AB17E79E1989",
            pubkeyString1,
            "testPubKeyNegatePos"
        )
    }

    /**
     * This tests public key create() for a valid secretkey
     */
    @Test
    fun testPubKeyParse() {
        val pub: ByteArray = Hex.decode("02C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D".toLowerCase())
        val resultArr: ByteArray = Secp256k1.pubkeyParse(pub)
        val pubkeyString: String = Hex.encode(resultArr).toUpperCase()
        assertEquals(
            "04C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D2103ED494718C697AC9AEBCFD19612E224DB46661011863ED2FC54E71861E2A6",
            pubkeyString,
            "testPubKeyAdd"
        )
    }

    @Test
    fun testPubKeyAdd() {
        val pub1: ByteArray = Hex.decode("041b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f70beaf8f588b541507fed6a642c5ab42dfdf8120a7f639de5122d47a69a8e8d1".toLowerCase())
        val pub2: ByteArray = Hex.decode("044d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d07662a3eada2d0fe208b6d257ceb0f064284662e857f57b66b54c198bd310ded36d0".toLowerCase())
        val pub3: ByteArray = Secp256k1.pubKeyAdd(pub1, pub2)
        val pubkeyString: String = Hex.encode(pub3).toUpperCase()
        assertEquals(
            "04531FE6068134503D2723133227C867AC8FA6C83C537E9A44C3C5BDBDCB1FE3379E92C265E71E481BA82A84675A47AC705A200FCD524E92D93B0E7386F26A5458",
            pubkeyString,
            "testPubKeyAdd"
        )
    }

    /**
     * This tests sign() for a valid secretkey
     */
    @Test
    fun testSignPos() {
        val data: ByteArray = Hex.decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90".toLowerCase()) //sha256hash of "testing"
        val sec: ByteArray = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".toLowerCase())
        val resultArr: ByteArray = Secp256k1.sign(data, sec)
        val sigString: String = Hex.encode(resultArr).toUpperCase()
        assertEquals(
            "182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A21C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9",
            sigString,
            "testSignPos"
        )
    }

    @Test
    fun testSignatureNormalize() {
        val data: ByteArray = Hex.decode("30440220182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A202201C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9".toLowerCase())
        val (resultArr, isHighS) = Secp256k1.signatureNormalize(data)
        val sigString: String = Hex.encode(resultArr).toUpperCase()
        assertEquals(
            "182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A21C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9",
            sigString,
            "testSignPos"
        )
        assertFalse(isHighS, "isHighS")
    }

    /**
     * This tests sign() for a invalid secretkey
     */
    @Test
    fun testSignNeg() {
        val data: ByteArray = Hex.decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90".toLowerCase()) //sha256hash of "testing"
        val sec: ByteArray = Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".toLowerCase())
        assertFails {
            val resultArr: ByteArray = Secp256k1.sign(data, sec)
            val sigString: String = Hex.encode(resultArr)
            assertEquals("", sigString, "testSignNeg")
        }
    }

    @Test
    fun testSignCompactPos() {
        val data: ByteArray = Hex.decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90".toLowerCase()) //sha256hash of "testing"
        val sec: ByteArray = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".toLowerCase())
        val resultArr: ByteArray = Secp256k1.sign(data, sec)
        val sigString: String = Hex.encode(resultArr).toUpperCase()
        assertEquals(
            "182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A21C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9",
            sigString,
            "testSignCompactPos"
        )
        //assertEquals( sigString, "30 44 02 20 182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A2 02 20 1C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9" , "testSignPos");
    }

    @Test
    fun testPrivKeyTweakNegate() {
        val sec: ByteArray = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".toLowerCase())
        val sec1: ByteArray = Secp256k1.privKeyNegate(sec)
        assertEquals(
            "981A9A7DD677A622518DA068D66D5F824E5F22F084B8A0E2F195B5662F300C11",
            Hex.encode(sec1).toUpperCase(),
            "testPrivKeyNegate"
        )
        val sec2: ByteArray = Secp256k1.privKeyNegate(sec1)
        assertTrue(sec.contentEquals(sec2))
    }

    /**
     * This tests private key tweak-add
     */
    @Test
    fun testPrivKeyTweakAdd_1() {
        val sec: ByteArray = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".toLowerCase())
        val data: ByteArray = Hex.decode("3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3".toLowerCase()) //sha256hash of "tweak"
        val resultArr: ByteArray = Secp256k1.privKeyTweakAdd(sec, data)
        val sigString: String = Hex.encode(resultArr).toUpperCase()
        assertEquals(
            "A168571E189E6F9A7E2D657A4B53AE99B909F7E712D1C23CED28093CD57C88F3",
            sigString,
            "testPrivKeyAdd_1"
        )
    }

    /**
     * This tests private key tweak-mul
     */
    @Test
    fun testPrivKeyTweakMul_1() {
        val sec: ByteArray = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".toLowerCase())
        val data: ByteArray = Hex.decode("3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3".toLowerCase()) //sha256hash of "tweak"
        val resultArr: ByteArray = Secp256k1.privKeyTweakMul(sec, data)
        val sigString: String = Hex.encode(resultArr).toUpperCase()
        assertEquals(
            "97F8184235F101550F3C71C927507651BD3F1CDB4A5A33B8986ACF0DEE20FFFC",
            sigString,
            "testPrivKeyMul_1"
        )
    }

    /**
     * This tests private key tweak-add uncompressed
     */
    @Test
    fun testPrivKeyTweakAdd_2() {
        val pub: ByteArray = Hex.decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40".toLowerCase())
        val data: ByteArray = Hex.decode("3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3".toLowerCase()) //sha256hash of "tweak"
        val resultArr: ByteArray = Secp256k1.pubKeyTweakAdd(pub, data)
        val sigString: String = Hex.encode(resultArr).toUpperCase()
        assertEquals(
            "0411C6790F4B663CCE607BAAE08C43557EDC1A4D11D88DFCB3D841D0C6A941AF525A268E2A863C148555C48FB5FBA368E88718A46E205FABC3DBA2CCFFAB0796EF",
            sigString,
            "testPrivKeyAdd_2"
        )
    }

    /**
     * This tests private key tweak-mul uncompressed
     */
    @Test
    fun testPrivKeyTweakMul_2() {
        val pub: ByteArray = Hex.decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40".toLowerCase())
        val data: ByteArray = Hex.decode("3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3".toLowerCase()) //sha256hash of "tweak"
        val resultArr: ByteArray = Secp256k1.pubKeyTweakMul(pub, data)
        val sigString: String = Hex.encode(resultArr).toUpperCase()
        assertEquals(
            "04E0FE6FE55EBCA626B98A807F6CAF654139E14E5E3698F01A9A658E21DC1D2791EC060D4F412A794D5370F672BC94B722640B5F76914151CFCA6E712CA48CC589",
            sigString,
            "testPrivKeyMul_2"
        )
    }

    @Test
    fun testCreateECDHSecret() {
        val sec: ByteArray = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".toLowerCase())
        val pub: ByteArray = Hex.decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40".toLowerCase())
        val resultArr: ByteArray = Secp256k1.ecdh(sec, pub)
        val ecdhString: String = Hex.encode(resultArr).toUpperCase()
        assertEquals(
            "2A2A67007A926E6594AF3EB564FC74005B37A9C8AEF2033C4552051B5C87F043",
            ecdhString,
            "testCreateECDHSecret"
        )
    }

    @Test
    fun testEcdsaRecover() {
        val data: ByteArray = Hex.decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90".toLowerCase()) //sha256hash of "testing"
        val sec: ByteArray = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".toLowerCase())
        val pub: ByteArray = Secp256k1.pubkeyCreate(sec)
        val sig: ByteArray = Secp256k1.sign(data, sec)
        val pub0: ByteArray = Secp256k1.ecdsaRecover(sig, data, 0)
        val pub1: ByteArray = Secp256k1.ecdsaRecover(sig, data, 1)
        assertTrue(pub.contentEquals(pub0) || pub.contentEquals(pub1), "testEcdsaRecover")
    }
}
