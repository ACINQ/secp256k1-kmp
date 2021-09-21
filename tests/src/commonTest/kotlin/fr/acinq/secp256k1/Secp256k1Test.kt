package fr.acinq.secp256k1

import kotlin.random.Random
import kotlin.test.*


/**
 * This class holds test cases defined for testing this library.
 */
class Secp256k1Test {
    //TODO improve comments/add more tests

    @Test
    fun testVerifyPos() {
        var result: Boolean
        val data: ByteArray = Hex.decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90".lowercase()) //sha256hash of "testing"
        val sig: ByteArray = Hex.decode("3044022079BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980220294F14E883B3F525B5367756C2A11EF6CF84B730B36C17CB0C56F0AAB2C98589".lowercase())
        val pub: ByteArray = Hex.decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40".lowercase())
        result = Secp256k1.verify(sig, data, pub)
        assertTrue(result, "testVerifyPos")
        val sigCompact: ByteArray = Hex.decode("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798294F14E883B3F525B5367756C2A11EF6CF84B730B36C17CB0C56F0AAB2C98589".lowercase())
        result = Secp256k1.verify(sigCompact, data, pub)
        assertTrue(result, "testVerifyPos")
    }

    @Test
    fun testVerifyNeg() {
        var result: Boolean
        val data: ByteArray = Hex.decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A91".lowercase()) //sha256hash of "testing"
        val sig: ByteArray = Hex.decode("3044022079BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980220294F14E883B3F525B5367756C2A11EF6CF84B730B36C17CB0C56F0AAB2C98589".lowercase())
        val pub: ByteArray = Hex.decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40".lowercase())
        result = Secp256k1.verify(sig, data, pub)
        assertFalse(result, "testVerifyNeg")
    }

    @Test
    fun testSecKeyVerifyPos() {
        var result: Boolean
        val sec: ByteArray = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".lowercase())
        result = Secp256k1.secKeyVerify(sec)
        assertTrue(result, "testSecKeyVerifyPos")
    }

    @Test
    fun testSecKeyVerifyNeg() {
        var result: Boolean
        val sec: ByteArray = Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".lowercase())
        result = Secp256k1.secKeyVerify(sec)
        assertFalse(result, "testSecKeyVerifyNeg")
    }

    @Test
    fun testPubKeyCreatePos() {
        val sec: ByteArray = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".lowercase())
        val resultArr: ByteArray = Secp256k1.pubkeyCreate(sec)
        val pubkeyString: String = Hex.encode(resultArr).uppercase()
        assertEquals(
            "04C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D2103ED494718C697AC9AEBCFD19612E224DB46661011863ED2FC54E71861E2A6",
            pubkeyString,
            "testPubKeyCreatePos"
        )
    }

    @Test
    fun testPubKeyCreateNeg() {
        val sec: ByteArray = Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".lowercase())
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.pubkeyCreate(sec)
        }
    }

    @Test
    fun testPubkeyCompress() {
        val pub = Hex.decode("04C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D2103ED494718C697AC9AEBCFD19612E224DB46661011863ED2FC54E71861E2A6")
        val compressed = Secp256k1.pubKeyCompress(pub)
        assertEquals("02C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D", Hex.encode(compressed).uppercase())
    }

    @Test
    fun testPubKeyNegatePos() {
        val sec: ByteArray = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".lowercase())
        val pubkey: ByteArray = Secp256k1.pubkeyCreate(sec)
        val pubkeyString: String = Hex.encode(pubkey).uppercase()
        assertEquals(
            "04C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D2103ED494718C697AC9AEBCFD19612E224DB46661011863ED2FC54E71861E2A6",
            pubkeyString,
            "testPubKeyCreatePos"
        )
        val pubkey1: ByteArray = Secp256k1.pubKeyNegate(pubkey)
        val pubkeyString1: String = Hex.encode(pubkey1).uppercase()
        assertEquals(
            "04C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2DDEFC12B6B8E73968536514302E69ED1DDB24B999EFEE79C12D03AB17E79E1989",
            pubkeyString1,
            "testPubKeyNegatePos"
        )
    }

    @Test
    fun testPubKeyParse() {
        val pub: ByteArray = Hex.decode("02C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D".lowercase())
        val resultArr: ByteArray = Secp256k1.pubkeyParse(pub)
        val pubkeyString: String = Hex.encode(resultArr).uppercase()
        assertEquals(
            "04C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D2103ED494718C697AC9AEBCFD19612E224DB46661011863ED2FC54E71861E2A6",
            pubkeyString,
            "testPubKeyAdd"
        )
    }

    @Test
    fun testPubKeyAdd() {
        val pub1: ByteArray = Hex.decode("041b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f70beaf8f588b541507fed6a642c5ab42dfdf8120a7f639de5122d47a69a8e8d1".lowercase())
        val pub2: ByteArray = Hex.decode("044d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d07662a3eada2d0fe208b6d257ceb0f064284662e857f57b66b54c198bd310ded36d0".lowercase())
        val pub3: ByteArray = Secp256k1.pubKeyAdd(pub1, pub2)
        val pubkeyString: String = Hex.encode(pub3).uppercase()
        assertEquals(
            "04531FE6068134503D2723133227C867AC8FA6C83C537E9A44C3C5BDBDCB1FE3379E92C265E71E481BA82A84675A47AC705A200FCD524E92D93B0E7386F26A5458",
            pubkeyString,
            "testPubKeyAdd"
        )
    }

    @Test
    fun testSignPos() {
        val data: ByteArray = Hex.decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90".lowercase()) //sha256hash of "testing"
        val sec: ByteArray = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".lowercase())
        val resultArr: ByteArray = Secp256k1.sign(data, sec)
        val sigString: String = Hex.encode(resultArr).uppercase()
        assertEquals(
            "182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A21C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9",
            sigString,
            "testSignPos"
        )
    }

    @Test
    fun testSignatureNormalize() {
        val data: ByteArray = Hex.decode("30440220182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A202201C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9".lowercase())
        val (resultArr, isHighS) = Secp256k1.signatureNormalize(data)
        val sigString: String = Hex.encode(resultArr).uppercase()
        assertEquals(
            "182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A21C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9",
            sigString,
            "testSignPos"
        )
        assertFalse(isHighS, "isHighS")
    }

    @Test
    fun testSignNeg() {
        val data: ByteArray = Hex.decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90".lowercase()) //sha256hash of "testing"
        val sec: ByteArray = Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".lowercase())
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.sign(data, sec)
        }
    }

    @Test
    fun testSignCompactPos() {
        val data: ByteArray = Hex.decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90".lowercase()) //sha256hash of "testing"
        val sec: ByteArray = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".lowercase())
        val resultArr: ByteArray = Secp256k1.sign(data, sec)
        val sigString: String = Hex.encode(resultArr).uppercase()
        assertEquals(
            "182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A21C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9",
            sigString,
            "testSignCompactPos"
        )
    }

    @Test
    fun testPrivKeyTweakNegate() {
        val sec: ByteArray = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".lowercase())
        val sec1: ByteArray = Secp256k1.privKeyNegate(sec)
        assertEquals(
            "981A9A7DD677A622518DA068D66D5F824E5F22F084B8A0E2F195B5662F300C11",
            Hex.encode(sec1).uppercase(),
            "testPrivKeyNegate"
        )
        val sec2: ByteArray = Secp256k1.privKeyNegate(sec1)
        assertTrue(sec.contentEquals(sec2))
    }

    @Test
    fun testPrivKeyTweakAdd_1() {
        val sec: ByteArray = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".lowercase())
        val data: ByteArray = Hex.decode("3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3".lowercase()) //sha256hash of "tweak"
        val resultArr: ByteArray = Secp256k1.privKeyTweakAdd(sec, data)
        val sigString: String = Hex.encode(resultArr).uppercase()
        assertEquals(
            "A168571E189E6F9A7E2D657A4B53AE99B909F7E712D1C23CED28093CD57C88F3",
            sigString,
            "testPrivKeyAdd_1"
        )
    }

    @Test
    fun testPrivKeyTweakMul_1() {
        val sec: ByteArray = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".lowercase())
        val data: ByteArray = Hex.decode("3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3".lowercase()) //sha256hash of "tweak"
        val resultArr: ByteArray = Secp256k1.privKeyTweakMul(sec, data)
        val sigString: String = Hex.encode(resultArr).uppercase()
        assertEquals(
            "97F8184235F101550F3C71C927507651BD3F1CDB4A5A33B8986ACF0DEE20FFFC",
            sigString,
            "testPrivKeyMul_1"
        )
    }

    @Test
    fun testPrivKeyTweakAdd_2() {
        val pub: ByteArray = Hex.decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40".lowercase())
        val data: ByteArray = Hex.decode("3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3".lowercase()) //sha256hash of "tweak"
        val resultArr: ByteArray = Secp256k1.pubKeyTweakAdd(pub, data)
        val sigString: String = Hex.encode(resultArr).uppercase()
        assertEquals(
            "0411C6790F4B663CCE607BAAE08C43557EDC1A4D11D88DFCB3D841D0C6A941AF525A268E2A863C148555C48FB5FBA368E88718A46E205FABC3DBA2CCFFAB0796EF",
            sigString,
            "testPrivKeyAdd_2"
        )
    }

    @Test
    fun testPrivKeyTweakMul_2() {
        val pub: ByteArray = Hex.decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40".lowercase())
        val data: ByteArray = Hex.decode("3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3".lowercase()) //sha256hash of "tweak"
        val resultArr: ByteArray = Secp256k1.pubKeyTweakMul(pub, data)
        val sigString: String = Hex.encode(resultArr).uppercase()
        assertEquals(
            "04E0FE6FE55EBCA626B98A807F6CAF654139E14E5E3698F01A9A658E21DC1D2791EC060D4F412A794D5370F672BC94B722640B5F76914151CFCA6E712CA48CC589",
            sigString,
            "testPrivKeyMul_2"
        )
    }

    @Test
    fun testCreateECDHSecret() {
        val sec: ByteArray = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".lowercase())
        val pub: ByteArray = Hex.decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40".lowercase())
        val resultArr: ByteArray = Secp256k1.ecdh(sec, pub)
        val ecdhString: String = Hex.encode(resultArr).uppercase()
        assertEquals(
            "2A2A67007A926E6594AF3EB564FC74005B37A9C8AEF2033C4552051B5C87F043",
            ecdhString,
            "testCreateECDHSecret"
        )
    }

    @Test
    fun testEcdsaRecover() {
        val data: ByteArray = Hex.decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90".lowercase()) //sha256hash of "testing"
        val sec: ByteArray = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".lowercase())
        val pub: ByteArray = Secp256k1.pubkeyCreate(sec)
        val sig: ByteArray = Secp256k1.sign(data, sec)
        val pub0: ByteArray = Secp256k1.ecdsaRecover(sig, data, 0)
        val pub1: ByteArray = Secp256k1.ecdsaRecover(sig, data, 1)
        assertTrue(pub.contentEquals(pub0) || pub.contentEquals(pub1), "testEcdsaRecover")
    }

    @Test
    fun testCompactToDER() {
        val sig: ByteArray = Hex.decode("182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A21C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9".lowercase()) //sha256hash of "testing"
        val der: ByteArray = Secp256k1.compact2der(sig)
        assertEquals(
            "30440220182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A202201C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9",
            Hex.encode(der).uppercase(),
        )
    }

    @Test
    fun testFormatConversion() {
        val random = Random.Default

        fun randomBytes(length: Int): ByteArray {
            val buffer = ByteArray(length)
            random.nextBytes(buffer)
            return buffer
        }

        repeat(200) {
            val priv = randomBytes(32)
            val pub = Secp256k1.pubkeyCreate(priv)
            val data = randomBytes(32)
            val sig = Secp256k1.sign(data, priv)
            val der = Secp256k1.compact2der(sig)
            Secp256k1.verify(der, data, pub)
        }
    }

    @Test
    fun testSchnorrSignature() {
        val seckey = Hex.decode("0000000000000000000000000000000000000000000000000000000000000003")
        val msg = Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")
        val auxrand32 = Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")
        val sig = Secp256k1.signSchnorr(msg, seckey, auxrand32)
        assertEquals(
            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
            Hex.encode(sig).toUpperCase(),
        )
        val pubkey = Secp256k1.pubkeyCreate(seckey).drop(1).take(32).toByteArray()
        assertEquals(
            "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            Hex.encode(pubkey).toUpperCase()
        )
        assertTrue(Secp256k1.verifySchnorr(sig, msg, pubkey))
    }

    @Test
    fun testSchnorrTestVectors() {
        //@formatter:off
        val testVectors = listOf(
            //listOf("index","secret key","public key","aux_rand","message","signature","verification result","comment"),
            listOf("0","0000000000000000000000000000000000000000000000000000000000000003","F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9","0000000000000000000000000000000000000000000000000000000000000000","0000000000000000000000000000000000000000000000000000000000000000","E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0","TRUE",""),
            listOf("1","B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF","DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659","0000000000000000000000000000000000000000000000000000000000000001","243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89","6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A","TRUE",""),
            listOf("2","C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9","DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8","C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906","7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C","5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7","TRUE",""),
            listOf("3","0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710","25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517","FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF","FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF","7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3","TRUE","test fails if msg is reduced modulo p or n"),
            listOf("4","","D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9","","4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703","00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4","TRUE",""),
            listOf("5","","EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34","","243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89","6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B","FALSE","public key not on the curve"),
            listOf("6","","DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659","","243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89","FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2","FALSE","has_even_y(R) is false"),
            listOf("7","","DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659","","243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89","1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD","FALSE","negated message"),
            listOf("8","","DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659","","243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89","6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6","FALSE","negated s value"),
            listOf("9","","DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659","","243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89","0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051","FALSE","sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 0"),
            listOf("10","","DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659","","243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89","00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197","FALSE","sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 1"),
            listOf("11","","DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659","","243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89","4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B","FALSE","siglistOf(0:32), is not an X coordinate on the curve"),
            listOf("12","","DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659","","243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89","FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B","FALSE","siglistOf(0:32), is equal to field size"),
            listOf("13","","DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659","","243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89","6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141","FALSE","siglistOf(32:64), is equal to curve order"),
            listOf("14","","FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30","","243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89","6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B","FALSE","public key is not a valid X coordinate because it exceeds the field size"),
        )
        //@formatter:on
        testVectors.forEach {
            val index = it[0]
            val seckey = Hex.decode(it[1])
            val pubkey = Hex.decode(it[2])
            val auxrand = if (it[3].isEmpty()) null else Hex.decode(it[3])
            val msg = Hex.decode(it[4])
            val sig = it[5]
            val expected = when (it[6]) {
                "FALSE" -> false
                else -> true
            }
            val comment = it[7]

            if (seckey.isNotEmpty()) {
                val ourSig = Secp256k1.signSchnorr(msg, seckey, auxrand)
                assertEquals(Hex.encode(ourSig).toUpperCase(), sig)
            }
            val result = try {
                Secp256k1.verifySchnorr(Hex.decode(sig), msg, pubkey)
            } catch (t: Throwable) {
                false
            }
            assertEquals(expected, result, "test [$index, $comment] failed")
        }
    }
}
