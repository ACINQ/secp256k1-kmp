package fr.acinq.secp256k1

import kotlin.random.Random

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
fun main() {
    val random = Random(System.currentTimeMillis())

    fun randomBytes(size: Int): ByteArray = random.nextBytes(size)

    var counter = 0
    var success = 0

    while(counter < 5000) {
        val privkeys = listOf(randomBytes(32), randomBytes(32))
        val msg32 = randomBytes(32)
        val pubkeys = privkeys.map { Secp256k1.pubkeyCreate(it) }
        val keyaggCaches = (0 until 2).map { ByteArray(Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) }
        val aggpubkey = Secp256k1.musigPubkeyAgg(pubkeys.toTypedArray(), keyaggCaches[0])
        Secp256k1.musigPubkeyAgg(pubkeys.toTypedArray(), keyaggCaches[1])

        val nonces = privkeys.indices.map {
            Secp256k1.musigNonceGen(randomBytes(32), privkeys[it], pubkeys[it], msg32, keyaggCaches[it], randomBytes(32))
        }
        val secnonces = nonces.map { it.copyOfRange(0, 132) }
        val pubnonces = nonces.map { it.copyOfRange(132, 132 + 66) }
        val aggnonce = Secp256k1.musigNonceAgg(pubnonces.toTypedArray())


        val sessions = (0 until 2).map { Secp256k1.musigNonceProcess(aggnonce, msg32, keyaggCaches[it]) }
        val psigs = (0 until 2).map {
            val psig = Secp256k1.musigPartialSign(secnonces[it], privkeys[it], keyaggCaches[it], sessions[it])
            assert(1 == Secp256k1.musigPartialSigVerify(psig, pubnonces[it], pubkeys[it], keyaggCaches[it], sessions[it]))
            psig
        }

        val sig = Secp256k1.musigPartialSigAgg(sessions[0], psigs.toTypedArray())

        if (Secp256k1.verifySchnorr(sig, msg32, aggpubkey)) success++
        if (counter++ % 10000 == 0) println("$counter $success")
    }
}