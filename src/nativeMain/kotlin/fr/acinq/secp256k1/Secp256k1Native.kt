package fr.acinq.secp256k1

import kotlinx.cinterop.*
import platform.posix.size_tVar
import secp256k1.*

@OptIn(ExperimentalUnsignedTypes::class)
public object Secp256k1Native : Secp256k1 {

    private val ctx: CPointer<secp256k1_context> by lazy {
        secp256k1_context_create((SECP256K1_FLAGS_TYPE_CONTEXT or SECP256K1_FLAGS_BIT_CONTEXT_SIGN or SECP256K1_FLAGS_BIT_CONTEXT_VERIFY).toUInt())
            ?: error("Could not create secp256k1 context")
    }

    private fun Int.requireSuccess(message: String): Int = if (this != 1) throw Secp256k1Exception(message) else this

    private fun MemScope.allocSignature(input: ByteArray): secp256k1_ecdsa_signature {
        val sig = alloc<secp256k1_ecdsa_signature>()
        val nativeBytes = toNat(input)

        val result = when {
            input.size == 64 -> secp256k1_ecdsa_signature_parse_compact(ctx, sig.ptr, nativeBytes)
            input.size < 64 -> throw Secp256k1Exception("Unknown signature format")
            else -> secp256k1_ecdsa_signature_parse_der(ctx, sig.ptr, nativeBytes, input.size.convert())
        }
        result.requireSuccess("cannot parse signature (size = ${input.size} sig = ${Hex.encode(input)}")
        return sig
    }

    private fun MemScope.serializeSignature(signature: secp256k1_ecdsa_signature): ByteArray {
        val natOutput = allocArray<UByteVar>(64)
        secp256k1_ecdsa_signature_serialize_compact(ctx, natOutput, signature.ptr).requireSuccess("secp256k1_ecdsa_signature_serialize_compact() failed")
        return natOutput.readBytes(64)
    }

    private fun MemScope.allocPublicKey(pubkey: ByteArray): secp256k1_pubkey {
        val natPub = toNat(pubkey)
        val pub = alloc<secp256k1_pubkey>()
        secp256k1_ec_pubkey_parse(ctx, pub.ptr, natPub, pubkey.size.convert()).requireSuccess("secp256k1_ec_pubkey_parse() failed")
        return pub
    }

    private fun MemScope.serializePubkey(pubkey: secp256k1_pubkey): ByteArray {
        val serialized = allocArray<UByteVar>(65)
        val outputLen = alloc<size_tVar>()
        outputLen.value = 65.convert()
        secp256k1_ec_pubkey_serialize(ctx, serialized, outputLen.ptr, pubkey.ptr, SECP256K1_EC_UNCOMPRESSED.convert()).requireSuccess("secp256k1_ec_pubkey_serialize() failed")
        return serialized.readBytes(outputLen.value.convert())
    }

    private fun DeferScope.toNat(bytes: ByteArray): CPointer<UByteVar>  {
        val ubytes = bytes.asUByteArray()
        val pinned = ubytes.pin()
        this.defer { pinned.unpin() }
        return pinned.addressOf(0)
    }

    public override fun verify(signature: ByteArray, message: ByteArray, pubkey: ByteArray): Boolean {
        require(message.size == 32)
        require(pubkey.size == 33 || pubkey.size == 65)
        memScoped {
            val nPubkey = allocPublicKey(pubkey)
            val nMessage = toNat(message)
            val nSig = allocSignature(signature)
            return secp256k1_ecdsa_verify(ctx, nSig.ptr, nMessage, nPubkey.ptr) == 1
        }
    }

    public override fun sign(message: ByteArray, privkey: ByteArray): ByteArray {
        require(privkey.size == 32)
        require(message.size == 32)
        memScoped {
            val nPrivkey = toNat(privkey)
            val nMessage = toNat(message)
            val nSig = alloc<secp256k1_ecdsa_signature>()
            secp256k1_ecdsa_sign(ctx, nSig.ptr, nMessage, nPrivkey, null, null).requireSuccess("secp256k1_ecdsa_sign() failed")
            return serializeSignature(nSig)
        }
    }

    public override fun signatureNormalize(sig: ByteArray): Pair<ByteArray, Boolean> {
        require(sig.size >= 64){ "invalid signature ${Hex.encode(sig)}" }
        memScoped {
            val nSig = allocSignature(sig)
            val isHighS = secp256k1_ecdsa_signature_normalize(ctx, nSig.ptr, nSig.ptr)
            return Pair(serializeSignature(nSig), isHighS == 1)
        }
    }

    public override fun secKeyVerify(privkey: ByteArray): Boolean {
        if (privkey.size != 32) return false
        memScoped {
            val nPrivkey = toNat(privkey)
            return secp256k1_ec_seckey_verify(ctx, nPrivkey) == 1
        }
    }

    public override fun pubkeyCreate(privkey: ByteArray): ByteArray {
        require(privkey.size == 32)
        memScoped {
            val nPrivkey = toNat(privkey)
            val nPubkey = alloc<secp256k1_pubkey>()
            secp256k1_ec_pubkey_create(ctx, nPubkey.ptr, nPrivkey).requireSuccess("secp256k1_ec_pubkey_create() failed")
            return serializePubkey(nPubkey)
        }
    }

    public override fun pubkeyParse(pubkey: ByteArray): ByteArray {
        require(pubkey.size == 33 || pubkey.size == 65)
        memScoped {
            val nPubkey = allocPublicKey(pubkey)
            return serializePubkey(nPubkey)
        }
    }

    public override fun privKeyNegate(privkey: ByteArray): ByteArray {
        require(privkey.size == 32)
        memScoped {
            val negated = privkey.copyOf()
            val negPriv = toNat(negated)
            secp256k1_ec_privkey_negate(ctx, negPriv).requireSuccess("secp256k1_ec_privkey_negate() failed")
            return negated
        }
    }

    public override fun privKeyTweakAdd(privkey: ByteArray, tweak: ByteArray): ByteArray {
        require(privkey.size == 32)
        memScoped {
            val added = privkey.copyOf()
            val natAdd = toNat(added)
            val natTweak = toNat(tweak)
            secp256k1_ec_privkey_tweak_add(ctx, natAdd, natTweak).requireSuccess("secp256k1_ec_privkey_tweak_add() failed")
            return added
        }
    }

    public override fun privKeyTweakMul(privkey: ByteArray, tweak: ByteArray): ByteArray {
        require(privkey.size == 32)
        memScoped {
            val multiplied = privkey.copyOf()
            val natMul = toNat(multiplied)
            val natTweak = toNat(tweak)
            secp256k1_ec_privkey_tweak_mul(ctx, natMul, natTweak).requireSuccess("secp256k1_ec_privkey_tweak_mul() failed")
            return multiplied
        }
    }

    public override fun pubKeyNegate(pubkey: ByteArray): ByteArray {
        require(pubkey.size == 33 || pubkey.size == 65)
        memScoped {
            val nPubkey = allocPublicKey(pubkey)
            secp256k1_ec_pubkey_negate(ctx, nPubkey.ptr).requireSuccess("secp256k1_ec_pubkey_negate() failed")
            return serializePubkey(nPubkey)
        }
    }

    public override fun pubKeyTweakAdd(pubkey: ByteArray, tweak: ByteArray): ByteArray {
        require(pubkey.size == 33 || pubkey.size == 65)
        memScoped {
            val nPubkey = allocPublicKey(pubkey)
            val nTweak = toNat(tweak)
            secp256k1_ec_pubkey_tweak_add(ctx, nPubkey.ptr, nTweak).requireSuccess("secp256k1_ec_pubkey_tweak_add() failed")
            return serializePubkey(nPubkey)
        }
    }

    public override fun pubKeyTweakMul(pubkey: ByteArray, tweak: ByteArray): ByteArray {
        require(pubkey.size == 33 || pubkey.size == 65)
        memScoped {
            val nPubkey = allocPublicKey(pubkey)
            val nTweak = toNat(tweak)
            secp256k1_ec_pubkey_tweak_mul(ctx, nPubkey.ptr, nTweak).requireSuccess("secp256k1_ec_pubkey_tweak_mul() failed")
            return serializePubkey(nPubkey)
        }
    }

    public override fun pubKeyCombine(pubkeys: Array<ByteArray>): ByteArray {
        pubkeys.forEach { require(it.size == 33 || it.size == 65) }
        memScoped {
            val nPubkeys = pubkeys.map { allocPublicKey(it).ptr }
            val combined = alloc<secp256k1_pubkey>()
            secp256k1_ec_pubkey_combine(ctx, combined.ptr, nPubkeys.toCValues(), pubkeys.size.convert()).requireSuccess("secp256k1_ec_pubkey_combine() failed")
            return serializePubkey(combined)
        }
    }

    public override fun ecdh(privkey: ByteArray, pubkey: ByteArray): ByteArray {
        require(privkey.size == 32)
        require(pubkey.size == 33 || pubkey.size == 65)
        memScoped {
            val nPubkey = allocPublicKey(pubkey)
            val nPrivkey = toNat(privkey)
            val output = allocArray<UByteVar>(32)
            secp256k1_ecdh(ctx, output, nPubkey.ptr, nPrivkey, null, null).requireSuccess("secp256k1_ecdh() failed")
            return output.readBytes(32)
        }
    }

    public override fun ecdsaRecover(sig: ByteArray, message: ByteArray, recid: Int): ByteArray {
        require(sig.size == 64)
        require(message.size == 32)
        memScoped {
            val nSig = toNat(sig)
            val rSig = alloc<secp256k1_ecdsa_recoverable_signature>()
            secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, rSig.ptr, nSig, recid).requireSuccess("secp256k1_ecdsa_recoverable_signature_parse_compact() failed")
            val nMessage = toNat(message)
            val pubkey = alloc<secp256k1_pubkey>()
            secp256k1_ecdsa_recover(ctx, pubkey.ptr, rSig.ptr, nMessage).requireSuccess("secp256k1_ecdsa_recover() failed")
            return serializePubkey(pubkey)
        }
    }

    public override fun compact2der(sig: ByteArray): ByteArray {
        require(sig.size == 64)
        memScoped {
            val nSig = allocSignature(sig)
            val natOutput = allocArray<UByteVar>(73)
            val len = alloc<size_tVar>()
            len.value = 73.convert()
            secp256k1_ecdsa_signature_serialize_der(ctx, natOutput, len.ptr, nSig.ptr).requireSuccess("secp256k1_ecdsa_signature_serialize_der() failed")
            return natOutput.readBytes(len.value.toInt())
        }
    }

    override fun verifySchnorr(signature: ByteArray, data: ByteArray, pub: ByteArray): Boolean {
        require(signature.size == 64)
        require(data.size == 32)
        require(pub.size == 32)
        memScoped {
            val nPub = toNat(pub)
            val pubkey = alloc<secp256k1_xonly_pubkey>()
            secp256k1_xonly_pubkey_parse(ctx, pubkey.ptr, nPub).requireSuccess("secp256k1_xonly_pubkey_parse() failed")
            val nData = toNat(data)
            val nSig = toNat(signature)
            return secp256k1_schnorrsig_verify(ctx, nSig, nData, 32, pubkey.ptr) == 1
        }
    }

    override fun signSchnorr(data: ByteArray, sec: ByteArray, auxrand32: ByteArray?): ByteArray {
        require(sec.size == 32)
        require(data.size == 32)
        auxrand32?.let { require(it.size == 32) }
        memScoped {
            val nSec = toNat(sec)
            val nData = toNat(data)
            val nAuxrand32 = auxrand32?.let { toNat(it) }
            val nSig = allocArray<UByteVar>(64)
            val keypair = alloc<secp256k1_keypair>()
            secp256k1_keypair_create(ctx, keypair.ptr, nSec).requireSuccess("secp256k1_keypair_create() failed")
            secp256k1_schnorrsig_sign(ctx, nSig, nData, keypair.ptr, nAuxrand32).requireSuccess("secp256k1_ecdsa_sign() failed")
            return nSig.readBytes(64)
        }
    }
    
    public override fun cleanup() {
        secp256k1_context_destroy(ctx)
    }


}

internal actual fun getSecpk256k1(): Secp256k1 = Secp256k1Native
