package fr.acinq.secp256k1

import kotlinx.cinterop.*
import platform.posix.size_tVar
import secp256k1.*

@OptIn(ExperimentalUnsignedTypes::class)
public actual object Secp256k1 {

    private const val SIG_FORMAT_UNKNOWN = 0
    private const val SIG_FORMAT_COMPACT = 1
    private const val SIG_FORMAT_DER = 2

    private val ctx: CPointer<secp256k1_context> by lazy {
        secp256k1_context_create((SECP256K1_FLAGS_TYPE_CONTEXT or SECP256K1_FLAGS_BIT_CONTEXT_SIGN or SECP256K1_FLAGS_BIT_CONTEXT_VERIFY).toUInt())
            ?: error("Could not create segp256k1 context")
    }

    private fun Int.requireSuccess() = require(this == 1) { "secp256k1 native function call failed" }

    private fun MemScope.allocSignature(input: ByteArray): secp256k1_ecdsa_signature {
        val sigFormat = when (input.size) {
            64 -> SIG_FORMAT_COMPACT
            70, 71, 72, 73 -> SIG_FORMAT_DER
            else -> SIG_FORMAT_UNKNOWN
        }
        val sig = alloc<secp256k1_ecdsa_signature>()
        val nativeBytes = toNat(input)
        val result = when (sigFormat) {
            SIG_FORMAT_COMPACT -> secp256k1_ecdsa_signature_parse_compact(ctx, sig.ptr, nativeBytes)
            SIG_FORMAT_DER -> secp256k1_ecdsa_signature_parse_der(ctx, sig.ptr, nativeBytes, input.size.toULong())
            else -> 0
        }
        require(result == 1) { "cannot parse signature (size = ${input.size}, format = $sigFormat sig = ${Hex.encode(input)}" }
        return sig
    }

    private fun MemScope.allocPublicKey(pubkey: ByteArray): secp256k1_pubkey {
        val natPub = toNat(pubkey)
        val pub = alloc<secp256k1_pubkey>()
        secp256k1_ec_pubkey_parse(ctx, pub.ptr, natPub, pubkey.size.convert()).requireSuccess()
        return pub
    }

    private fun MemScope.serializePubkey(pubkey: secp256k1_pubkey, len: Int): ByteArray {
        val serialized = allocArray<UByteVar>(len)
        val outputLen = alloc<size_tVar>()
        outputLen.value = len.convert()
        secp256k1_ec_pubkey_serialize(ctx, serialized, outputLen.ptr, pubkey.ptr, (if (len == 33) SECP256K1_EC_COMPRESSED else SECP256K1_EC_UNCOMPRESSED).convert()).requireSuccess()
        return serialized.readBytes(outputLen.value.convert())
    }

    private fun DeferScope.toNat(bytes: ByteArray): CPointer<UByteVar>  {
        val ubytes = bytes.asUByteArray()
        val pinned = ubytes.pin()
        this.defer { pinned.unpin() }
        return pinned.addressOf(0)
    }

    public actual fun verify(data: ByteArray, signature: ByteArray, pub: ByteArray): Boolean {
        require(data.size == 32)
        require(pub.size == 33 || pub.size == 65)
        memScoped {
            val pubkey = allocPublicKey(pub)
            val natData = toNat(data)
            val parsedSig = allocSignature(signature)
            return secp256k1_ecdsa_verify(ctx, parsedSig.ptr, natData, pubkey.ptr) == 1
        }
    }

    public actual fun sign(data: ByteArray, sec: ByteArray): ByteArray {
        require(sec.size == 32)
        require(data.size == 32)
        memScoped {
            val natSec = toNat(sec)
            val natData = toNat(data)
            val natSig = alloc<secp256k1_ecdsa_signature>()
            val result = secp256k1_ecdsa_sign(ctx, natSig.ptr, natData, natSec, null, null)
            if (result == 0) return ByteArray(0)
            val natOutput = allocArray<UByteVar>(72)
            val outputLen = alloc<size_tVar>()
            outputLen.value = 72.convert()
            secp256k1_ecdsa_signature_serialize_der(ctx, natOutput, outputLen.ptr, natSig.ptr).requireSuccess()
            return natOutput.readBytes(outputLen.value.toInt())
        }
    }

    public actual fun signCompact(data: ByteArray, sec: ByteArray): ByteArray {
        require(data.size == 32)
        require(sec.size <= 32)
        memScoped {
            val natSec = toNat(sec)
            val natData = toNat(data)
            val natSig = alloc<secp256k1_ecdsa_signature>()
            secp256k1_ecdsa_sign(ctx, natSig.ptr, natData, natSec, null, null).requireSuccess()
            val natCompact = allocArray<UByteVar>(64)
            secp256k1_ecdsa_signature_serialize_compact(ctx, natCompact, natSig.ptr).requireSuccess()
            return natCompact.readBytes(64)
        }
    }

    public actual fun secKeyVerify(seckey: ByteArray): Boolean {
        require(seckey.size == 32)
        memScoped {
            val natSec = toNat(seckey)
            return secp256k1_ec_seckey_verify(ctx, natSec) == 1
        }
    }

    public actual fun computePubkey(seckey: ByteArray): ByteArray {
        require(seckey.size == 32)
        memScoped {
            val natSec = toNat(seckey)
            val pubkey = alloc<secp256k1_pubkey>()
            val result = secp256k1_ec_pubkey_create(ctx, pubkey.ptr, natSec)
            if (result == 0) return ByteArray(0)
            return serializePubkey(pubkey, 65)
        }
    }

    public actual fun parsePubkey(pubkey: ByteArray): ByteArray {
        require(pubkey.size == 33 || pubkey.size == 65)
        memScoped {
            val nPubkey = allocPublicKey(pubkey)
            return serializePubkey(nPubkey, 65)
        }
    }

    public actual fun cleanup() {
        secp256k1_context_destroy(ctx)
    }

    public actual fun privKeyNegate(privkey: ByteArray): ByteArray {
        require(privkey.size == 32)
        memScoped {
            val negated = privkey.copyOf()
            val negPriv = toNat(negated)
            secp256k1_ec_privkey_negate(ctx, negPriv).requireSuccess()
            return negated
        }
    }

    public actual fun privKeyTweakMul(privkey: ByteArray, tweak: ByteArray): ByteArray {
        require(privkey.size == 32)
        memScoped {
            val multiplied = privkey.copyOf()
            val natMul = toNat(multiplied)
            val natTweak = toNat(tweak)
            secp256k1_ec_privkey_tweak_mul(ctx, natMul, natTweak).requireSuccess()
            return multiplied
        }
    }

    public actual fun privKeyTweakAdd(privkey: ByteArray, tweak: ByteArray): ByteArray {
        require(privkey.size == 32)
        memScoped {
            val added = privkey.copyOf()
            val natAdd = toNat(added)
            val natTweak = toNat(tweak)
            secp256k1_ec_privkey_tweak_add(ctx, natAdd, natTweak).requireSuccess()
            return added
        }
    }

    public actual fun pubKeyNegate(pubkey: ByteArray): ByteArray {
        require(pubkey.size == 33 || pubkey.size == 65)
        memScoped {
            val nPubkey = allocPublicKey(pubkey)
            secp256k1_ec_pubkey_negate(ctx, nPubkey.ptr).requireSuccess()
            return serializePubkey(nPubkey, pubkey.size)
        }
    }

    public actual fun pubKeyTweakAdd(pubkey: ByteArray, tweak: ByteArray): ByteArray {
        require(pubkey.size == 33 || pubkey.size == 65)
        memScoped {
            val nPubkey = allocPublicKey(pubkey)
            val nTweak = toNat(tweak)
            secp256k1_ec_pubkey_tweak_add(ctx, nPubkey.ptr, nTweak).requireSuccess()
            return serializePubkey(nPubkey, 65)
        }
    }

    public actual fun pubKeyTweakMul(pubkey: ByteArray, tweak: ByteArray): ByteArray {
        require(pubkey.size == 33 || pubkey.size == 65)
        memScoped {
            val nPubkey = allocPublicKey(pubkey)
            val nTweak = toNat(tweak)
            secp256k1_ec_pubkey_tweak_mul(ctx, nPubkey.ptr, nTweak).requireSuccess()
            return serializePubkey(nPubkey, 65)
        }
    }

    public actual fun pubKeyAdd(pubkey1: ByteArray, pubkey2: ByteArray): ByteArray {
        require(pubkey1.size == 33 || pubkey2.size == 65)
        memScoped {
            val nPubkey1 = allocPublicKey(pubkey1)
            val nPubkey2 = allocPublicKey(pubkey2)
            val combined = nativeHeap.alloc<secp256k1_pubkey>()
            secp256k1_ec_pubkey_combine(ctx, combined.ptr, cValuesOf(nPubkey1.ptr, nPubkey2.ptr), 2.convert()).requireSuccess()
            return serializePubkey(combined, 65)
        }
    }

    public actual fun createECDHSecret(seckey: ByteArray, pubkey: ByteArray): ByteArray {
        require(seckey.size == 32)
        require(pubkey.size == 33 || pubkey.size == 65)
        memScoped {
            val nPubkey = allocPublicKey(pubkey)
            val nSeckey = toNat(seckey)
            val output = allocArray<UByteVar>(32)
            secp256k1_ecdh(ctx, output, nPubkey.ptr, nSeckey, null, null).requireSuccess()
            return output.readBytes(32)
        }
    }

    public actual fun ecdsaRecover(sig: ByteArray, message: ByteArray, recid: Int): ByteArray {
        require(sig.size == 64)
        require(message.size == 32)
        memScoped {
            val nSig = toNat(sig)
            val rSig = nativeHeap.alloc<secp256k1_ecdsa_recoverable_signature>()
            secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, rSig.ptr, nSig, recid).requireSuccess()
            val nMessage = toNat(message)
            val pubkey = nativeHeap.alloc<secp256k1_pubkey>()
            secp256k1_ecdsa_recover(ctx, pubkey.ptr, rSig.ptr, nMessage).requireSuccess()
            return serializePubkey(pubkey, 65)
        }
    }

    public actual fun randomize(seed: ByteArray): Boolean {
        require(seed.size == 32)
        memScoped {
            val nSeed = toNat(seed)
            return secp256k1_context_randomize(ctx, nSeed) == 1
        }
    }
}
