package org.bitcoin;

import java.nio.ByteBuffer;

public class Secp256k1CFunctions {
    static native long secp256k1_init_context();
    static native int secp256k1_context_randomize(ByteBuffer byteBuff, long context);
    static native byte[][] secp256k1_privkey_negate(ByteBuffer byteBuff, long context);
    static native byte[][] secp256k1_privkey_tweak_add(ByteBuffer byteBuff, long context);
    static native byte[][] secp256k1_privkey_tweak_mul(ByteBuffer byteBuff, long context);
    static native byte[][] secp256k1_pubkey_negate(ByteBuffer byteBuff, long context, int pubLen);
    static native byte[][] secp256k1_pubkey_tweak_add(ByteBuffer byteBuff, long context, int pubLen);
    static native byte[][] secp256k1_pubkey_tweak_mul(ByteBuffer byteBuff, long context, int pubLen);
    static native void secp256k1_destroy_context(long context);
    static native int secp256k1_ecdsa_verify(ByteBuffer byteBuff, long context, int sigLen, int pubLen);
    static native byte[][] secp256k1_ecdsa_sign(ByteBuffer byteBuff, boolean compact, long context);
    static native byte[][] secp256k1_ecdsa_normalize(ByteBuffer byteBuff, int sigLen, boolean compact, long context);
    static native int secp256k1_ec_seckey_verify(ByteBuffer byteBuff, long context);
    static native byte[][] secp256k1_ec_pubkey_create(ByteBuffer byteBuff, boolean compressed, long context);
    static native byte[][] secp256k1_ec_pubkey_parse(ByteBuffer byteBuff, long context, int inputLen, boolean compressed);
    static native byte[][] secp256k1_ec_pubkey_add(ByteBuffer byteBuff, long context, int lent1, int len2);
    static native byte[][] secp256k1_ecdh(ByteBuffer byteBuff, long context, int inputLen);
    static native byte[][] secp256k1_ecdsa_recover(ByteBuffer byteBuff, long context, int recid, boolean compressed);
}
