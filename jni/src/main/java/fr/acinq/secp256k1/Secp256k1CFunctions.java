package fr.acinq.secp256k1;

public class Secp256k1CFunctions {
    /**
     * All flags' lower 8 bits indicate what they're for. Do not use directly.
     */
    public static int SECP256K1_FLAGS_TYPE_MASK = ((1 << 8) - 1);
    public static int SECP256K1_FLAGS_TYPE_CONTEXT = (1 << 0);
    public static int SECP256K1_FLAGS_TYPE_COMPRESSION = (1 << 1);

    /**
     * The higher bits contain the actual data. Do not use directly.
     */
    public static int SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = (1 << 8);
    public static int SECP256K1_FLAGS_BIT_CONTEXT_SIGN = (1 << 9);
    public static int SECP256K1_FLAGS_BIT_COMPRESSION = (1 << 8);

    /**
     * Flags to pass to secp256k1_context_create, secp256k1_context_preallocated_size, and
     * secp256k1_context_preallocated_create.
     */
    public static int SECP256K1_CONTEXT_VERIFY = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY);
    public static int SECP256K1_CONTEXT_SIGN = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN);
    public static int SECP256K1_CONTEXT_NONE = (SECP256K1_FLAGS_TYPE_CONTEXT);

    /**
     * Flag to pass to secp256k1_ec_pubkey_serialize.
     */
    public static int SECP256K1_EC_COMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION);
    public static int SECP256K1_EC_UNCOMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION);

    public static native long secp256k1_context_create(int flags);

    public static native void secp256k1_context_destroy(long ctx);

    public static native int secp256k1_ec_seckey_verify(long ctx, byte[] seckey);
    
    public static native byte[] secp256k1_ec_pubkey_parse(long ctx, byte[] pubkey);

    public static native byte[] secp256k1_ec_pubkey_create(long ctx, byte[] seckey);

    public static native byte[] secp256k1_ecdsa_sign(long ctx, byte[] msg, byte[] seckey);

    public static native int secp256k1_ecdsa_verify(long ctx, byte[] sig, byte[] msg, byte[] pubkey);

    public static native int secp256k1_ecdsa_signature_normalize(long ctx, byte[] sigin, byte[] sigout);

    public static native byte[] secp256k1_ec_privkey_negate(long ctx, byte[] privkey);

    public static native byte[] secp256k1_ec_pubkey_negate(long ctx, byte[] pubkey);

    public static native byte[] secp256k1_ec_privkey_tweak_add(long ctx, byte[] seckey, byte[] tweak);

    public static native byte[] secp256k1_ec_pubkey_tweak_add(long ctx, byte[] pubkey, byte[] tweak);

    public static native byte[] secp256k1_ec_privkey_tweak_mul(long ctx, byte[] seckey, byte[] tweak);

    public static native byte[] secp256k1_ec_pubkey_tweak_mul(long ctx, byte[] pubkey, byte[] tweak);

    public static native byte[] secp256k1_ec_pubkey_add(long ctx, byte[] pubkey1, byte[] pubkey2);

    public static native byte[] secp256k1_ec_pubkey_combine(long ctx, byte[][] pubkeys);

    public static native byte[] secp256k1_ecdh(long ctx, byte[] seckey, byte[] pubkey);

    public static native byte[] secp256k1_ecdsa_recover(long ctx, byte[] sig, byte[] msg32, int recid);
}
