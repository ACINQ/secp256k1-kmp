package fr.acinq.secp256k1;

public class Secp256k1CFunctions {
    /**
     * All flags' lower 8 bits indicate what they're for. Do not use directly.
     */
    public static int SECP256K1_FLAGS_TYPE_MASK = ((1 << 8) - 1);
    public static final int SECP256K1_FLAGS_TYPE_CONTEXT = (1 << 0);
    public static final int SECP256K1_FLAGS_TYPE_COMPRESSION = (1 << 1);

    /**
     * The higher bits contain the actual data. Do not use directly.
     */
    public static final int SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = (1 << 8);
    public static final int SECP256K1_FLAGS_BIT_CONTEXT_SIGN = (1 << 9);
    public static final int SECP256K1_FLAGS_BIT_COMPRESSION = (1 << 8);

    /**
     * Flags to pass to secp256k1_context_create, secp256k1_context_preallocated_size, and
     * secp256k1_context_preallocated_create.
     */
    public static final int SECP256K1_CONTEXT_VERIFY = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY);
    public static final int SECP256K1_CONTEXT_SIGN = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN);
    public static final int SECP256K1_CONTEXT_NONE = (SECP256K1_FLAGS_TYPE_CONTEXT);

    /**
     * Flag to pass to secp256k1_ec_pubkey_serialize.
     */
    public static final int SECP256K1_EC_COMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION);
    public static final int SECP256K1_EC_UNCOMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION);

    /**
     * A musig2 public nonce is simply two elliptic curve points.
     */
    public static final int SECP256K1_MUSIG_PUBLIC_NONCE_SIZE = 66;

    /**
     * A musig2 private nonce is basically two scalars, but should be treated as an opaque blob.
     */
    public static final int SECP256K1_MUSIG_SECRET_NONCE_SIZE = 132;

    /**
     * When aggregating public keys, we cache information in an opaque blob (must not be interpreted).
     */
    public static final int SECP256K1_MUSIG_KEYAGG_CACHE_SIZE = 197;

    /**
     * When creating partial signatures and aggregating them, session data is kept in an opaque blob (must not be interpreted).
     */
    public static final int SECP256K1_MUSIG_SESSION_SIZE = 133;

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

    public static native byte[] secp256k1_ec_pubkey_combine(long ctx, byte[][] pubkeys);

    public static native byte[] secp256k1_ecdh(long ctx, byte[] seckey, byte[] pubkey);

    public static native byte[] secp256k1_ecdsa_recover(long ctx, byte[] sig, byte[] msg32, int recid);

    public static native byte[] secp256k1_compact_to_der(long ctx, byte[] sig);

    public static native byte[] secp256k1_schnorrsig_sign(long ctx, byte[] msg, byte[] seckey, byte[] aux_rand32);

    public static native int secp256k1_schnorrsig_verify(long ctx, byte[] sig, byte[] msg, byte[] pubkey);

    public static native byte[] secp256k1_musig_nonce_gen(long ctx, byte[] session_rand32, byte[] seckey, byte[] pubkey, byte[] msg32, byte[] keyagg_cache, byte[] extra_input32);

    public static native byte[] secp256k1_musig_nonce_gen_counter(long ctx, long nonrepeating_cnt, byte[] seckey, byte[] pubkey, byte[] msg32, byte[] keyagg_cache, byte[] extra_input32);

    public static native byte[] secp256k1_musig_nonce_agg(long ctx, byte[][] nonces);

    public static native byte[] secp256k1_musig_pubkey_agg(long ctx, byte[][] pubkeys, byte[] keyagg_cache);

    public static native byte[] secp256k1_musig_pubkey_ec_tweak_add(long ctx, byte[] keyagg_cache, byte[] tweak32);

    public static native byte[] secp256k1_musig_pubkey_xonly_tweak_add(long ctx, byte[] keyagg_cache, byte[] tweak32);

    public static native byte[] secp256k1_musig_nonce_process(long ctx, byte[] aggnonce, byte[] msg32, byte[] keyagg_cache);

    public static native byte[] secp256k1_musig_partial_sign(long ctx, byte[] secnonce, byte[] privkey, byte[] keyagg_cache, byte[] session);

    public static native int secp256k1_musig_partial_sig_verify(long ctx, byte[] psig, byte[] pubnonce, byte[] pubkey, byte[] keyagg_cache, byte[] session);

    public static native byte[] secp256k1_musig_partial_sig_agg(long ctx, byte[] session, byte[][] psigs);
}
