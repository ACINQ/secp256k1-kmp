#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
#define SECP256K1_STATIC // needed on windows when linking to a static version of secp256k1
#endif
#include "fr_acinq_secp256k1_Secp256k1CFunctions.h"
#include "include/secp256k1.h"
#include "include/secp256k1_ecdh.h"
#include "include/secp256k1_musig.h"
#include "include/secp256k1_recovery.h"
#include "include/secp256k1_schnorrsig.h"

/*
 * libsecp256k1 tags each of its opaque musig2 objects with a 4-byte magic prefix and validates it
 * internally with ARG_CHECK, which invokes the context's illegal-argument callback. The default
 * callback aborts the process, so a blob that has the right size but does not actually hold a
 * musig2 object would kill the JVM instead of raising an exception. We check the prefix before
 * handing the blob to libsecp256k1 so that these cases throw Secp256k1Exception.
 *
 * Keep in sync with native/secp256k1/src/modules/musig/{keyagg,session}_impl.h.
 */
static const unsigned char MUSIG_KEYAGG_CACHE_MAGIC[4] = { 0xf4, 0xad, 0xbb, 0xdf };
static const unsigned char MUSIG_SECNONCE_MAGIC[4] = { 0x22, 0x0e, 0xdc, 0xf1 };
static const unsigned char MUSIG_SESSION_MAGIC[4] = { 0x9d, 0xed, 0xe9, 0x17 };

#define CHECKMAGIC(data, magic, message) CHECKRESULT(memcmp((data), (magic), 4) != 0, message)

/*
 * Installed on every context we create, replacing the default callback that aborts the process.
 * Returning from here makes the libsecp256k1 return undefined values, but in practice calls fail with 0,
 * which the bindings below already turn into a Secp256k1Exception. 
 * The CHECKMAGIC checks above are the primary defence; this is the backstop for anything missed.
 */
static void JNI_IllegalArgumentCallback(const char* message, void* data)
{
    (void)message;
    (void)data;
}

static void JNI_ThrowByName(JNIEnv* penv, const char* name, const char* msg)
{
    jclass cls = (*penv)->FindClass(penv, name);
    if (cls != NULL) {
        (*penv)->ThrowNew(penv, cls, msg);
        (*penv)->DeleteLocalRef(penv, cls);
    }
}

static void JNI_ThrowSecp256k1(JNIEnv* penv, const char* msg)
{
    JNI_ThrowByName(penv, "fr/acinq/secp256k1/Secp256k1Exception", msg);
}

static void JNI_ThrowNull(JNIEnv* penv, const char* name)
{
    char msg[128];
    snprintf(msg, sizeof(msg), "%s cannot be null", name);
    JNI_ThrowSecp256k1(penv, msg);
}

static void JNI_ThrowSize(JNIEnv* penv, const char* name, int size)
{
    char msg[128];
    snprintf(msg, sizeof(msg), "%s must be %d bytes", name, size);
    JNI_ThrowSecp256k1(penv, msg);
}

#define CHECKRESULT(errorcheck, message)                                             \
    {                                                                                \
        if (errorcheck) {                                                            \
            JNI_ThrowByName(penv, "fr/acinq/secp256k1/Secp256k1Exception", message); \
            return 0;                                                                \
        }                                                                            \
    }

#define CHECKRESULT1(errorcheck, message, dosomething)                               \
    {                                                                                \
        if (errorcheck) {                                                            \
            dosomething;                                                             \
            JNI_ThrowByName(penv, "fr/acinq/secp256k1/Secp256k1Exception", message); \
            return 0;                                                                \
        }                                                                            \
    }

/* Buffers are `unsigned char` everywhere below: the jbyte <-> unsigned char conversion
 * is confined to get_bytes() and copy_bytes_to_java(), the two JNI boundary helpers. */
static inline jbyteArray copy_bytes_to_java(JNIEnv* penv, const unsigned char* from, size_t size)
{
    jbyteArray dest = (*penv)->NewByteArray(penv, (jsize)size);
    CHECKRESULT(dest == NULL, "memory allocation failed");
    (*penv)->SetByteArrayRegion(penv, dest, 0, (jsize)size, (const jbyte*)from);
    return dest;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_context_create
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1context_1create(JNIEnv* penv, jclass clazz, jint flags)
{
    secp256k1_context* ctx = secp256k1_context_create(flags);
    if (ctx != NULL) {
        /* secp256k1_context_set_illegal_callback needs exclusive access to the context, so it must
           be done here, before the context is returned and can be shared between threads. */
        secp256k1_context_set_illegal_callback(ctx, JNI_IllegalArgumentCallback, NULL);
    }
    return (jlong)ctx;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_context_destroy
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1context_1destroy(JNIEnv* penv, jclass clazz, jlong ctx)
{
    if (ctx != 0) {
        secp256k1_context_destroy((secp256k1_context*)ctx);
    }
}

/* The get_xxx() helpers below all return 1 on success, and on failure throw a
 * Secp256k1Exception describing what was wrong with the argument and return 0.
 * They must not be called when an exception is already pending: callers are
 * expected to return as soon as one of them fails. */
static inline int get_bytes(JNIEnv* penv, jbyteArray jbytes, size_t size, unsigned char* bytes, const char* name)
{
    if (jbytes == NULL) {
        JNI_ThrowNull(penv, name);
        return 0;
    }
    if ((*penv)->GetArrayLength(penv, jbytes) != (jsize)size) {
        JNI_ThrowSize(penv, name, (int)size);
        return 0;
    }
    (*penv)->GetByteArrayRegion(penv, jbytes, 0, (jsize)size, (jbyte*)bytes);
    return 1;
}

static inline int get_bytes32(JNIEnv* penv, jbyteArray jbytes, unsigned char* bytes, const char* name)
{
    return get_bytes(penv, jbytes, 32, bytes, name);
}

static inline int get_pubkey(JNIEnv* penv, const secp256k1_context* ctx, jbyteArray jpubkey, secp256k1_pubkey* pubkey)
{
    jsize size;
    unsigned char pubkeyBytes[65];

    if (jpubkey == NULL) {
        JNI_ThrowNull(penv, "public key");
        return 0;
    }
    size = (*penv)->GetArrayLength(penv, jpubkey);
    if ((size != 33) && (size != 65)) {
        JNI_ThrowSecp256k1(penv, "public key must be 33 or 65 bytes");
        return 0;
    }
    (*penv)->GetByteArrayRegion(penv, jpubkey, 0, size, (jbyte*)pubkeyBytes);
    if (!secp256k1_ec_pubkey_parse(ctx, pubkey, pubkeyBytes, (size_t)size)) {
        JNI_ThrowSecp256k1(penv, "secp256k1_ec_pubkey_parse failed");
        return 0;
    }
    return 1;
}

static inline int get_signature(JNIEnv* penv, const secp256k1_context* ctx, jbyteArray jsig, secp256k1_ecdsa_signature* sig, const char* name)
{
    unsigned char buffer[64];

    if (!get_bytes(penv, jsig, 64, buffer, name)) return 0;
    if (!secp256k1_ecdsa_signature_parse_compact(ctx, sig, buffer)) {
        JNI_ThrowSecp256k1(penv, "secp256k1_ecdsa_signature_parse_compact failed");
        return 0;
    }
    return 1;
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_ec_seckey_verify
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1seckey_1verify(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jseckey)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char seckey[32];

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jseckey, seckey, "secret key")) return 0;
    return secp256k1_ec_seckey_verify(ctx, seckey);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_pubkey_parse
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1pubkey_1parse(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jpubkey)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    secp256k1_pubkey pubkey;
    unsigned char pubkeyBytes[65];
    size_t size;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_pubkey(penv, ctx, jpubkey, &pubkey)) return NULL;
    size = 65;
    result = secp256k1_ec_pubkey_serialize(ctx, pubkeyBytes, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

    return copy_bytes_to_java(penv, pubkeyBytes, 65);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_pubkey_create
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1pubkey_1create(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jseckey)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char seckey[32], pubkey[65];
    secp256k1_pubkey pub;
    int result = 0;
    size_t len;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jseckey, seckey, "secret key")) return NULL;
    result = secp256k1_ec_pubkey_create(ctx, &pub, seckey);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_create failed");

    len = 65;
    result = secp256k1_ec_pubkey_serialize(ctx, pubkey, &len, &pub, SECP256K1_EC_UNCOMPRESSED);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

    return copy_bytes_to_java(penv, pubkey, 65);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ecdsa_sign
 * Signature: (J[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ecdsa_1sign(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jmsg, jbyteArray jseckey, jbyteArray jndata)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char seckey[32], msg[32], ndata[32], sig[64];
    secp256k1_ecdsa_signature signature;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jseckey, seckey, "secret key")) return NULL;
    if (!get_bytes32(penv, jmsg, msg, "message")) return NULL;
    if (jndata != NULL) {
        if (!get_bytes32(penv, jndata, ndata, "auxiliary data")) return NULL;
    }

    result = secp256k1_ecdsa_sign(ctx, &signature, msg, seckey, NULL, jndata != NULL ? ndata : NULL);
    CHECKRESULT(!result, "secp256k1_ecdsa_sign failed");

    result = secp256k1_ecdsa_signature_serialize_compact(ctx, sig, &signature);
    CHECKRESULT(!result, "secp256k1_ecdsa_signature_serialize_compact failed");

    return copy_bytes_to_java(penv, sig, 64);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ecdsa_verify
 * Signature: (J[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ecdsa_1verify(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jsig, jbyteArray jmsg, jbyteArray jpubkey)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char msg[32];
    secp256k1_ecdsa_signature signature;
    secp256k1_pubkey pubkey;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_signature(penv, ctx, jsig, &signature, "signature")) return 0;
    if (!get_pubkey(penv, ctx, jpubkey, &pubkey)) return 0;
    if (!get_bytes32(penv, jmsg, msg, "message")) return 0;

    result = secp256k1_ecdsa_verify(ctx, &signature, msg, &pubkey);
    return result;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ecdsa_signature_normalize
 * Signature: (J[B[B)I
 */
JNIEXPORT jint JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ecdsa_1signature_1normalize(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jsigin, jbyteArray jsigout)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char sig[64];
    secp256k1_ecdsa_signature signature_in, signature_out;
    int result = 0;
    int return_value = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (jsigout == NULL) {
        JNI_ThrowNull(penv, "output signature");
        return 0;
    }
    if ((*penv)->GetArrayLength(penv, jsigout) != 64) {
        JNI_ThrowSize(penv, "output signature", 64);
        return 0;
    }
    if (!get_signature(penv, ctx, jsigin, &signature_in, "input signature")) return 0;

    return_value = secp256k1_ecdsa_signature_normalize(ctx, &signature_out, &signature_in);
    result = secp256k1_ecdsa_signature_serialize_compact(ctx, sig, &signature_out);
    CHECKRESULT(!result, "secp256k1_ecdsa_signature_serialize_compact failed");

    (*penv)->SetByteArrayRegion(penv, jsigout, 0, 64, (const jbyte*)sig);

    return return_value;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_seckey_negate
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1seckey_1negate(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jseckey)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char seckey[32];
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jseckey, seckey, "secret key")) return NULL;
    result = secp256k1_ec_seckey_negate(ctx, seckey);
    CHECKRESULT(!result, "secp256k1_ec_seckey_negate failed");

    return copy_bytes_to_java(penv, seckey, 32);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_pubkey_negate
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1pubkey_1negate(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jpubkey)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char pub[65];
    secp256k1_pubkey pubkey;
    size_t size;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_pubkey(penv, ctx, jpubkey, &pubkey)) return NULL;

    result = secp256k1_ec_pubkey_negate(ctx, &pubkey);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_negate failed");

    size = 65;
    result = secp256k1_ec_pubkey_serialize(ctx, pub, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

    return copy_bytes_to_java(penv, pub, 65);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_seckey_tweak_add
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1seckey_1tweak_1add(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jseckey, jbyteArray jtweak)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char seckey[32], tweak[32];
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jseckey, seckey, "secret key")) return NULL;
    if (!get_bytes32(penv, jtweak, tweak, "tweak")) return NULL;

    result = secp256k1_ec_seckey_tweak_add(ctx, seckey, tweak);
    CHECKRESULT(!result, "secp256k1_ec_seckey_tweak_add failed");

    return copy_bytes_to_java(penv, seckey, 32);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_pubkey_tweak_add
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1pubkey_1tweak_1add(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jpubkey, jbyteArray jtweak)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char pub[65], tweak[32];
    secp256k1_pubkey pubkey;
    size_t size;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_pubkey(penv, ctx, jpubkey, &pubkey)) return NULL;
    if (!get_bytes32(penv, jtweak, tweak, "tweak")) return NULL;

    result = secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, tweak);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_tweak_add failed");

    size = 65;
    result = secp256k1_ec_pubkey_serialize(ctx, pub, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

    return copy_bytes_to_java(penv, pub, 65);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_seckey_tweak_mul
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1seckey_1tweak_1mul(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jseckey, jbyteArray jtweak)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char seckey[32], tweak[32];
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jseckey, seckey, "secret key")) return NULL;
    if (!get_bytes32(penv, jtweak, tweak, "tweak")) return NULL;

    result = secp256k1_ec_seckey_tweak_mul(ctx, seckey, tweak);
    CHECKRESULT(!result, "secp256k1_ec_seckey_tweak_mul failed");

    return copy_bytes_to_java(penv, seckey, 32);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_pubkey_tweak_mul
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1pubkey_1tweak_1mul(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jpubkey, jbyteArray jtweak)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char pub[65], tweak[32];
    secp256k1_pubkey pubkey;
    size_t size;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_pubkey(penv, ctx, jpubkey, &pubkey)) return NULL;
    if (!get_bytes32(penv, jtweak, tweak, "tweak")) return NULL;

    result = secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, tweak);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_tweak_mul failed");

    size = 65;
    result = secp256k1_ec_pubkey_serialize(ctx, pub, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

    return copy_bytes_to_java(penv, pub, 65);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_pubkey_combine
 * Signature: (J[[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1pubkey_1combine(JNIEnv* penv, jclass clazz, jlong jctx, jobjectArray jpubkeys)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char pub[65];
    secp256k1_pubkey* pubkeys;
    secp256k1_pubkey** pubkey_ptrs;
    secp256k1_pubkey combined;
    jbyteArray jpubkey;
    size_t size, count;
    size_t i;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    CHECKRESULT(jpubkeys == NULL, "public keys cannot be null");

    count = (*penv)->GetArrayLength(penv, jpubkeys);
    CHECKRESULT(count < 1, "pubkey array cannot be empty")
    pubkeys = calloc(count, sizeof(secp256k1_pubkey));
    CHECKRESULT(pubkeys == NULL, "memory allocation failed");
    pubkey_ptrs = calloc(count, sizeof(secp256k1_pubkey*));
    CHECKRESULT1(pubkey_ptrs == NULL, "memory allocation failed", free(pubkeys));

    for (i = 0; i < count; i++) {
        pubkey_ptrs[i] = &(pubkeys[i]);
        jpubkey = (jbyteArray)(*penv)->GetObjectArrayElement(penv, jpubkeys, i);
        if (!get_pubkey(penv, ctx, jpubkey, pubkey_ptrs[i])) {
            free(pubkey_ptrs);
            free(pubkeys);
            return NULL;
        }
        (*penv)->DeleteLocalRef(penv, jpubkey);
    }
    result = secp256k1_ec_pubkey_combine(ctx, &combined, (const secp256k1_pubkey* const*)pubkey_ptrs, count);
    free(pubkey_ptrs);
    free(pubkeys);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_combine failed");

    size = 65;
    result = secp256k1_ec_pubkey_serialize(ctx, pub, &size, &combined, SECP256K1_EC_UNCOMPRESSED);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

    return copy_bytes_to_java(penv, pub, 65);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ecdh
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ecdh(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jseckey, jbyteArray jpubkey)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char seckeyBytes[32], output[32];
    secp256k1_pubkey pubkey;
    int result;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jseckey, seckeyBytes, "secret key")) return NULL;
    if (!get_pubkey(penv, ctx, jpubkey, &pubkey)) return NULL;

    result = secp256k1_ecdh(ctx, output, &pubkey, seckeyBytes, NULL, NULL);
    CHECKRESULT(!result, "secp256k1_ecdh failed");

    return copy_bytes_to_java(penv, output, 32);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ecdsa_recover
 * Signature: (J[B[BI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ecdsa_1recover(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jsig, jbyteArray jmsg, jint recid)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char sig[64], msg[32], pub[65];
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_recoverable_signature signature;
    size_t size;
    int result;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    CHECKRESULT(recid < 0 || recid > 3, "invalid recovery id");
    if (!get_bytes(penv, jsig, 64, sig, "signature")) return NULL;
    if (!get_bytes32(penv, jmsg, msg, "message")) return NULL;

    result = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &signature, sig, recid);
    CHECKRESULT(!result, "secp256k1_ecdsa_recoverable_signature_parse_compact failed");

    result = secp256k1_ecdsa_recover(ctx, &pubkey, &signature, msg);
    CHECKRESULT(!result, "secp256k1_ecdsa_recover failed");

    size = 65;
    result = secp256k1_ec_pubkey_serialize(ctx, pub, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

    return copy_bytes_to_java(penv, pub, 65);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_compact_to_der
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1compact_1to_1der(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jsig)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    secp256k1_ecdsa_signature signature;
    unsigned char der[73];
    size_t size;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_signature(penv, ctx, jsig, &signature, "signature")) return NULL;

    size = 73;
    result = secp256k1_ecdsa_signature_serialize_der(ctx, der, &size, &signature);
    CHECKRESULT(!result, "secp256k1_ecdsa_signature_serialize_der failed");
    return copy_bytes_to_java(penv, der, size);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_der_to_compact
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1der_1to_1compact(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jsig)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char sig[73];
    secp256k1_ecdsa_signature signature;
    unsigned char compact[64];
    jsize size;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (jsig == NULL) {
        JNI_ThrowNull(penv, "signature");
        return NULL;
    }
    size = (*penv)->GetArrayLength(penv, jsig);
    CHECKRESULT(size < 8 || size > 73, "DER signature must be between 8 and 73 bytes");

    (*penv)->GetByteArrayRegion(penv, jsig, 0, size, (jbyte*)sig);
    result = secp256k1_ecdsa_signature_parse_der(ctx, &signature, sig, (size_t)size);
    CHECKRESULT(!result, "secp256k1_ecdsa_signature_parse_der failed");

    result = secp256k1_ecdsa_signature_serialize_compact(ctx, compact, &signature);
    CHECKRESULT(!result, "secp256k1_ecdsa_signature_serialize_der failed");

    return copy_bytes_to_java(penv, compact, 64);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_schnorrsig_sign
 * Signature: (J[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1schnorrsig_1sign(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jmsg, jbyteArray jseckey, jbyteArray jauxrand32)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char seckey[32], msg[32], auxrand32[32];
    secp256k1_keypair keypair;
    unsigned char signature[64];
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jmsg, msg, "message")) return NULL;
    if (!get_bytes32(penv, jseckey, seckey, "secret key")) return NULL;
    if (jauxrand32 != NULL) {
        if (!get_bytes32(penv, jauxrand32, auxrand32, "auxiliary random data")) return NULL;
    }
    result = secp256k1_keypair_create(ctx, &keypair, seckey);
    CHECKRESULT(!result, "secp256k1_keypair_create failed");

    result = secp256k1_schnorrsig_sign32(ctx, signature, msg, &keypair, jauxrand32 != NULL ? auxrand32 : NULL);
    CHECKRESULT(!result, "secp256k1_schnorrsig_sign failed");

    return copy_bytes_to_java(penv, signature, 64);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_schnorrsig_verify
 * Signature: (J[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1schnorrsig_1verify(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jsig, jbyteArray jmsg, jbyteArray jpubkey)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char pub[32], msg[32], sig[64];
    secp256k1_xonly_pubkey pubkey;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes(penv, jsig, 64, sig, "signature")) return 0;
    if (!get_bytes32(penv, jmsg, msg, "message")) return 0;
    if (!get_bytes32(penv, jpubkey, pub, "x-only public key")) return 0;

    result = secp256k1_xonly_pubkey_parse(ctx, &pubkey, pub);
    CHECKRESULT(!result, "secp256k1_xonly_pubkey_parse failed");

    result = secp256k1_schnorrsig_verify(ctx, sig, msg, 32, &pubkey);
    return result;
}

// session_id32: ByteArray, seckey: ByteArray?, pubkey: ByteArray, msg32: ByteArray?, keyagg_cache: ByteArray?, extra_input32: ByteArray?
/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_nonce_gen
 * Signature: (J[B[B[B[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1nonce_1gen(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jsession_id32, jbyteArray jseckey, jbyteArray jpubkey, jbyteArray jmsg32, jbyteArray jkeyaggcache, jbyteArray jextra_input32)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    int result = 0;
    secp256k1_musig_pubnonce pubnonce;
    secp256k1_musig_secnonce secnonce;
    unsigned char session_id32[32];
    secp256k1_pubkey pubkey;
    unsigned char seckey[32];
    unsigned char msg32[32];
    secp256k1_musig_keyagg_cache keyaggcache;
    unsigned char extra_input32[32];
    unsigned char nonce[fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SECRET_NONCE_SIZE + fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE];

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jsession_id32, session_id32, "session id")) return NULL;

    if (jseckey != NULL) {
        if (!get_bytes32(penv, jseckey, seckey, "secret key")) return NULL;
    }

    if (!get_pubkey(penv, ctx, jpubkey, &pubkey)) return NULL;

    if (jmsg32 != NULL) {
        if (!get_bytes32(penv, jmsg32, msg32, "message")) return NULL;
    }

    if (jkeyaggcache != NULL) {
        if (!get_bytes(penv, jkeyaggcache, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, keyaggcache.data, "keyagg cache")) return NULL;
        CHECKMAGIC(keyaggcache.data, MUSIG_KEYAGG_CACHE_MAGIC, "invalid keyagg cache");
    }

    if (jextra_input32 != NULL) {
        if (!get_bytes32(penv, jextra_input32, extra_input32, "extra input")) return NULL;
    }

    result = secp256k1_musig_nonce_gen(ctx, &secnonce, &pubnonce, session_id32,
                                       jseckey == NULL ? NULL : seckey, &pubkey,
                                       jmsg32 == NULL ? NULL : msg32, jkeyaggcache == NULL ? NULL : &keyaggcache, jextra_input32 == NULL ? NULL : extra_input32);
    CHECKRESULT(!result, "secp256k1_musig_nonce_gen failed");

    memcpy(nonce, secnonce.data, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SECRET_NONCE_SIZE);
    result = secp256k1_musig_pubnonce_serialize(ctx, nonce + fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SECRET_NONCE_SIZE, &pubnonce);
    CHECKRESULT(!result, "secp256k1_musig_pubnonce_serialize failed");

    return copy_bytes_to_java(penv, nonce, sizeof(nonce));
}

JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1nonce_1gen_1counter(JNIEnv* penv, jclass clazz, jlong jctx, jlong jcounter, jbyteArray jseckey, jbyteArray jmsg32, jbyteArray jkeyaggcache, jbyteArray jextra_input32)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    int result = 0;
    secp256k1_musig_pubnonce pubnonce;
    secp256k1_musig_secnonce secnonce;
    unsigned char seckey[32];
    unsigned char msg32[32];
    secp256k1_keypair keypair;
    secp256k1_musig_keyagg_cache keyaggcache;
    unsigned char extra_input32[32];
    unsigned char nonce[fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SECRET_NONCE_SIZE + fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE];

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jseckey, seckey, "secret key")) return NULL;
    result = secp256k1_keypair_create(ctx, &keypair, seckey);
    CHECKRESULT(!result, "secp256k1_keypair_create failed");

    if (jmsg32 != NULL) {
        if (!get_bytes32(penv, jmsg32, msg32, "message")) return NULL;
    }

    if (jkeyaggcache != NULL) {
        if (!get_bytes(penv, jkeyaggcache, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, keyaggcache.data, "keyagg cache")) return NULL;
        CHECKMAGIC(keyaggcache.data, MUSIG_KEYAGG_CACHE_MAGIC, "invalid keyagg cache");
    }

    if (jextra_input32 != NULL) {
        if (!get_bytes32(penv, jextra_input32, extra_input32, "extra input")) return NULL;
    }

    result = secp256k1_musig_nonce_gen_counter(ctx, &secnonce, &pubnonce, jcounter,
                                               &keypair,
                                               jmsg32 == NULL ? NULL : msg32, jkeyaggcache == NULL ? NULL : &keyaggcache, jextra_input32 == NULL ? NULL : extra_input32);
    CHECKRESULT(!result, "secp256k1_musig_nonce_gen failed");

    memcpy(nonce, secnonce.data, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SECRET_NONCE_SIZE);
    result = secp256k1_musig_pubnonce_serialize(ctx, nonce + fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SECRET_NONCE_SIZE, &pubnonce);
    CHECKRESULT(!result, "secp256k1_musig_pubnonce_serialize failed");

    return copy_bytes_to_java(penv, nonce, sizeof(nonce));
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_nonce_agg
 * Signature: (J[[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1nonce_1agg(JNIEnv* penv, jclass clazz, jlong jctx, jobjectArray jnonces)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char in66[fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE];
    secp256k1_musig_pubnonce* pubnonces;
    secp256k1_musig_pubnonce** pubnonce_ptrs;
    secp256k1_musig_aggnonce combined;
    jbyteArray jnonce;
    size_t count;
    size_t i;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    CHECKRESULT(jnonces == NULL, "public nonces cannot be null");

    count = (*penv)->GetArrayLength(penv, jnonces);
    CHECKRESULT(count == 0, "public nonces count cannot be 0");

    pubnonces = calloc(count, sizeof(secp256k1_musig_pubnonce));
    CHECKRESULT(pubnonces == NULL, "memory allocation error");
    pubnonce_ptrs = calloc(count, sizeof(secp256k1_musig_pubnonce*));
    CHECKRESULT1(pubnonce_ptrs == NULL, "memory allocation error", free(pubnonces));

    for (i = 0; i < count; i++) {
        pubnonce_ptrs[i] = &(pubnonces[i]);
        jnonce = (jbyteArray)(*penv)->GetObjectArrayElement(penv, jnonces, i);
        if (!get_bytes(penv, jnonce, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE, in66, "public nonce")) {
            free(pubnonce_ptrs);
            free(pubnonces);
            return NULL;
        }
        (*penv)->DeleteLocalRef(penv, jnonce);
        result = secp256k1_musig_pubnonce_parse(ctx, pubnonce_ptrs[i], in66);
        CHECKRESULT1(!result, "secp256k1_musig_pubnonce_parse failed", free(pubnonce_ptrs); free(pubnonces));
    }
    result = secp256k1_musig_nonce_agg(ctx, &combined, (const secp256k1_musig_pubnonce* const*)pubnonce_ptrs, count);
    free(pubnonce_ptrs);
    free(pubnonces);
    CHECKRESULT(!result, "secp256k1_musig_nonce_agg failed");

    result = secp256k1_musig_aggnonce_serialize(ctx, in66, &combined);
    CHECKRESULT(!result, "secp256k1_musig_aggnonce_serialize failed");

    return copy_bytes_to_java(penv, in66, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_pubkey_agg
 * Signature: (J[[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1pubkey_1agg(JNIEnv* penv, jclass clazz, jlong jctx, jobjectArray jpubkeys, jbyteArray jkeyaggcache)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char pub[65];
    secp256k1_pubkey* pubkeys;
    secp256k1_pubkey** pubkey_ptrs;
    secp256k1_xonly_pubkey combined;
    secp256k1_musig_keyagg_cache keyaggcache;
    jbyteArray jpubkey;
    size_t count;
    size_t i;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    CHECKRESULT(jpubkeys == NULL, "public keys cannot be null");
    count = (*penv)->GetArrayLength(penv, jpubkeys);
    CHECKRESULT(count == 0, "pubkeys count cannot be 0");

    if (jkeyaggcache != NULL) {
        if (!get_bytes(penv, jkeyaggcache, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, keyaggcache.data, "keyagg cache")) return NULL;
    }

    pubkeys = calloc(count, sizeof(secp256k1_pubkey));
    CHECKRESULT(pubkeys == NULL, "memory allocation error");
    pubkey_ptrs = calloc(count, sizeof(secp256k1_pubkey*));
    CHECKRESULT1(pubkey_ptrs == NULL, "memory allocation error", free(pubkeys));

    for (i = 0; i < count; i++) {
        pubkey_ptrs[i] = &(pubkeys[i]);
        jpubkey = (jbyteArray)(*penv)->GetObjectArrayElement(penv, jpubkeys, i);
        if (!get_pubkey(penv, ctx, jpubkey, pubkey_ptrs[i])) {
            free(pubkey_ptrs);
            free(pubkeys);
            return NULL;
        }
        (*penv)->DeleteLocalRef(penv, jpubkey);
    }
    result = secp256k1_musig_pubkey_agg(ctx, &combined, jkeyaggcache == NULL ? NULL : &keyaggcache, (const secp256k1_pubkey* const*)pubkey_ptrs, count);
    free(pubkey_ptrs);
    free(pubkeys);
    CHECKRESULT(!result, "secp256k1_musig_pubkey_agg failed");
    result = secp256k1_xonly_pubkey_serialize(ctx, pub, &combined);
    CHECKRESULT(!result, "secp256k1_xonly_pubkey_serialize failed");

    jpubkey = (*penv)->NewByteArray(penv, 32);
    CHECKRESULT(jpubkey == NULL, "memory allocation failed");
    (*penv)->SetByteArrayRegion(penv, jpubkey, 0, 32, (const jbyte*)pub);

    if (jkeyaggcache != NULL) {
        (*penv)->SetByteArrayRegion(penv, jkeyaggcache, 0, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, (const jbyte*)keyaggcache.data);
    }
    return jpubkey;
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_pubkey_ec_tweak_add
 * Signature: (J[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1pubkey_1ec_1tweak_1add(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jkeyaggcache, jbyteArray jtweak32)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char tweak32[32], pub[65];
    secp256k1_pubkey pubkey;
    secp256k1_musig_keyagg_cache keyaggcache;
    jbyteArray jpubkey;
    size_t size;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes(penv, jkeyaggcache, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, keyaggcache.data, "keyagg cache")) return NULL;
    CHECKMAGIC(keyaggcache.data, MUSIG_KEYAGG_CACHE_MAGIC, "invalid keyagg cache");

    if (!get_bytes32(penv, jtweak32, tweak32, "tweak")) return NULL;

    result = secp256k1_musig_pubkey_ec_tweak_add(ctx, &pubkey, &keyaggcache, tweak32);
    CHECKRESULT(!result, "secp256k1_musig_pubkey_ec_tweak_add failed");

    size = 65;
    result = secp256k1_ec_pubkey_serialize(ctx, pub, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

    jpubkey = (*penv)->NewByteArray(penv, 65);
    CHECKRESULT(jpubkey == NULL, "memory allocation failed");
    (*penv)->SetByteArrayRegion(penv, jpubkey, 0, 65, (const jbyte*)pub);

    (*penv)->SetByteArrayRegion(penv, jkeyaggcache, 0, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, (const jbyte*)keyaggcache.data);

    return jpubkey;
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_pubkey_xonly_tweak_add
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1pubkey_1xonly_1tweak_1add(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jkeyaggcache, jbyteArray jtweak32)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char tweak32[32], pub[65];
    secp256k1_pubkey pubkey;
    secp256k1_musig_keyagg_cache keyaggcache;
    jbyteArray jpubkey;
    size_t size;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes(penv, jkeyaggcache, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, keyaggcache.data, "keyagg cache")) return NULL;
    CHECKMAGIC(keyaggcache.data, MUSIG_KEYAGG_CACHE_MAGIC, "invalid keyagg cache");
    if (!get_bytes32(penv, jtweak32, tweak32, "tweak")) return NULL;

    result = secp256k1_musig_pubkey_xonly_tweak_add(ctx, &pubkey, &keyaggcache, tweak32);
    CHECKRESULT(!result, "secp256k1_musig_pubkey_xonly_tweak_add failed");

    size = 65;
    result = secp256k1_ec_pubkey_serialize(ctx, pub, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

    jpubkey = (*penv)->NewByteArray(penv, 65);
    CHECKRESULT(jpubkey == NULL, "memory allocation failed");
    (*penv)->SetByteArrayRegion(penv, jpubkey, 0, 65, (const jbyte*)pub);

    (*penv)->SetByteArrayRegion(penv, jkeyaggcache, 0, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, (const jbyte*)keyaggcache.data);

    return jpubkey;
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_nonce_process
 * Signature: (J[B[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1nonce_1process(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jaggnonce, jbyteArray jmsg32, jbyteArray jkeyaggcache)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    secp256k1_musig_keyagg_cache keyaggcache;
    secp256k1_musig_aggnonce aggnonce;
    secp256k1_musig_session session;
    unsigned char msg32[32];
    unsigned char buffer[fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE];
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes(penv, jaggnonce, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE, buffer, "aggregate nonce")) return NULL;
    result = secp256k1_musig_aggnonce_parse(ctx, &aggnonce, buffer);
    CHECKRESULT(!result, "secp256k1_musig_aggnonce_parse failed");

    if (!get_bytes32(penv, jmsg32, msg32, "message")) return NULL;
    if (!get_bytes(penv, jkeyaggcache, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, keyaggcache.data, "keyagg cache")) return NULL;
    CHECKMAGIC(keyaggcache.data, MUSIG_KEYAGG_CACHE_MAGIC, "invalid keyagg cache");

    result = secp256k1_musig_nonce_process(ctx, &session, &aggnonce, msg32, &keyaggcache);
    CHECKRESULT(!result, "secp256k1_musig_nonce_process failed");

    return copy_bytes_to_java(penv, session.data, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SESSION_SIZE);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_partial_sign
 * Signature: (J[B[B[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1partial_1sign(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jsecnonce, jbyteArray jprivkey, jbyteArray jkeyaggcache, jbyteArray jsession)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    secp256k1_musig_partial_sig psig;
    secp256k1_musig_secnonce secnonce;
    unsigned char seckey[32], sig[32];
    secp256k1_keypair keypair;
    secp256k1_musig_keyagg_cache keyaggcache;
    secp256k1_musig_session session;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jprivkey, seckey, "secret key")) return NULL;
    result = secp256k1_keypair_create(ctx, &keypair, seckey);
    CHECKRESULT(!result, "secp256k1_keypair_create failed");
    if (!get_bytes(penv, jsecnonce, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SECRET_NONCE_SIZE, secnonce.data, "secret nonce")) return NULL;
    CHECKMAGIC(secnonce.data, MUSIG_SECNONCE_MAGIC, "invalid secret nonce");
    if (!get_bytes(penv, jkeyaggcache, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, keyaggcache.data, "keyagg cache")) return NULL;
    CHECKMAGIC(keyaggcache.data, MUSIG_KEYAGG_CACHE_MAGIC, "invalid keyagg cache");
    if (!get_bytes(penv, jsession, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SESSION_SIZE, session.data, "session")) return NULL;
    CHECKMAGIC(session.data, MUSIG_SESSION_MAGIC, "invalid session");

    result = secp256k1_musig_partial_sign(ctx, &psig, &secnonce, &keypair, &keyaggcache, &session);
    CHECKRESULT(!result, "secp256k1_musig_partial_sign failed");

    result = secp256k1_musig_partial_sig_serialize(ctx, sig, &psig);
    CHECKRESULT(!result, "secp256k1_musig_partial_sig_serialize failed");

    return copy_bytes_to_java(penv, sig, 32);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_partial_sig_verify
 * Signature: (J[B[B[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1partial_1sig_1verify(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jpsig, jbyteArray jpubnonce, jbyteArray jpubkey, jbyteArray jkeyaggcache, jbyteArray jsession)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    secp256k1_musig_partial_sig psig;
    secp256k1_musig_pubnonce pubnonce;
    secp256k1_pubkey pubkey;
    secp256k1_musig_keyagg_cache keyaggcache;
    secp256k1_musig_session session;
    unsigned char psig_buffer[32];
    unsigned char nonce_buffer[fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE];
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jpsig, psig_buffer, "partial signature")) return 0;
    if (!get_bytes(penv, jpubnonce, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE, nonce_buffer, "public nonce")) return 0;
    if (!get_pubkey(penv, ctx, jpubkey, &pubkey)) return 0;
    if (!get_bytes(penv, jkeyaggcache, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, keyaggcache.data, "keyagg cache")) return 0;
    CHECKMAGIC(keyaggcache.data, MUSIG_KEYAGG_CACHE_MAGIC, "invalid keyagg cache");
    if (!get_bytes(penv, jsession, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SESSION_SIZE, session.data, "session")) return 0;
    CHECKMAGIC(session.data, MUSIG_SESSION_MAGIC, "invalid session");

    result = secp256k1_musig_partial_sig_parse(ctx, &psig, psig_buffer);
    CHECKRESULT(!result, "secp256k1_musig_partial_sig_parse failed");

    result = secp256k1_musig_pubnonce_parse(ctx, &pubnonce, nonce_buffer);
    CHECKRESULT(!result, "secp256k1_musig_pubnonce_parse failed");

    result = secp256k1_musig_partial_sig_verify(ctx, &psig, &pubnonce, &pubkey, &keyaggcache, &session);
    return result;
}


/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_partial_sig_agg
 * Signature: (J[B[[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1partial_1sig_1agg(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jsession, jobjectArray jpsigs)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    secp256k1_musig_session session;
    secp256k1_musig_partial_sig* psigs;
    secp256k1_musig_partial_sig** psig_ptrs;
    unsigned char sig64[64];
    jbyteArray jpsig;
    size_t count;
    size_t i;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes(penv, jsession, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SESSION_SIZE, session.data, "session")) return NULL;
    CHECKMAGIC(session.data, MUSIG_SESSION_MAGIC, "invalid session");

    CHECKRESULT(jpsigs == NULL, "partial signatures cannot be null");
    count = (*penv)->GetArrayLength(penv, jpsigs);
    CHECKRESULT(count == 0, "partial sigs count cannot be 0");

    psigs = calloc(count, sizeof(secp256k1_musig_partial_sig));
    CHECKRESULT(psigs == NULL, "memory allocation error");
    psig_ptrs = calloc(count, sizeof(secp256k1_musig_partial_sig*));
    CHECKRESULT1(psig_ptrs == NULL, "memory allocation error", free(psigs));

    for (i = 0; i < count; i++) {
        psig_ptrs[i] = &(psigs[i]);
        jpsig = (jbyteArray)(*penv)->GetObjectArrayElement(penv, jpsigs, i);
        if (!get_bytes(penv, jpsig, 32, sig64, "partial signature")) {
            free(psig_ptrs);
            free(psigs);
            return NULL;
        }
        (*penv)->DeleteLocalRef(penv, jpsig);
        result = secp256k1_musig_partial_sig_parse(ctx, psig_ptrs[i], sig64);
        CHECKRESULT1(!result, "secp256k1_musig_partial_sig_parse failed", free(psig_ptrs); free(psigs));
    }
    result = secp256k1_musig_partial_sig_agg(ctx, sig64, &session, (const secp256k1_musig_partial_sig* const*)psig_ptrs, count);
    free(psig_ptrs);
    free(psigs);
    CHECKRESULT(!result, "secp256k1_musig_pubkey_agg failed");

    return copy_bytes_to_java(penv, sig64, 64);
}
