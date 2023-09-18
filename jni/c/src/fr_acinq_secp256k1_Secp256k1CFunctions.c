#include <string.h>
#include <stdlib.h>

#ifdef WIN32
#define SECP256K1_STATIC // needed on windows when linking to a static version of secp256k1
#endif
#include "include/secp256k1.h"
#include "include/secp256k1_ecdh.h"
#include "include/secp256k1_recovery.h"
#include "include/secp256k1_schnorrsig.h"
#include "fr_acinq_secp256k1_Secp256k1CFunctions.h"

#define SIG_FORMAT_UNKNOWN 0
#define SIG_FORMAT_COMPACT 1
#define SIG_FORMAT_DER 2

void JNI_ThrowByName(JNIEnv *penv, const char* name, const char* msg)
 {
     jclass cls = (*penv)->FindClass(penv, name);
     if (cls != NULL) {
         (*penv)->ThrowNew(penv, cls, msg);
         (*penv)->DeleteLocalRef(penv, cls);
     }
 }

#define CHECKRESULT(errorcheck, message) {                                        \
    if (errorcheck) {                                                             \
        JNI_ThrowByName(penv, "fr/acinq/secp256k1/Secp256k1Exception", message);  \
        return 0;                                                                 \
    }                                                                             \
}

#define CHECKRESULT1(errorcheck, message, dosomething) {                          \
    if (errorcheck) {                                                             \
        dosomething;                                                              \
        JNI_ThrowByName(penv, "fr/acinq/secp256k1/Secp256k1Exception", message);  \
        return 0;                                                                 \
    }                                                                             \
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_context_create
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1context_1create
  (JNIEnv *penv, jclass clazz, jint flags)
{
    return (jlong) secp256k1_context_create(flags);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_context_destroy
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1context_1destroy
  (JNIEnv *penv, jclass clazz, jlong ctx)
{
    if (ctx != 0) {
        secp256k1_context_destroy((secp256k1_context*)ctx);
    }
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_ec_seckey_verify
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1seckey_1verify
  (JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jseckey)
{
    secp256k1_context* ctx = (secp256k1_context *)jctx;
    jbyte *seckey;
    int result = 0;

    if (jctx == 0) return 0;
    if (jseckey == NULL) return 0;
    if ((*penv)->GetArrayLength(penv, jseckey) != 32) return 0;

    seckey = (*penv)->GetByteArrayElements(penv, jseckey, 0);
    result = secp256k1_ec_seckey_verify(ctx, (unsigned char*)seckey);
    (*penv)->ReleaseByteArrayElements(penv, jseckey, seckey, 0);
    return result;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_pubkey_parse
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1pubkey_1parse
  (JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jpubkey)
{
    secp256k1_context* ctx = (secp256k1_context *)jctx;
    jbyte *pubkeyBytes;
    secp256k1_pubkey pubkey;
    size_t size;
    int result = 0;

    if (jctx == 0) return 0;
    if (jpubkey == NULL) return 0;

    size = (*penv)->GetArrayLength(penv, jpubkey);
    CHECKRESULT((size != 33) && (size != 65), "invalid public key size");

    pubkeyBytes = (*penv)->GetByteArrayElements(penv, jpubkey, 0);
    result = secp256k1_ec_pubkey_parse(ctx, &pubkey, (unsigned char*) pubkeyBytes, size);
    (*penv)->ReleaseByteArrayElements(penv, jpubkey, pubkeyBytes, 0);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_parse failed");

    size = 65;
    jpubkey = (*penv)->NewByteArray(penv, 65);
    pubkeyBytes = (*penv)->GetByteArrayElements(penv, jpubkey, 0);
    result = secp256k1_ec_pubkey_serialize(ctx, (unsigned char*) pubkeyBytes, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    (*penv)->ReleaseByteArrayElements(penv, jpubkey, pubkeyBytes, 0);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");
    return jpubkey;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_pubkey_create
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1pubkey_1create
  (JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jseckey)
{
    secp256k1_context* ctx = (secp256k1_context *)jctx;
    jbyte *seckey, *pubkey;
    secp256k1_pubkey pub;
    int result = 0;
    size_t len;
    jbyteArray jpubkey = 0;

    if (jseckey == NULL) return NULL;
    if (jctx == 0) return NULL;

    CHECKRESULT((*penv)->GetArrayLength(penv, jseckey) != 32, "secret key must be 32 bytes");
    seckey = (*penv)->GetByteArrayElements(penv, jseckey, 0);
    result = secp256k1_ec_pubkey_create(ctx, &pub, (unsigned char*)seckey);
    (*penv)->ReleaseByteArrayElements(penv, jseckey, seckey, 0);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_create failed");
    jpubkey = (*penv)->NewByteArray(penv, 65);
    pubkey = (*penv)->GetByteArrayElements(penv, jpubkey, 0);
    len = 65;
    result = secp256k1_ec_pubkey_serialize(ctx, (unsigned char*)pubkey, &len, &pub, SECP256K1_EC_UNCOMPRESSED);
    (*penv)->ReleaseByteArrayElements(penv, jpubkey, pubkey, 0);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");
    return jpubkey;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ecdsa_sign
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ecdsa_1sign
  (JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jmsg, jbyteArray jseckey)
{
    secp256k1_context* ctx = (secp256k1_context *)jctx;
    jbyte *seckey, *msg, *sig;
    secp256k1_ecdsa_signature signature;
    int result = 0;
    jbyteArray jsig;

    if (jctx == 0) return NULL;
    if (jmsg == NULL) return NULL;
    if (jseckey == NULL) return NULL;

    CHECKRESULT((*penv)->GetArrayLength(penv, jseckey) != 32, "secret key must be 32 bytes");
    CHECKRESULT((*penv)->GetArrayLength(penv, jmsg) != 32, "message key must be 32 bytes");
    seckey = (*penv)->GetByteArrayElements(penv, jseckey, 0);
    msg = (*penv)->GetByteArrayElements(penv, jmsg, 0);

    result = secp256k1_ecdsa_sign(ctx, &signature, (unsigned char*)msg, (unsigned char*)seckey, NULL, NULL);
    (*penv)->ReleaseByteArrayElements(penv, jseckey, seckey, 0);
    (*penv)->ReleaseByteArrayElements(penv, jmsg, msg, 0);
    CHECKRESULT(!result, "secp256k1_ecdsa_sign failed");

    jsig = (*penv)->NewByteArray(penv, 64);
    sig = (*penv)->GetByteArrayElements(penv, jsig, 0);
    result = secp256k1_ecdsa_signature_serialize_compact(ctx, (unsigned char*)sig, &signature);
    (*penv)->ReleaseByteArrayElements(penv, jsig, sig, 0);
    CHECKRESULT(!result, "secp256k1_ecdsa_signature_serialize_compact failed");
    return jsig;
}

int GetSignatureFormat(size_t size)
{
    if (size == 64) return SIG_FORMAT_COMPACT;
    if (size < 64) return SIG_FORMAT_UNKNOWN;
    return SIG_FORMAT_DER;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ecdsa_verify
 * Signature: (J[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ecdsa_1verify
  (JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jsig, jbyteArray jmsg, jbyteArray jpubkey)
{
    secp256k1_context* ctx = (secp256k1_context *)jctx;
    jbyte *pub, *msg, *sig;
    secp256k1_ecdsa_signature signature;
    secp256k1_pubkey pubkey;
    size_t sigSize, pubSize;
    int result = 0;

    if (jctx == 0) return 0;
    if (jsig == NULL) return 0;
    if (jmsg == NULL) return 0;
    if (jpubkey == NULL) return 0;

    sigSize = (*penv)->GetArrayLength(penv, jsig);
    int sigFormat = GetSignatureFormat(sigSize);
    CHECKRESULT(sigFormat == SIG_FORMAT_UNKNOWN, "invalid signature size");

    pubSize = (*penv)->GetArrayLength(penv, jpubkey);
    CHECKRESULT((pubSize != 33) && (pubSize != 65), "invalid public key size");

    CHECKRESULT((*penv)->GetArrayLength(penv, jmsg) != 32, "message must be 32 bytes");

    sig = (*penv)->GetByteArrayElements(penv, jsig, 0);
    switch(sigFormat) {
        case SIG_FORMAT_COMPACT:
            result = secp256k1_ecdsa_signature_parse_compact(ctx, &signature, (unsigned char*)sig);
            (*penv)->ReleaseByteArrayElements(penv, jsig, sig, 0);
            CHECKRESULT(!result, "secp256k1_ecdsa_signature_parse_compact failed");
            break;
        case SIG_FORMAT_DER:
            result = secp256k1_ecdsa_signature_parse_der(ctx, &signature, (unsigned char*)sig, sigSize);
            (*penv)->ReleaseByteArrayElements(penv, jsig, sig, 0);
            CHECKRESULT(!result, "secp256k1_ecdsa_signature_parse_der failed");
            break;
    }

    pub = (*penv)->GetByteArrayElements(penv, jpubkey, 0);
    result = secp256k1_ec_pubkey_parse(ctx, &pubkey, (unsigned char*)pub, pubSize);
    (*penv)->ReleaseByteArrayElements(penv, jpubkey, pub, 0);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_parse failed");

    msg = (*penv)->GetByteArrayElements(penv, jmsg, 0);
    result = secp256k1_ecdsa_verify(ctx, &signature, (unsigned char*)msg, &pubkey);
    (*penv)->ReleaseByteArrayElements(penv, jmsg, msg, 0);
    return result;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ecdsa_signature_normalize
 * Signature: (J[B[B)I
 */
JNIEXPORT jint JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ecdsa_1signature_1normalize
  (JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jsigin, jbyteArray jsigout)
{
    secp256k1_context* ctx = (secp256k1_context *)jctx;
    jbyte *sig;
    secp256k1_ecdsa_signature signature_in, signature_out;
    size_t size;
    int result = 0;
    int return_value = 0;
    int sigFormat = SIG_FORMAT_UNKNOWN;

    if (jctx == 0) return 0;
    if (jsigin == NULL) return 0;
    if (jsigout == NULL) return 0;

    size = (*penv)->GetArrayLength(penv, jsigin);
    sigFormat = GetSignatureFormat(size);
    CHECKRESULT(sigFormat == SIG_FORMAT_UNKNOWN, "invalid signature size");
    CHECKRESULT((*penv)->GetArrayLength(penv, jsigout) != 64, "output signature length must be 64 bytes");

    sig = (*penv)->GetByteArrayElements(penv, jsigin, 0);
    switch(sigFormat) {
        case SIG_FORMAT_COMPACT:
            result = secp256k1_ecdsa_signature_parse_compact(ctx, &signature_in, (unsigned char*)sig);
            (*penv)->ReleaseByteArrayElements(penv, jsigin, sig, 0);
            CHECKRESULT(!result, "secp256k1_ecdsa_signature_parse_compact failed");
            break;
        case SIG_FORMAT_DER:
            result = secp256k1_ecdsa_signature_parse_der(ctx, &signature_in, (unsigned char*)sig, size);
            (*penv)->ReleaseByteArrayElements(penv, jsigin, sig, 0);
            CHECKRESULT(!result, "secp256k1_ecdsa_signature_parse_der failed");
            break;
    }
    return_value = secp256k1_ecdsa_signature_normalize(ctx, &signature_out, &signature_in);
    sig = (*penv)->GetByteArrayElements(penv, jsigout, 0);
    result = secp256k1_ecdsa_signature_serialize_compact(ctx, (unsigned char*)sig, &signature_out);
    (*penv)->ReleaseByteArrayElements(penv, jsigout, sig, 0);
    CHECKRESULT(!result, "secp256k1_ecdsa_signature_serialize_compact failed");

    return return_value;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_privkey_negate
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1privkey_1negate
  (JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jseckey)
{
    secp256k1_context* ctx = (secp256k1_context *)jctx;
    jbyte *seckey;
    int result = 0;

    if (jctx == 0) return 0;
    if (jseckey == NULL) return 0;
    CHECKRESULT((*penv)->GetArrayLength(penv, jseckey) != 32, "secret key must be 32 bytes");
    seckey = (*penv)->GetByteArrayElements(penv, jseckey, 0);
    result = secp256k1_ec_seckey_negate(ctx, (unsigned char*)seckey);
    (*penv)->ReleaseByteArrayElements(penv, jseckey, seckey, 0);
    CHECKRESULT(!result, "secp256k1_ec_seckey_negate failed");
    return jseckey;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_pubkey_negate
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1pubkey_1negate
  (JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jpubkey)
{
    secp256k1_context* ctx = (secp256k1_context *)jctx;
    jbyte *pub;
    secp256k1_pubkey pubkey;
    size_t size;
    int result = 0;

    if (jctx == 0) return 0;
    if (jpubkey == NULL) return 0;

    size = (*penv)->GetArrayLength(penv, jpubkey);
    CHECKRESULT((size != 33) && (size != 65), "invalid public key size");
    pub = (*penv)->GetByteArrayElements(penv, jpubkey, 0);
    result = secp256k1_ec_pubkey_parse(ctx, &pubkey, (unsigned char*)pub, size);
    (*penv)->ReleaseByteArrayElements(penv, jpubkey, pub, 0);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_parse failed");

    result = secp256k1_ec_pubkey_negate(ctx, &pubkey);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_negate failed");

    size = 65;
    jpubkey = (*penv)->NewByteArray(penv, 65);
    pub = (*penv)->GetByteArrayElements(penv, jpubkey, 0);
    result = secp256k1_ec_pubkey_serialize(ctx, (unsigned char*)pub, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    (*penv)->ReleaseByteArrayElements(penv, jpubkey, pub, 0);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");
    return jpubkey;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_privkey_tweak_add
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1privkey_1tweak_1add
  (JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jseckey, jbyteArray jtweak)
{
    secp256k1_context* ctx = (secp256k1_context *)jctx;
    jbyte *seckey, *tweak;
    int result = 0;

    if (jctx == 0) return NULL;
    if (jseckey == NULL) return NULL;
    if (jtweak == NULL) return NULL;

    CHECKRESULT((*penv)->GetArrayLength(penv, jseckey) != 32, "secret key must be 32 bytes");
    CHECKRESULT((*penv)->GetArrayLength(penv, jtweak) != 32, "tweak must be 32 bytes");
    seckey = (*penv)->GetByteArrayElements(penv, jseckey, 0);
    tweak = (*penv)->GetByteArrayElements(penv, jtweak, 0);
    result = secp256k1_ec_seckey_tweak_add(ctx, (unsigned char*)seckey, (unsigned char*)tweak);
    (*penv)->ReleaseByteArrayElements(penv, jseckey, seckey, 0);
    (*penv)->ReleaseByteArrayElements(penv, jtweak, tweak, 0);
    CHECKRESULT(!result, "secp256k1_ec_seckey_tweak_add failed");
    return jseckey;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_pubkey_tweak_add
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1pubkey_1tweak_1add
  (JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jpubkey, jbyteArray jtweak)
{
    secp256k1_context* ctx = (secp256k1_context *)jctx;
    jbyte *pub, *tweak;
    secp256k1_pubkey pubkey;
    size_t size;
    int result = 0;

    if (jctx == 0) return NULL;
    if (jpubkey == NULL) return NULL;
    if (jtweak == NULL) return NULL;

    size = (*penv)->GetArrayLength(penv, jpubkey);
    CHECKRESULT((size != 33) && (size != 65), "invalid public key size");
    CHECKRESULT((*penv)->GetArrayLength(penv, jtweak) != 32, "tweak must be 32 bytes");

    pub = (*penv)->GetByteArrayElements(penv, jpubkey, 0);
    result = secp256k1_ec_pubkey_parse(ctx, &pubkey, (unsigned char*)pub, size);
    (*penv)->ReleaseByteArrayElements(penv, jpubkey, pub, 0);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_parse failed");

    tweak = (*penv)->GetByteArrayElements(penv, jtweak, 0);
    result = secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, (unsigned char*)tweak);
    (*penv)->ReleaseByteArrayElements(penv, jtweak, tweak, 0);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_tweak_add failed");

    size = 65;
    jpubkey = (*penv)->NewByteArray(penv, 65);
    pub = (*penv)->GetByteArrayElements(penv, jpubkey, 0);
    result = secp256k1_ec_pubkey_serialize(ctx, (unsigned char*)pub, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    (*penv)->ReleaseByteArrayElements(penv, jpubkey, pub, 0);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");
    return jpubkey;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_privkey_tweak_mul
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1privkey_1tweak_1mul
  (JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jseckey, jbyteArray jtweak)
{
    secp256k1_context* ctx = (secp256k1_context *)jctx;
    jbyte *seckey, *tweak;
    int result = 0;

    if (jctx == 0) return NULL;
    if (jseckey == NULL) return NULL;
    if (jtweak == NULL) return NULL;

    CHECKRESULT((*penv)->GetArrayLength(penv, jseckey) != 32, "secret key must be 32 bytes");
    CHECKRESULT((*penv)->GetArrayLength(penv, jtweak) != 32, "tweak must be 32 bytes");
    seckey = (*penv)->GetByteArrayElements(penv, jseckey, 0);
    tweak = (*penv)->GetByteArrayElements(penv, jtweak, 0);
    result = secp256k1_ec_seckey_tweak_mul(ctx, (unsigned char*)seckey, (unsigned char*)tweak);
    CHECKRESULT(!result, "secp256k1_ec_seckey_tweak_mul failed");
    (*penv)->ReleaseByteArrayElements(penv, jseckey, seckey, 0);
    (*penv)->ReleaseByteArrayElements(penv, jtweak, tweak, 0);
    return jseckey;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_pubkey_tweak_mul
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1pubkey_1tweak_1mul
  (JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jpubkey, jbyteArray jtweak)
{
    secp256k1_context* ctx = (secp256k1_context *)jctx;
    jbyte *pub, *tweak;
    secp256k1_pubkey pubkey;
    size_t size;
    int result = 0;

    if (jctx == 0) return NULL;
    if (jpubkey == NULL) return NULL;
    if (jtweak == NULL) return NULL;

    size = (*penv)->GetArrayLength(penv, jpubkey);
    CHECKRESULT((size != 33) && (size != 65), "invalid public key size");
    CHECKRESULT((*penv)->GetArrayLength(penv, jtweak) != 32, "tweak must be 32 bytes");
    pub = (*penv)->GetByteArrayElements(penv, jpubkey, 0);
    result = secp256k1_ec_pubkey_parse(ctx, &pubkey, (unsigned char*)pub, size);
    (*penv)->ReleaseByteArrayElements(penv, jpubkey, pub, 0);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_parse failed");

    tweak = (*penv)->GetByteArrayElements(penv, jtweak, 0);
    result = secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, (unsigned char*)tweak);
    (*penv)->ReleaseByteArrayElements(penv, jtweak, tweak, 0);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_tweak_mul failed");

    size = 65;
    jpubkey = (*penv)->NewByteArray(penv, 65);
    pub = (*penv)->GetByteArrayElements(penv, jpubkey, 0);
    result = secp256k1_ec_pubkey_serialize(ctx, (unsigned char*)pub, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    (*penv)->ReleaseByteArrayElements(penv, jpubkey, pub, 0);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");
    return jpubkey;
}

void free_pubkeys(secp256k1_pubkey **pubkeys, size_t count)
{
    size_t i;
    for(i = 0; i < count; i++) {
        if (pubkeys[i] != NULL) free(pubkeys[i]);
    }
    free(pubkeys);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_pubkey_combine
 * Signature: (J[[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1pubkey_1combine
  (JNIEnv *penv, jclass clazz, jlong jctx, jobjectArray jpubkeys)
{
    secp256k1_context* ctx = (secp256k1_context *)jctx;
    jbyte *pub;
    secp256k1_pubkey **pubkeys;
    secp256k1_pubkey combined;
    jbyteArray jpubkey;
    size_t size, count;
    size_t i;
    int result = 0;

    if (jctx == 0) return NULL;
    if (jpubkeys == NULL) return NULL;

    count = (*penv)->GetArrayLength(penv, jpubkeys);
    pubkeys = calloc(count, sizeof(secp256k1_pubkey*));

    for(i = 0; i < count; i++) {
        pubkeys[i] = calloc(1, sizeof(secp256k1_pubkey));
        jpubkey = (jbyteArray) (*penv)->GetObjectArrayElement(penv, jpubkeys, i);
        size = (*penv)->GetArrayLength(penv, jpubkey);
        CHECKRESULT1((size != 33) && (size != 65), "invalid public key size", free_pubkeys(pubkeys, count));
        pub = (*penv)->GetByteArrayElements(penv, jpubkey, 0);
        result = secp256k1_ec_pubkey_parse(ctx, pubkeys[i], (unsigned char*)pub, size);
        (*penv)->ReleaseByteArrayElements(penv, jpubkey, pub, 0);
        CHECKRESULT1(!result, "secp256k1_ec_pubkey_parse failed", free_pubkeys(pubkeys, count));
    }
    result = secp256k1_ec_pubkey_combine(ctx, &combined, (const secp256k1_pubkey * const *)pubkeys, count);
    free_pubkeys(pubkeys, count);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_combine failed");

    size = 65;
    jpubkey = (*penv)->NewByteArray(penv, 65);
    pub = (*penv)->GetByteArrayElements(penv, jpubkey, 0);
    result = secp256k1_ec_pubkey_serialize(ctx, (unsigned char*)pub, &size, &combined, SECP256K1_EC_UNCOMPRESSED);
    (*penv)->ReleaseByteArrayElements(penv, jpubkey, pub, 0);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");
    return jpubkey;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ecdh
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ecdh
  (JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jseckey, jbyteArray jpubkey)
{
    secp256k1_context* ctx = (secp256k1_context *)jctx;
    jbyte* seckeyBytes, *pubkeyBytes, *output;
    secp256k1_pubkey pubkey;
    jbyteArray joutput;
    size_t size;
    int result;

    if (jctx == 0) return NULL;
    if (jseckey == NULL) return NULL;
    if (jpubkey == NULL) return NULL;

    CHECKRESULT((*penv)->GetArrayLength(penv, jseckey) != 32, "invalid private key size");

    size = (*penv)->GetArrayLength(penv, jpubkey);
    CHECKRESULT((size != 33) && (size != 65), "invalid public key size");
    pubkeyBytes = (*penv)->GetByteArrayElements(penv, jpubkey, 0);
    result = secp256k1_ec_pubkey_parse(ctx, &pubkey, (unsigned char*)pubkeyBytes, size);
    (*penv)->ReleaseByteArrayElements(penv, jpubkey, pubkeyBytes, 0);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_parse failed");

    seckeyBytes = (*penv)->GetByteArrayElements(penv, jseckey, 0);
    joutput = (*penv)->NewByteArray(penv, 32);
    output = (*penv)->GetByteArrayElements(penv, joutput, 0);
    result = secp256k1_ecdh(ctx, (unsigned char*)output, &pubkey, (unsigned char*)seckeyBytes, NULL, NULL);
    (*penv)->ReleaseByteArrayElements(penv, joutput, output, 0);
    (*penv)->ReleaseByteArrayElements(penv, jseckey, seckeyBytes, 0);
    return joutput;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ecdsa_recover
 * Signature: (J[B[BI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ecdsa_1recover
  (JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jsig, jbyteArray jmsg, jint recid)
{
    secp256k1_context* ctx = (secp256k1_context *)jctx;
    jbyte* sig, *msg, *pub;
    jbyteArray jpubkey;
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_recoverable_signature signature;
    secp256k1_ecdsa_signature dummy;
    unsigned char dummyBytes[64];
    size_t sigSize, size;
    int result;

    if (jctx == 0) return NULL;
    if (jsig == NULL) return NULL;
    if (jmsg == NULL) return NULL;

    sigSize = (*penv)->GetArrayLength(penv, jsig);
    int sigFormat = GetSignatureFormat(sigSize);
    CHECKRESULT(sigFormat == SIG_FORMAT_UNKNOWN, "invalid signature size");
    CHECKRESULT((*penv)->GetArrayLength(penv, jmsg) != 32, "message must be 32 bytes");
    sig = (*penv)->GetByteArrayElements(penv, jsig, 0);
    switch(sigFormat) {
        case SIG_FORMAT_COMPACT:
            result = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &signature, (unsigned char*)sig, recid);
            (*penv)->ReleaseByteArrayElements(penv, jsig, sig, 0);
            CHECKRESULT(!result, "secp256k1_ecdsa_recoverable_signature_parse_compact failed");
            break;
        case SIG_FORMAT_DER:
            result = secp256k1_ecdsa_signature_parse_der(ctx, &dummy, (unsigned char*)sig, sigSize);
            (*penv)->ReleaseByteArrayElements(penv, jsig, sig, 0);
            CHECKRESULT(!result, "secp256k1_ecdsa_signature_parse_der failed");
            result = secp256k1_ecdsa_signature_serialize_compact(ctx, dummyBytes, &dummy);
            CHECKRESULT(!result, "secp256k1_ecdsa_signature_serialize_compact failed");
            result = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &signature, dummyBytes, recid);
            CHECKRESULT(!result, "secp256k1_ecdsa_recoverable_signature_parse_compact failed");
            break;
    }
    msg = (*penv)->GetByteArrayElements(penv, jmsg, 0);
    result = secp256k1_ecdsa_recover(ctx, &pubkey, &signature, (unsigned char*)msg);
    (*penv)->ReleaseByteArrayElements(penv, jmsg, msg, 0);
    CHECKRESULT(!result, "secp256k1_ecdsa_recover failed");

    size = 65;
    jpubkey = (*penv)->NewByteArray(penv, 65);
    pub = (*penv)->GetByteArrayElements(penv, jpubkey, 0);
    result = secp256k1_ec_pubkey_serialize(ctx, (unsigned char*)pub, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    (*penv)->ReleaseByteArrayElements(penv, jpubkey, pub, 0);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");
    return jpubkey;
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_compact_to_der
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1compact_1to_1der
  (JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jsig)
{
    secp256k1_context* ctx = (secp256k1_context *)jctx;
    jbyte *sig;
    secp256k1_ecdsa_signature signature;;
    unsigned char der[73];
    size_t size;
    int result = 0;

    if (jctx == 0) return 0;
    if (jsig == NULL) return 0;
    CHECKRESULT((*penv)->GetArrayLength(penv, jsig) != 64, "invalid signature size");

    size = (*penv)->GetArrayLength(penv, jsig);
    sig = (*penv)->GetByteArrayElements(penv, jsig, 0);
    result = secp256k1_ecdsa_signature_parse_compact(ctx, &signature, (unsigned char*)sig);
    (*penv)->ReleaseByteArrayElements(penv, jsig, sig, 0);
    CHECKRESULT(!result, "secp256k1_ecdsa_signature_parse_compact failed");

    size = 73;
    result = secp256k1_ecdsa_signature_serialize_der(ctx, der, &size, &signature);
    CHECKRESULT(!result, "secp256k1_ecdsa_signature_serialize_der failed");
    jsig = (*penv)->NewByteArray(penv, size);
    sig = (*penv)->GetByteArrayElements(penv, jsig, 0);
    memcpy(sig, der, size);
    (*penv)->ReleaseByteArrayElements(penv, jsig, sig, 0);
    return jsig;
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_schnorrsig_sign
 * Signature: (J[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1schnorrsig_1sign
  (JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jmsg, jbyteArray jseckey, jbyteArray jauxrand32)
{
    secp256k1_context* ctx = (secp256k1_context *)jctx;
    jbyte *seckey, *msg, *sig, *auxrand32 = NULL;
    secp256k1_keypair keypair;
    unsigned char signature[64];
    int result = 0;
    jbyteArray jsig;

    if (jctx == 0) return NULL;
    if (jmsg == NULL) return NULL;
    if (jseckey == NULL) return NULL;

    CHECKRESULT((*penv)->GetArrayLength(penv, jseckey) != 32, "secret key must be 32 bytes");
    CHECKRESULT((*penv)->GetArrayLength(penv, jmsg) != 32, "message must be 32 bytes");
    if (jauxrand32 != 0) {
        CHECKRESULT((*penv)->GetArrayLength(penv, jauxrand32) != 32, "auxiliary random data must be 32 bytes");
    }
    seckey = (*penv)->GetByteArrayElements(penv, jseckey, 0);
    result = secp256k1_keypair_create(ctx, &keypair, seckey);
    (*penv)->ReleaseByteArrayElements(penv, jseckey, seckey, 0);
    CHECKRESULT(!result, "secp256k1_keypair_create failed");

    msg = (*penv)->GetByteArrayElements(penv, jmsg, 0);
    if (jauxrand32 != 0) {
        auxrand32 = (*penv)->GetByteArrayElements(penv, jauxrand32, 0);
    }

    result = secp256k1_schnorrsig_sign32(ctx, signature, (unsigned char*)msg, &keypair, auxrand32);
    (*penv)->ReleaseByteArrayElements(penv, jmsg, msg, 0);
    if (auxrand32 != 0) {
        (*penv)->ReleaseByteArrayElements(penv, jauxrand32, auxrand32, 0);
    }
    CHECKRESULT(!result, "secp256k1_schnorrsig_sign failed");

    jsig = (*penv)->NewByteArray(penv, 64);
    sig = (*penv)->GetByteArrayElements(penv, jsig, 0);
    memcpy(sig, signature, 64);
    (*penv)->ReleaseByteArrayElements(penv, jsig, sig, 0);
    return jsig;
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_schnorrsig_verify
 * Signature: (J[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1schnorrsig_1verify
  (JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jsig, jbyteArray jmsg, jbyteArray jpubkey)
{
    secp256k1_context* ctx = (secp256k1_context *)jctx;
    jbyte *pub, *msg, *sig;
    secp256k1_xonly_pubkey pubkey;
    int result = 0;

    if (jctx == 0) return 0;
    if (jsig == NULL) return 0;
    if (jmsg == NULL) return 0;
    if (jpubkey == NULL) return 0;

    CHECKRESULT((*penv)->GetArrayLength(penv, jsig) != 64, "signature must be 64 bytes");
    CHECKRESULT((*penv)->GetArrayLength(penv, jpubkey) != 32, "public key must be 32 bytes");
    CHECKRESULT((*penv)->GetArrayLength(penv, jmsg) != 32, "message must be 32 bytes");

    pub = (*penv)->GetByteArrayElements(penv, jpubkey, 0);
    result = secp256k1_xonly_pubkey_parse(ctx, &pubkey, (unsigned char*)pub);
    (*penv)->ReleaseByteArrayElements(penv, jpubkey, pub, 0);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_parse failed");

    sig = (*penv)->GetByteArrayElements(penv, jsig, 0);
    msg = (*penv)->GetByteArrayElements(penv, jmsg, 0);
    result = secp256k1_schnorrsig_verify(ctx, (unsigned char*)sig, (unsigned char*)msg, 32, &pubkey);
    (*penv)->ReleaseByteArrayElements(penv, jsig, sig, 0);
    (*penv)->ReleaseByteArrayElements(penv, jmsg, msg, 0);
    return result;
}
