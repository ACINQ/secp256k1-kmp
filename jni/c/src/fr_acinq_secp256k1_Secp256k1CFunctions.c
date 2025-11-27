#include <string.h>
#include <stdlib.h>

#ifdef WIN32
#define SECP256K1_STATIC // needed on windows when linking to a static version of secp256k1
#endif
#include "include/secp256k1.h"
#include "include/secp256k1_ecdh.h"
#include "include/secp256k1_recovery.h"
#include "include/secp256k1_schnorrsig.h"
#include "include/secp256k1_musig.h"
#include "fr_acinq_secp256k1_Secp256k1CFunctions.h"

#define SIG_FORMAT_UNKNOWN 0
#define SIG_FORMAT_COMPACT 1
#define SIG_FORMAT_DER 2

static void JNI_ThrowByName(JNIEnv *penv, const char *name, const char *msg)
{
  jclass cls = (*penv)->FindClass(penv, name);
  if (cls != NULL)
  {
    (*penv)->ThrowNew(penv, cls, msg);
    (*penv)->DeleteLocalRef(penv, cls);
  }
}

#define CHECKRESULT(errorcheck, message)                                       \
  {                                                                            \
    if (errorcheck)                                                            \
    {                                                                          \
      JNI_ThrowByName(penv, "fr/acinq/secp256k1/Secp256k1Exception", message); \
      return 0;                                                                \
    }                                                                          \
  }

#define CHECKRESULT1(errorcheck, message, dosomething)                         \
  {                                                                            \
    if (errorcheck)                                                            \
    {                                                                          \
      dosomething;                                                             \
      JNI_ThrowByName(penv, "fr/acinq/secp256k1/Secp256k1Exception", message); \
      return 0;                                                                \
    }                                                                          \
  }

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_context_create
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1context_1create(JNIEnv *penv, jclass clazz, jint flags)
{
  return (jlong)secp256k1_context_create(flags);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_context_destroy
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1context_1destroy(JNIEnv *penv, jclass clazz, jlong ctx)
{
  if (ctx != 0)
  {
    secp256k1_context_destroy((secp256k1_context *)ctx);
  }
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_ec_seckey_verify
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1seckey_1verify(JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jseckey)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  jbyte seckey[32];
  int result = 0;

  if (jctx == 0) return 0;
  if (jseckey == NULL) return 0;
  if ((*penv)->GetArrayLength(penv, jseckey) != 32) return 0;

  (*penv)->GetByteArrayRegion(penv, jseckey, 0, 32, seckey);
  result = secp256k1_ec_seckey_verify(ctx, (unsigned char *)seckey);
  return result;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_pubkey_parse
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1pubkey_1parse(JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jpubkey)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  jbyte pubkeyBytes[65];
  secp256k1_pubkey pubkey;
  size_t size;
  int result = 0;

  if (jctx == 0) return 0;
  if (jpubkey == NULL) return 0;

  size = (*penv)->GetArrayLength(penv, jpubkey);
  CHECKRESULT((size != 33) && (size != 65), "invalid public key size");

  (*penv)->GetByteArrayRegion(penv, jpubkey, 0, size, pubkeyBytes);
  result = secp256k1_ec_pubkey_parse(ctx, &pubkey, (unsigned char *)pubkeyBytes, size);
  CHECKRESULT(!result, "secp256k1_ec_pubkey_parse failed");
  size = 65;
  result = secp256k1_ec_pubkey_serialize(ctx, (unsigned char *)pubkeyBytes, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
  CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

  jpubkey = (*penv)->NewByteArray(penv, 65);
  (*penv)->SetByteArrayRegion(penv, jpubkey, 0, 65, pubkeyBytes);
  return jpubkey;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_pubkey_create
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1pubkey_1create(JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jseckey)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  jbyte seckey[32], pubkey[65];
  secp256k1_pubkey pub;
  int result = 0;
  size_t len;
  jbyteArray jpubkey = 0;

  if (jseckey == NULL) return NULL;
  if (jctx == 0) return NULL;

  CHECKRESULT((*penv)->GetArrayLength(penv, jseckey) != 32, "secret key must be 32 bytes");
  (*penv)->GetByteArrayRegion(penv, jseckey, 0, 32, seckey);
  result = secp256k1_ec_pubkey_create(ctx, &pub, (unsigned char *)seckey);
  CHECKRESULT(!result, "secp256k1_ec_pubkey_create failed");

  len = 65;
  result = secp256k1_ec_pubkey_serialize(ctx, (unsigned char *)pubkey, &len, &pub, SECP256K1_EC_UNCOMPRESSED);
  CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");
 
  jpubkey = (*penv)->NewByteArray(penv, 65);
  (*penv)->SetByteArrayRegion(penv, jpubkey, 0, 65, pubkey);
  return jpubkey;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ecdsa_sign
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ecdsa_1sign(JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jmsg, jbyteArray jseckey)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  jbyte seckey[32], msg[32], sig[64];
  secp256k1_ecdsa_signature signature;
  int result = 0;
  jbyteArray jsig;

  if (jctx == 0) return NULL;
  if (jmsg == NULL) return NULL;
  if (jseckey == NULL) return NULL;

  CHECKRESULT((*penv)->GetArrayLength(penv, jseckey) != 32, "secret key must be 32 bytes");
  CHECKRESULT((*penv)->GetArrayLength(penv, jmsg) != 32, "message key must be 32 bytes");
  (*penv)->GetByteArrayRegion(penv, jseckey, 0, 32, seckey);
  (*penv)->GetByteArrayRegion(penv, jmsg, 0, 32, msg);

  result = secp256k1_ecdsa_sign(ctx, &signature, (unsigned char *)msg, (unsigned char *)seckey, NULL, NULL);
  CHECKRESULT(!result, "secp256k1_ecdsa_sign failed");

  result = secp256k1_ecdsa_signature_serialize_compact(ctx, (unsigned char *)sig, &signature);
  CHECKRESULT(!result, "secp256k1_ecdsa_signature_serialize_compact failed");

  jsig = (*penv)->NewByteArray(penv, 64);
  (*penv)->SetByteArrayRegion(penv, jsig, 0, 64, sig);
  return jsig;
}

static int GetSignatureFormat(size_t size)
{
  if (size == 64)
    return SIG_FORMAT_COMPACT;
  if (size < 64)
    return SIG_FORMAT_UNKNOWN;
  if (size > 73)
    return SIG_FORMAT_UNKNOWN;
  return SIG_FORMAT_DER;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ecdsa_verify
 * Signature: (J[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ecdsa_1verify(JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jsig, jbyteArray jmsg, jbyteArray jpubkey)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  jbyte pub[65], msg[32], sig[73];
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

  (*penv)->GetByteArrayRegion(penv, jsig, 0, sigSize, sig);
  switch (sigFormat)
  {
  case SIG_FORMAT_COMPACT:
    result = secp256k1_ecdsa_signature_parse_compact(ctx, &signature, (unsigned char *)sig);
    CHECKRESULT(!result, "secp256k1_ecdsa_signature_parse_compact failed");
    break;
  case SIG_FORMAT_DER:
    result = secp256k1_ecdsa_signature_parse_der(ctx, &signature, (unsigned char *)sig, sigSize);
    CHECKRESULT(!result, "secp256k1_ecdsa_signature_parse_der failed");
    break;
  }

  (*penv)->GetByteArrayRegion(penv, jpubkey, 0, pubSize, pub);
  result = secp256k1_ec_pubkey_parse(ctx, &pubkey, (unsigned char *)pub, pubSize);
  CHECKRESULT(!result, "secp256k1_ec_pubkey_parse failed");

  (*penv)->GetByteArrayRegion(penv, jmsg, 0, 32, msg);
  result = secp256k1_ecdsa_verify(ctx, &signature, (unsigned char *)msg, &pubkey);
  return result;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ecdsa_signature_normalize
 * Signature: (J[B[B)I
 */
JNIEXPORT jint JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ecdsa_1signature_1normalize(JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jsigin, jbyteArray jsigout)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  jbyte sig[73];
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

  (*penv)->GetByteArrayRegion(penv, jsigin, 0, size, sig);
  switch (sigFormat)
  {
  case SIG_FORMAT_COMPACT:
    result = secp256k1_ecdsa_signature_parse_compact(ctx, &signature_in, (unsigned char *)sig);
    CHECKRESULT(!result, "secp256k1_ecdsa_signature_parse_compact failed");
    break;
  case SIG_FORMAT_DER:
    result = secp256k1_ecdsa_signature_parse_der(ctx, &signature_in, (unsigned char *)sig, size);
    CHECKRESULT(!result, "secp256k1_ecdsa_signature_parse_der failed");
    break;
  }
  return_value = secp256k1_ecdsa_signature_normalize(ctx, &signature_out, &signature_in);
  result = secp256k1_ecdsa_signature_serialize_compact(ctx, (unsigned char *)sig, &signature_out);
  CHECKRESULT(!result, "secp256k1_ecdsa_signature_serialize_compact failed");

  (*penv)->SetByteArrayRegion(penv, jsigout, 0, 64, sig);

  return return_value;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_seckey_negate
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1seckey_1negate(JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jseckey)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  jbyte seckey[32];
  int result = 0;

  if (jctx == 0) return 0;
  if (jseckey == NULL) return 0;
  CHECKRESULT((*penv)->GetArrayLength(penv, jseckey) != 32, "secret key must be 32 bytes");
  (*penv)->GetByteArrayRegion(penv, jseckey, 0, 32, seckey);
  result = secp256k1_ec_seckey_negate(ctx, (unsigned char *)seckey);
  CHECKRESULT(!result, "secp256k1_ec_seckey_negate failed");

  jseckey = (*penv)->NewByteArray(penv, 32);
  (*penv)->SetByteArrayRegion(penv, jseckey, 0, 32, seckey);
  return jseckey;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_pubkey_negate
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1pubkey_1negate(JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jpubkey)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  jbyte pub[65];
  secp256k1_pubkey pubkey;
  size_t size;
  int result = 0;

  if (jctx == 0) return 0;
  if (jpubkey == NULL) return 0;

  size = (*penv)->GetArrayLength(penv, jpubkey);
  CHECKRESULT((size != 33) && (size != 65), "invalid public key size");
  (*penv)->GetByteArrayRegion(penv, jpubkey, 0, size, pub);
  result = secp256k1_ec_pubkey_parse(ctx, &pubkey, (unsigned char *)pub, size);
  CHECKRESULT(!result, "secp256k1_ec_pubkey_parse failed");

  result = secp256k1_ec_pubkey_negate(ctx, &pubkey);
  CHECKRESULT(!result, "secp256k1_ec_pubkey_negate failed");

  size = 65;
  result = secp256k1_ec_pubkey_serialize(ctx, (unsigned char *)pub, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
  CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

  jpubkey = (*penv)->NewByteArray(penv, 65);
  (*penv)->SetByteArrayRegion(penv, jpubkey, 0, 65, pub);
  return jpubkey;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_seckey_tweak_add
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1seckey_1tweak_1add(JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jseckey, jbyteArray jtweak)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  jbyte seckey[32], tweak[32];
  int result = 0;

  if (jctx == 0) return NULL;
  if (jseckey == NULL) return NULL;
  if (jtweak == NULL) return NULL;

  CHECKRESULT((*penv)->GetArrayLength(penv, jseckey) != 32, "secret key must be 32 bytes");
  CHECKRESULT((*penv)->GetArrayLength(penv, jtweak) != 32, "tweak must be 32 bytes");
  (*penv)->GetByteArrayRegion(penv, jseckey, 0, 32, seckey);
  (*penv)->GetByteArrayRegion(penv, jtweak, 0, 32, tweak);

  result = secp256k1_ec_seckey_tweak_add(ctx, (unsigned char *)seckey, (unsigned char *)tweak);
  CHECKRESULT(!result, "secp256k1_ec_seckey_tweak_add failed");

  jseckey = (*penv)->NewByteArray(penv, 32);
  (*penv)->SetByteArrayRegion(penv, jseckey, 0, 32, seckey);
  return jseckey;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_pubkey_tweak_add
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1pubkey_1tweak_1add(JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jpubkey, jbyteArray jtweak)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  jbyte pub[65], tweak[32];
  secp256k1_pubkey pubkey;
  size_t size;
  int result = 0;

  if (jctx == 0) return NULL;
  if (jpubkey == NULL) return NULL;
  if (jtweak == NULL) return NULL;

  size = (*penv)->GetArrayLength(penv, jpubkey);
  CHECKRESULT((size != 33) && (size != 65), "invalid public key size");
  CHECKRESULT((*penv)->GetArrayLength(penv, jtweak) != 32, "tweak must be 32 bytes");

  (*penv)->GetByteArrayRegion(penv, jpubkey, 0, size, pub);
  result = secp256k1_ec_pubkey_parse(ctx, &pubkey, (unsigned char *)pub, size);
  CHECKRESULT(!result, "secp256k1_ec_pubkey_parse failed");

  (*penv)->GetByteArrayRegion(penv, jtweak, 0, 32, tweak);
  result = secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, (unsigned char *)tweak);
  CHECKRESULT(!result, "secp256k1_ec_pubkey_tweak_add failed");

  size = 65;
  result = secp256k1_ec_pubkey_serialize(ctx, (unsigned char *)pub, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
  CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");
 
  jpubkey = (*penv)->NewByteArray(penv, 65);
  (*penv)->SetByteArrayRegion(penv, jpubkey, 0, 65, pub);
  return jpubkey;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_seckey_tweak_mul
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1seckey_1tweak_1mul(JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jseckey, jbyteArray jtweak)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  jbyte seckey[32], tweak[32];
  int result = 0;

  if (jctx == 0) return NULL;
  if (jseckey == NULL) return NULL;
  if (jtweak == NULL) return NULL;

  CHECKRESULT((*penv)->GetArrayLength(penv, jseckey) != 32, "secret key must be 32 bytes");
  CHECKRESULT((*penv)->GetArrayLength(penv, jtweak) != 32, "tweak must be 32 bytes");
  (*penv)->GetByteArrayRegion(penv, jseckey, 0, 32, seckey);
  (*penv)->GetByteArrayRegion(penv, jtweak, 0, 32, tweak);
  result = secp256k1_ec_seckey_tweak_mul(ctx, (unsigned char *)seckey, (unsigned char *)tweak);
  CHECKRESULT(!result, "secp256k1_ec_seckey_tweak_mul failed");

  jseckey = (*penv)->NewByteArray(penv, 32);
  (*penv)->SetByteArrayRegion(penv, jseckey, 0, 32, seckey);
  return jseckey;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_pubkey_tweak_mul
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1pubkey_1tweak_1mul(JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jpubkey, jbyteArray jtweak)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  jbyte pub[65], tweak[32];
  secp256k1_pubkey pubkey;
  size_t size;
  int result = 0;

  if (jctx == 0) return NULL;
  if (jpubkey == NULL) return NULL;
  if (jtweak == NULL) return NULL;

  size = (*penv)->GetArrayLength(penv, jpubkey);
  CHECKRESULT((size != 33) && (size != 65), "invalid public key size");
  CHECKRESULT((*penv)->GetArrayLength(penv, jtweak) != 32, "tweak must be 32 bytes");
  (*penv)->GetByteArrayRegion(penv, jpubkey, 0, size, pub);
  result = secp256k1_ec_pubkey_parse(ctx, &pubkey, (unsigned char *)pub, size);
  CHECKRESULT(!result, "secp256k1_ec_pubkey_parse failed");

  (*penv)->GetByteArrayRegion(penv, jtweak, 0, 32, tweak);
  result = secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, (unsigned char *)tweak);
  CHECKRESULT(!result, "secp256k1_ec_pubkey_tweak_mul failed");

  size = 65;
  result = secp256k1_ec_pubkey_serialize(ctx, (unsigned char *)pub, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
  CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

  jpubkey = (*penv)->NewByteArray(penv, 65);
  (*penv)->SetByteArrayRegion(penv, jpubkey, 0, 65, pub);
  return jpubkey;
}

static void free_pubkeys(secp256k1_pubkey **pubkeys, size_t count)
{
  size_t i;
  if (pubkeys == NULL) return;
  for (i = 0; i < count; i++)
  {
    if (pubkeys[i] != NULL)
      free(pubkeys[i]);
  }
  free(pubkeys);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_pubkey_combine
 * Signature: (J[[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1pubkey_1combine(JNIEnv *penv, jclass clazz, jlong jctx, jobjectArray jpubkeys)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  jbyte pub[65];
  secp256k1_pubkey **pubkeys;
  secp256k1_pubkey combined;
  jbyteArray jpubkey;
  size_t size, count;
  size_t i;
  int result = 0;

  if (jctx == 0)
    return NULL;
  if (jpubkeys == NULL)
    return NULL;

  count = (*penv)->GetArrayLength(penv, jpubkeys);
  CHECKRESULT(count < 1, "pubkey array cannot be empty")
  pubkeys = calloc(count, sizeof(secp256k1_pubkey *));
  CHECKRESULT(pubkeys == NULL, "memory allocation failed");

  for (i = 0; i < count; i++)
  {
    pubkeys[i] = calloc(1, sizeof(secp256k1_pubkey));
    CHECKRESULT1(pubkeys[i] == NULL, "memory allocation failed", free_pubkeys(pubkeys, count));
    jpubkey = (jbyteArray)(*penv)->GetObjectArrayElement(penv, jpubkeys, i);
    size = (*penv)->GetArrayLength(penv, jpubkey);
    CHECKRESULT1((size != 33) && (size != 65), "invalid public key size", free_pubkeys(pubkeys, count));
    (*penv)->GetByteArrayRegion(penv, jpubkey, 0, size, pub);
    result = secp256k1_ec_pubkey_parse(ctx, pubkeys[i], (unsigned char *)pub, size);
    CHECKRESULT1(!result, "secp256k1_ec_pubkey_parse failed", free_pubkeys(pubkeys, count));
  }
  result = secp256k1_ec_pubkey_combine(ctx, &combined, (const secp256k1_pubkey *const *)pubkeys, count);
  free_pubkeys(pubkeys, count);
  CHECKRESULT(!result, "secp256k1_ec_pubkey_combine failed");

  size = 65;
  result = secp256k1_ec_pubkey_serialize(ctx, (unsigned char *)pub, &size, &combined, SECP256K1_EC_UNCOMPRESSED);
  CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

  jpubkey = (*penv)->NewByteArray(penv, 65);
  (*penv)->SetByteArrayRegion(penv, jpubkey, 0, 65, pub);
  return jpubkey;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ecdh
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ecdh(JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jseckey, jbyteArray jpubkey)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  jbyte seckeyBytes[32], pubkeyBytes[65], output[32];
  secp256k1_pubkey pubkey;
  jbyteArray joutput;
  size_t size;
  int result;

  if (jctx == 0) return NULL;
  if (jseckey == NULL) return NULL;
  if (jpubkey == NULL) return NULL;

  CHECKRESULT((*penv)->GetArrayLength(penv, jseckey) != 32, "invalid private key size");
  (*penv)->GetByteArrayRegion(penv, jseckey, 0, 32, seckeyBytes);

  size = (*penv)->GetArrayLength(penv, jpubkey);
  CHECKRESULT((size != 33) && (size != 65), "invalid public key size");
  (*penv)->GetByteArrayRegion(penv, jpubkey, 0, size, pubkeyBytes);
  result = secp256k1_ec_pubkey_parse(ctx, &pubkey, (unsigned char *)pubkeyBytes, size);
  CHECKRESULT(!result, "secp256k1_ec_pubkey_parse failed");

  result = secp256k1_ecdh(ctx, (unsigned char *)output, &pubkey, (unsigned char *)seckeyBytes, NULL, NULL);
  CHECKRESULT(!result, "secp256k1_ecdh failed");

  joutput = (*penv)->NewByteArray(penv, 32);
  (*penv)->SetByteArrayRegion(penv, joutput, 0, 32, output);
  return joutput;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ecdsa_recover
 * Signature: (J[B[BI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ecdsa_1recover(JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jsig, jbyteArray jmsg, jint recid)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  jbyte sig[73], msg[32], pub[65];
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
  CHECKRESULT(recid < 0 || recid > 3, "invalid recovery id");

  sigSize = (*penv)->GetArrayLength(penv, jsig);
  int sigFormat = GetSignatureFormat(sigSize);
  CHECKRESULT(sigFormat == SIG_FORMAT_UNKNOWN, "invalid signature size");

  CHECKRESULT((*penv)->GetArrayLength(penv, jmsg) != 32, "message must be 32 bytes");
  (*penv)->GetByteArrayRegion(penv, jsig, 0, sigSize, sig);
  switch (sigFormat)
  {
  case SIG_FORMAT_COMPACT:
    result = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &signature, (unsigned char *)sig, recid);
    CHECKRESULT(!result, "secp256k1_ecdsa_recoverable_signature_parse_compact failed");
    break;
  case SIG_FORMAT_DER:
    result = secp256k1_ecdsa_signature_parse_der(ctx, &dummy, (unsigned char *)sig, sigSize);
    CHECKRESULT(!result, "secp256k1_ecdsa_signature_parse_der failed");
    result = secp256k1_ecdsa_signature_serialize_compact(ctx, dummyBytes, &dummy);
    CHECKRESULT(!result, "secp256k1_ecdsa_signature_serialize_compact failed");
    result = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &signature, dummyBytes, recid);
    CHECKRESULT(!result, "secp256k1_ecdsa_recoverable_signature_parse_compact failed");
    break;
  }
  (*penv)->GetByteArrayRegion(penv, jmsg, 0, 32, msg);
  result = secp256k1_ecdsa_recover(ctx, &pubkey, &signature, (unsigned char *)msg);
  CHECKRESULT(!result, "secp256k1_ecdsa_recover failed");

  size = 65;
  result = secp256k1_ec_pubkey_serialize(ctx, (unsigned char *)pub, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
  CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

  jpubkey = (*penv)->NewByteArray(penv, 65);
  (*penv)->SetByteArrayRegion(penv, jpubkey, 0, 65, pub);
  return jpubkey;
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_compact_to_der
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1compact_1to_1der(JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jsig)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  jbyte sig[64];
  secp256k1_ecdsa_signature signature;
  unsigned char der[73];
  size_t size;
  int result = 0;

  if (jctx == 0) return 0;
  if (jsig == NULL) return 0;
  CHECKRESULT((*penv)->GetArrayLength(penv, jsig) != 64, "invalid signature size");

  (*penv)->GetByteArrayRegion(penv, jsig, 0, 64, sig);
  result = secp256k1_ecdsa_signature_parse_compact(ctx, &signature, (unsigned char *)sig);
  CHECKRESULT(!result, "secp256k1_ecdsa_signature_parse_compact failed");

  size = 73;
  result = secp256k1_ecdsa_signature_serialize_der(ctx, der, &size, &signature);
  CHECKRESULT(!result, "secp256k1_ecdsa_signature_serialize_der failed");
  jsig = (*penv)->NewByteArray(penv, size);
  (*penv)->SetByteArrayRegion(penv, jsig, 0, size, der);
  return jsig;
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_schnorrsig_sign
 * Signature: (J[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1schnorrsig_1sign(JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jmsg, jbyteArray jseckey, jbyteArray jauxrand32)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  jbyte seckey[32], msg[32], auxrand32[32];
  secp256k1_keypair keypair;
  unsigned char signature[64];
  int result = 0;
  jbyteArray jsig;

  if (jctx == 0) return NULL;
  if (jmsg == NULL) return NULL;
  if (jseckey == NULL)return NULL;

  CHECKRESULT((*penv)->GetArrayLength(penv, jseckey) != 32, "secret key must be 32 bytes");
  CHECKRESULT((*penv)->GetArrayLength(penv, jmsg) != 32, "message must be 32 bytes");
  if (jauxrand32 != 0)
  {
    CHECKRESULT((*penv)->GetArrayLength(penv, jauxrand32) != 32, "auxiliary random data must be 32 bytes");
  }
  (*penv)->GetByteArrayRegion(penv, jseckey, 0, 32, seckey);
  result = secp256k1_keypair_create(ctx, &keypair, (const unsigned char*)seckey);
  CHECKRESULT(!result, "secp256k1_keypair_create failed");

  (*penv)->GetByteArrayRegion(penv, jmsg, 0, 32, msg);
  if (jauxrand32 != 0)
  {
    (*penv)->GetByteArrayRegion(penv, jauxrand32, 0, 32, auxrand32);
  }

  result = secp256k1_schnorrsig_sign32(ctx, signature, (unsigned char *)msg, &keypair, jauxrand32 != 0 ? auxrand32 : NULL);
  CHECKRESULT(!result, "secp256k1_schnorrsig_sign failed");

  jsig = (*penv)->NewByteArray(penv, 64);
  (*penv)->SetByteArrayRegion(penv, jsig, 0, 64, signature);
  return jsig;
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_schnorrsig_verify
 * Signature: (J[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1schnorrsig_1verify(JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jsig, jbyteArray jmsg, jbyteArray jpubkey)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  jbyte pub[32], msg[32], sig[64];
  secp256k1_xonly_pubkey pubkey;
  int result = 0;

  if (jctx == 0) return 0;
  if (jsig == NULL) return 0;
  if (jmsg == NULL) return 0;
  if (jpubkey == NULL) return 0;

  CHECKRESULT((*penv)->GetArrayLength(penv, jsig) != 64, "signature must be 64 bytes");
  CHECKRESULT((*penv)->GetArrayLength(penv, jpubkey) != 32, "public key must be 32 bytes");
  CHECKRESULT((*penv)->GetArrayLength(penv, jmsg) != 32, "message must be 32 bytes");

  (*penv)->GetByteArrayRegion(penv, jpubkey, 0, 32, pub);
  result = secp256k1_xonly_pubkey_parse(ctx, &pubkey, (unsigned char *)pub);
  CHECKRESULT(!result, "secp256k1_ec_pubkey_parse failed");

  (*penv)->GetByteArrayRegion(penv, jsig, 0, 64, sig);
  (*penv)->GetByteArrayRegion(penv, jmsg, 0, 32, msg);
  result = secp256k1_schnorrsig_verify(ctx, (unsigned char *)sig, (unsigned char *)msg, 32, &pubkey);
  return result;
}

// session_id32: ByteArray, seckey: ByteArray?, pubkey: ByteArray, msg32: ByteArray?, keyagg_cache: ByteArray?, extra_input32: ByteArray?
/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_nonce_gen
 * Signature: (J[B[B[B[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1nonce_1gen(JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jsession_id32, jbyteArray jseckey, jbyteArray jpubkey, jbyteArray jmsg32, jbyteArray jkeyaggcache, jbyteArray jextra_input32)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  int result = 0;
  size_t size;
  secp256k1_musig_pubnonce pubnonce;
  secp256k1_musig_secnonce secnonce;
  unsigned char session_id32[32];
  jbyte pubkeyBytes[65];
  secp256k1_pubkey pubkey;
  unsigned char seckey[32];
  unsigned char msg32[32];
  secp256k1_musig_keyagg_cache keyaggcache;
  unsigned char extra_input32[32];
  jbyteArray jnonce;
  unsigned char nonce[fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SECRET_NONCE_SIZE + fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE];

  if (jctx == 0) return NULL;

  if (jsession_id32 == 0) return NULL;
  size = (*penv)->GetArrayLength(penv, jsession_id32);
  CHECKRESULT(size != 32, "invalid session_id size");
  (*penv)->GetByteArrayRegion(penv, jsession_id32, 0, 32, (jbyte*)session_id32);

  if (jseckey != NULL)
  {
    size = (*penv)->GetArrayLength(penv, jseckey);
    CHECKRESULT(size != 32, "invalid private key size");
    (*penv)->GetByteArrayRegion(penv, jseckey, 0, 32, (jbyte*)seckey);
  }

  if (jpubkey == NULL) return NULL;
  size = (*penv)->GetArrayLength(penv, jpubkey);
  CHECKRESULT((size != 33) && (size != 65), "invalid public key size");
  (*penv)->GetByteArrayRegion(penv, jpubkey, 0, size, pubkeyBytes);
  result = secp256k1_ec_pubkey_parse(ctx, &pubkey, (unsigned char*)pubkeyBytes, size);
  CHECKRESULT(!result, "secp256k1_ec_pubkey_parse failed");

  if (jmsg32 != NULL)
  {
    size = (*penv)->GetArrayLength(penv, jmsg32);
    CHECKRESULT(size != 32, "invalid message size");
    (*penv)->GetByteArrayRegion(penv, jmsg32, 0, 32, msg32);
  }

  if (jkeyaggcache != NULL)
  {
    size = (*penv)->GetArrayLength(penv, jkeyaggcache);
    CHECKRESULT(size != fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, "invalid keyagg cache size");
    (*penv)->GetByteArrayRegion(penv, jkeyaggcache, 0, size, keyaggcache.data);
  }

  if (jextra_input32 != NULL)
  {
    size = (*penv)->GetArrayLength(penv, jextra_input32);
    CHECKRESULT(size != 32, "invalid extra input size");
    (*penv)->GetByteArrayRegion(penv, jextra_input32, 0, size, extra_input32);
  }

  result = secp256k1_musig_nonce_gen(ctx, &secnonce, &pubnonce, session_id32,
                                     jseckey == NULL ? NULL : seckey, &pubkey,
                                     jmsg32 == NULL ? NULL : msg32, jkeyaggcache == NULL ? NULL : &keyaggcache, jextra_input32 == NULL ? NULL : extra_input32);
  CHECKRESULT(!result, "secp256k1_musig_nonce_gen failed");

  memcpy(nonce, secnonce.data, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SECRET_NONCE_SIZE);
  result = secp256k1_musig_pubnonce_serialize(ctx, nonce + fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SECRET_NONCE_SIZE, &pubnonce);
  CHECKRESULT(!result, "secp256k1_musig_pubnonce_serialize failed");

  jnonce = (*penv)->NewByteArray(penv, sizeof(nonce));
  (*penv)->SetByteArrayRegion(penv, jnonce, 0, sizeof(nonce), nonce);
  return jnonce;
}

JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1nonce_1gen_1counter(JNIEnv *penv, jclass clazz, jlong jctx, jlong jcounter, jbyteArray jseckey, jbyteArray jmsg32, jbyteArray jkeyaggcache, jbyteArray jextra_input32)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  int result = 0;
  size_t size;
  secp256k1_musig_pubnonce pubnonce;
  secp256k1_musig_secnonce secnonce;
  jbyte seckey[32];
  unsigned char msg32[32];
  secp256k1_keypair keypair;
  secp256k1_musig_keyagg_cache keyaggcache;
  unsigned char extra_input32[32];
  jbyteArray jnonce;
  unsigned char nonce[fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SECRET_NONCE_SIZE + fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE];

  if (jctx == 0) return NULL;

  if (jseckey == NULL) return NULL;
  size = (*penv)->GetArrayLength(penv, jseckey);
  CHECKRESULT(size != 32, "invalid private key size");
  (*penv)->GetByteArrayRegion(penv, jseckey, 0, 32, seckey);
  result = secp256k1_keypair_create(ctx, &keypair, (const unsigned char*)seckey);
  CHECKRESULT(!result, "secp256k1_keypair_create failed");

  if (jmsg32 != NULL)
  {
    size = (*penv)->GetArrayLength(penv, jmsg32);
    CHECKRESULT(size != 32, "invalid message size");
   (*penv)->GetByteArrayRegion(penv, jmsg32, 0, 32, (jbyte*)msg32);
  }

  if (jkeyaggcache != NULL)
  {
    size = (*penv)->GetArrayLength(penv, jkeyaggcache);
    CHECKRESULT(size != fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, "invalid keyagg cache size");
   (*penv)->GetByteArrayRegion(penv, jkeyaggcache, 0, size, (jbyte*)keyaggcache.data);
  }

  if (jextra_input32 != NULL)
  {
    size = (*penv)->GetArrayLength(penv, jextra_input32);
    CHECKRESULT(size != 32, "invalid extra input size");
   (*penv)->GetByteArrayRegion(penv, jextra_input32, 0, 32, (jbyte*)extra_input32);
  }

  result = secp256k1_musig_nonce_gen_counter(ctx, &secnonce, &pubnonce, jcounter,
                                             &keypair,
                                             jmsg32 == NULL ? NULL : msg32, jkeyaggcache == NULL ? NULL : &keyaggcache, jextra_input32 == NULL ? NULL : extra_input32);
  CHECKRESULT(!result, "secp256k1_musig_nonce_gen failed");

  memcpy(nonce, secnonce.data, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SECRET_NONCE_SIZE);
  result = secp256k1_musig_pubnonce_serialize(ctx, nonce + fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SECRET_NONCE_SIZE, &pubnonce);
  CHECKRESULT(!result, "secp256k1_musig_pubnonce_serialize failed");

  jnonce = (*penv)->NewByteArray(penv, sizeof(nonce));
  (*penv)->SetByteArrayRegion(penv, jnonce, 0, sizeof(nonce), (const jbyte*)nonce);
  return jnonce;
}

static void free_nonces(secp256k1_musig_pubnonce **nonces, size_t count)
{
  size_t i;
  if (nonces == NULL) return;
  for (i = 0; i < count; i++)
  {
    if (nonces[i] != NULL)
      free(nonces[i]);
  }
  free(nonces);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_nonce_agg
 * Signature: (J[[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1nonce_1agg(JNIEnv *penv, jclass clazz, jlong jctx, jobjectArray jnonces)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  jbyte in66[fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE];
  secp256k1_musig_pubnonce **pubnonces;
  secp256k1_musig_aggnonce combined;
  jbyteArray jnonce;
  size_t size, count;
  size_t i;
  int result = 0;

  if (jctx == 0) return NULL;
  if (jnonces == NULL) return NULL;

  count = (*penv)->GetArrayLength(penv, jnonces);
  CHECKRESULT(count == 0, "public nonces count cannot be 0");
  for (i = 0; i < count; i++)
  {
    jnonce = (jbyteArray)(*penv)->GetObjectArrayElement(penv, jnonces, i);
    size = (*penv)->GetArrayLength(penv, jnonce);
    CHECKRESULT(size != fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE, "invalid public nonce size");
  }

  pubnonces = calloc(count, sizeof(secp256k1_musig_pubnonce *));
  CHECKRESULT(pubnonces == NULL, "memory allocation error");

  for (i = 0; i < count; i++)
  {
    pubnonces[i] = calloc(1, sizeof(secp256k1_musig_pubnonce));
    CHECKRESULT1(pubnonces[i] == NULL, "memory allocation error", free_nonces(pubnonces, count));
    jnonce = (jbyteArray)(*penv)->GetObjectArrayElement(penv, jnonces, i);
    size = fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE;
    (*penv)->GetByteArrayRegion(penv, jnonce, 0, size, in66);
    result = secp256k1_musig_pubnonce_parse(ctx, pubnonces[i], (unsigned char *)in66);
    CHECKRESULT1(!result, "secp256k1_musig_pubnonce_parse failed", free_nonces(pubnonces, count));
  }
  result = secp256k1_musig_nonce_agg(ctx, &combined, (const secp256k1_musig_pubnonce *const *)pubnonces, count);
  free_nonces(pubnonces, count);
  CHECKRESULT(!result, "secp256k1_musig_nonce_agg failed");

  result = secp256k1_musig_aggnonce_serialize(ctx, (unsigned char *)in66, &combined);
  CHECKRESULT(!result, "secp256k1_musig_aggnonce_serialize failed");
  jnonce = (*penv)->NewByteArray(penv, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE);
  (*penv)->SetByteArrayRegion(penv, jnonce, 0, size, in66);
  return jnonce;
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_pubkey_agg
 * Signature: (J[[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1pubkey_1agg(JNIEnv *penv, jclass clazz, jlong jctx, jobjectArray jpubkeys, jbyteArray jkeyaggcache)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  jbyte pub[65];
  secp256k1_pubkey **pubkeys;
  secp256k1_xonly_pubkey combined;
  secp256k1_musig_keyagg_cache keyaggcache;
  jbyteArray jpubkey;
  size_t size, count;
  size_t i;
  int result = 0;

  if (jctx == 0) return NULL;
  if (jpubkeys == NULL) return NULL;
  count = (*penv)->GetArrayLength(penv, jpubkeys);
  CHECKRESULT(count == 0, "pubkeys count cannot be 0");
  for (i = 0; i < count; i++)
  {
    jpubkey = (jbyteArray)(*penv)->GetObjectArrayElement(penv, jpubkeys, i);
    size = (*penv)->GetArrayLength(penv, jpubkey);
    CHECKRESULT((size != 33) && (size != 65), "invalid public key size");
  }

  if (jkeyaggcache != NULL)
  {
    size = (*penv)->GetArrayLength(penv, jkeyaggcache);
    CHECKRESULT(size != fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, "invalid keyagg cache size");
    (*penv)->GetByteArrayRegion(penv, jkeyaggcache, 0, size, keyaggcache.data);
  }

  pubkeys = calloc(count, sizeof(secp256k1_pubkey *));
  CHECKRESULT(pubkeys == NULL, "memory allocation error");

  for (i = 0; i < count; i++)
  {
    pubkeys[i] = calloc(1, sizeof(secp256k1_pubkey));
    CHECKRESULT1(pubkeys[i] == NULL, "memory allocation error", free_pubkeys(pubkeys, count));
    jpubkey = (jbyteArray)(*penv)->GetObjectArrayElement(penv, jpubkeys, i);
    size = (*penv)->GetArrayLength(penv, jpubkey);
    (*penv)->GetByteArrayRegion(penv, jpubkey, 0, size, pub);
    result = secp256k1_ec_pubkey_parse(ctx, pubkeys[i], (unsigned char *)pub, size);
    CHECKRESULT1(!result, "secp256k1_ec_pubkey_parse failed", free_pubkeys(pubkeys, count));
  }
  result = secp256k1_musig_pubkey_agg(ctx, &combined, jkeyaggcache == NULL ? NULL : &keyaggcache, (const secp256k1_pubkey *const *)pubkeys, count);
  free_pubkeys(pubkeys, count);
  CHECKRESULT(!result, "secp256k1_musig_pubkey_agg failed");
  result = secp256k1_xonly_pubkey_serialize(ctx, (unsigned char *)pub, &combined);
  CHECKRESULT(!result, "secp256k1_xonly_pubkey_serialize failed");

  jpubkey = (*penv)->NewByteArray(penv, 32);
  (*penv)->SetByteArrayRegion(penv, jpubkey, 0, 32, pub);

  if (jkeyaggcache != NULL)
  {
    (*penv)->SetByteArrayRegion(penv, jkeyaggcache, 0, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, (const jbyte*)keyaggcache.data);
  }
  return jpubkey;
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_pubkey_ec_tweak_add
 * Signature: (J[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1pubkey_1ec_1tweak_1add(JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jkeyaggcache, jbyteArray jtweak32)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  jbyte tweak32[32], pub[65];
  secp256k1_pubkey pubkey;
  secp256k1_musig_keyagg_cache keyaggcache;
  jbyteArray jpubkey;
  size_t size;
  int result = 0;

  if (jctx == 0) return NULL;
  if (jkeyaggcache == NULL) return NULL;
  size = (*penv)->GetArrayLength(penv, jkeyaggcache);
  CHECKRESULT(size != fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, "invalid keyagg cache size");
  (*penv)->GetByteArrayRegion(penv, jkeyaggcache, 0, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, (jbyte*)keyaggcache.data);

  if (jtweak32 == NULL) return NULL;
  CHECKRESULT((*penv)->GetArrayLength(penv, jtweak32) != 32, "tweak must be 32 bytes");
  (*penv)->GetByteArrayRegion(penv, jtweak32, 0, 32, tweak32);

  result = secp256k1_musig_pubkey_ec_tweak_add(ctx, &pubkey, &keyaggcache, (const unsigned char*)tweak32);
  CHECKRESULT(!result, "secp256k1_musig_pubkey_ec_tweak_add failed");

  size = 65;
  result = secp256k1_ec_pubkey_serialize(ctx, (unsigned char*)pub, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
  CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

  jpubkey = (*penv)->NewByteArray(penv, 65);
  (*penv)->SetByteArrayRegion(penv, jpubkey, 0, 65, pub);

  (*penv)->SetByteArrayRegion(penv, jkeyaggcache, 0, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, (const jbyte*)keyaggcache.data);

  return jpubkey;
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_pubkey_xonly_tweak_add
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1pubkey_1xonly_1tweak_1add(JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jkeyaggcache, jbyteArray jtweak32)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  jbyte tweak32[32], pub[65];
  secp256k1_pubkey pubkey;
  secp256k1_musig_keyagg_cache keyaggcache;
  jbyteArray jpubkey;
  size_t size;
  int result = 0;

  if (jctx == 0) return NULL;
  if (jkeyaggcache == NULL) return NULL;
  size = (*penv)->GetArrayLength(penv, jkeyaggcache);
  CHECKRESULT(size != fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, "invalid keyagg cache size");
  (*penv)->GetByteArrayRegion(penv, jkeyaggcache, 0, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, (jbyte*)keyaggcache.data);

  if (jtweak32 == NULL) return NULL;
  CHECKRESULT((*penv)->GetArrayLength(penv, jtweak32) != 32, "tweak must be 32 bytes");
  (*penv)->GetByteArrayRegion(penv, jtweak32, 0, 32, tweak32);

  result = secp256k1_musig_pubkey_xonly_tweak_add(ctx, &pubkey, &keyaggcache, (const unsigned char*)tweak32);
  CHECKRESULT(!result, "secp256k1_musig_pubkey_xonly_tweak_add failed");

  size = 65;
  result = secp256k1_ec_pubkey_serialize(ctx, (unsigned char*)pub, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
  CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

  jpubkey = (*penv)->NewByteArray(penv, 65);
  (*penv)->SetByteArrayRegion(penv, jpubkey, 0, 65, pub);
  
  (*penv)->SetByteArrayRegion(penv, jkeyaggcache, 0, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, (const jbyte*)keyaggcache.data);

  return jpubkey;
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_nonce_process
 * Signature: (J[B[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1nonce_1process(JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jaggnonce, jbyteArray jmsg32, jbyteArray jkeyaggcache)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  secp256k1_musig_keyagg_cache keyaggcache;
  secp256k1_musig_aggnonce aggnonce;
  secp256k1_musig_session session;
  unsigned char msg32[32];
  jbyteArray jsession;
  jbyte buffer[fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE];
  int result = 0;

  if (jctx == 0) return NULL;
  if (jaggnonce == NULL) return NULL;
  CHECKRESULT((*penv)->GetArrayLength(penv, jaggnonce) != fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE, "invalid nonce size");
  if (jmsg32 == NULL) return NULL;
  CHECKRESULT((*penv)->GetArrayLength(penv, jmsg32) != 32, "invalid message size");
  if (jkeyaggcache == NULL) return NULL;
  CHECKRESULT((*penv)->GetArrayLength(penv, jkeyaggcache) != fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, "invalid keyagg cache size");

  (*penv)->GetByteArrayRegion(penv, jaggnonce, 0, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE, buffer);
  result = secp256k1_musig_aggnonce_parse(ctx, &aggnonce, (const unsigned char*)buffer);
  CHECKRESULT(!result, "secp256k1_musig_aggnonce_parse failed");

  (*penv)->GetByteArrayRegion(penv, jmsg32, 0, 32, msg32);

  (*penv)->GetByteArrayRegion(penv, jkeyaggcache, 0, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, (jbyte*)keyaggcache.data);

  result = secp256k1_musig_nonce_process(ctx, &session, &aggnonce, msg32, &keyaggcache);
  CHECKRESULT(!result, "secp256k1_musig_nonce_process failed");

  jsession = (*penv)->NewByteArray(penv, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SESSION_SIZE);
  (*penv)->SetByteArrayRegion(penv, jsession, 0, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SESSION_SIZE, (const jbyte*)session.data);
  return jsession;
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_partial_sign
 * Signature: (J[B[B[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1partial_1sign(JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jsecnonce, jbyteArray jprivkey, jbyteArray jkeyaggcache, jbyteArray jsession)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  secp256k1_musig_partial_sig psig;
  secp256k1_musig_secnonce secnonce;
  unsigned char seckey[32], sig[32];
  secp256k1_keypair keypair;
  secp256k1_musig_keyagg_cache keyaggcache;
  secp256k1_musig_session session;
  jbyteArray jpsig;
  int result = 0;

  if (jctx == 0) return NULL;
  if (jsecnonce == NULL) return NULL;
  CHECKRESULT((*penv)->GetArrayLength(penv, jsecnonce) != fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SECRET_NONCE_SIZE, "invalid secret nonce size");
  if (jprivkey == NULL) return NULL;
  CHECKRESULT((*penv)->GetArrayLength(penv, jprivkey) != 32, "invalid private key size");
  if (jkeyaggcache == NULL) return NULL;
  CHECKRESULT((*penv)->GetArrayLength(penv, jkeyaggcache) != fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, "invalid cache size");
  if (jsession == NULL) return NULL;
  CHECKRESULT((*penv)->GetArrayLength(penv, jsession) != fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SESSION_SIZE, "invalid session size");


  (*penv)->GetByteArrayRegion(penv, jsecnonce, 0, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SECRET_NONCE_SIZE, (jbyte*)secnonce.data);

  (*penv)->GetByteArrayRegion(penv, jprivkey, 0, 32, seckey);
  result = secp256k1_keypair_create(ctx, &keypair, seckey);
  CHECKRESULT(!result, "secp256k1_keypair_create failed");


  (*penv)->GetByteArrayRegion(penv, jkeyaggcache, 0, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, (jbyte*)keyaggcache.data);
  (*penv)->GetByteArrayRegion(penv, jsession, 0, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SESSION_SIZE, (jbyte*)session.data);

  result = secp256k1_musig_partial_sign(ctx, &psig, &secnonce, &keypair, &keyaggcache, &session);
  CHECKRESULT(!result, "secp256k1_musig_partial_sign failed");

  result = secp256k1_musig_partial_sig_serialize(ctx, sig, &psig);
  CHECKRESULT(!result, "secp256k1_musig_partial_sig_serialize failed");

  jpsig = (*penv)->NewByteArray(penv, 32);
  (*penv)->SetByteArrayRegion(penv, jpsig, 0, 32, sig);
  return jpsig;
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_partial_sig_verify
 * Signature: (J[B[B[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1partial_1sig_1verify(JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jpsig, jbyteArray jpubnonce, jbyteArray jpubkey, jbyteArray jkeyaggcache, jbyteArray jsession)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  secp256k1_musig_partial_sig psig;
  secp256k1_musig_pubnonce pubnonce;
  secp256k1_pubkey pubkey;
  jsize pubkeySize;
  secp256k1_musig_keyagg_cache keyaggcache;
  secp256k1_musig_session session;
  // we use the same buffer to copy a partial sig, a nonce and a pubkey, largest size is a nonce
  jbyte buffer[fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE];
  int result = 0;

  if (jctx == 0) return 0;

  if (jpsig == NULL) return 0;
  CHECKRESULT((*penv)->GetArrayLength(penv, jpsig) != 32, "invalid partial signature size");

  if (jpubnonce == NULL) return 0;
  CHECKRESULT((*penv)->GetArrayLength(penv, jpubnonce) != fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE, "invalid public nonce size");

  if (jpubkey == NULL) return 0;
  pubkeySize = (*penv)->GetArrayLength(penv, jpubkey);
  CHECKRESULT(pubkeySize != 33 && pubkeySize != 65, "invalid public key size");

  if (jkeyaggcache == NULL) return 0;
  CHECKRESULT((*penv)->GetArrayLength(penv, jkeyaggcache) != fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, "invalid cache size");

  if (jsession == NULL) return 0;
  CHECKRESULT((*penv)->GetArrayLength(penv, jsession) != fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SESSION_SIZE, "invalid session size");

  (*penv)->GetByteArrayRegion(penv, jpsig, 0, 32, buffer);
  result = secp256k1_musig_partial_sig_parse(ctx, &psig, (const unsigned char*)buffer);
  CHECKRESULT(!result, "secp256k1_musig_partial_sig_parse failed");

  (*penv)->GetByteArrayRegion(penv, jpubnonce, 0, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE, buffer);
  result = secp256k1_musig_pubnonce_parse(ctx, &pubnonce, (const unsigned char*)buffer);
  CHECKRESULT(!result, "secp256k1_musig_pubnonce_parse failed");

  (*penv)->GetByteArrayRegion(penv, jpubkey, 0, pubkeySize, buffer);
  result = secp256k1_ec_pubkey_parse(ctx, &pubkey, (const unsigned char*)buffer, pubkeySize);
  CHECKRESULT(!result, "secp256k1_musig_pubkey_parse failed");

  (*penv)->GetByteArrayRegion(penv, jkeyaggcache, 0, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, (jbyte*)keyaggcache.data);
  (*penv)->GetByteArrayRegion(penv, jsession, 0, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SESSION_SIZE, (jbyte*)session.data);

  result = secp256k1_musig_partial_sig_verify(ctx, &psig, &pubnonce, &pubkey, &keyaggcache, &session);

  return result;
}

static void free_partial_sigs(secp256k1_musig_partial_sig **psigs, size_t count)
{
  size_t i;
  if (psigs == NULL) return;
  for (i = 0; i < count; i++)
  {
    if (psigs[i] != NULL)
      free(psigs[i]);
  }
  free(psigs);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_partial_sig_agg
 * Signature: (J[B[[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1partial_1sig_1agg(JNIEnv *penv, jclass clazz, jlong jctx, jbyteArray jsession, jobjectArray jpsigs)
{
  const secp256k1_context *ctx = (const secp256k1_context *)jctx;
  secp256k1_musig_session session;
  secp256k1_musig_partial_sig **psigs;
  unsigned char sig64[64];
  jbyteArray jpsig;
  size_t size, count;
  size_t i;
  int result = 0;

  if (jctx == 0) return NULL;
  if (jsession == NULL) return NULL;
  CHECKRESULT((*penv)->GetArrayLength(penv, jsession) != fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SESSION_SIZE, "invalid session size");
  (*penv)->GetByteArrayRegion(penv, jsession, 0, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SESSION_SIZE, (jbyte*)session.data);

  if (jpsigs == NULL) return NULL;
  count = (*penv)->GetArrayLength(penv, jpsigs);
  CHECKRESULT(count == 0, "partial sigs count cannot be 0");

  psigs = calloc(count, sizeof(secp256k1_musig_partial_sig *));
  CHECKRESULT(psigs == NULL, "memory allocation error");

  for (i = 0; i < count; i++)
  {
    psigs[i] = calloc(1, sizeof(secp256k1_musig_partial_sig));
    CHECKRESULT1(psigs[i] == NULL, "memory allocation error", free_partial_sigs(psigs, count));
    jpsig = (jbyteArray)(*penv)->GetObjectArrayElement(penv, jpsigs, i);
    size = (*penv)->GetArrayLength(penv, jpsig);
    CHECKRESULT1(size != 32, "invalid partial signature size", free_partial_sigs(psigs, count));
    (*penv)->GetByteArrayRegion(penv, jpsig, 0, 32, (jbyte*)sig64);
    result = secp256k1_musig_partial_sig_parse(ctx, psigs[i], sig64);
    CHECKRESULT1(!result, "secp256k1_musig_partial_sig_parse failed", free_partial_sigs(psigs, count));
  }
  result = secp256k1_musig_partial_sig_agg(ctx, sig64, &session, (const secp256k1_musig_partial_sig *const *)psigs, count);
  free_partial_sigs(psigs, count);
  CHECKRESULT(!result, "secp256k1_musig_pubkey_agg failed");

  jpsig = (*penv)->NewByteArray(penv, 64);
  (*penv)->SetByteArrayRegion(penv, jpsig, 0, 64, (const jbyte*)sig64);
  return jpsig;
}
