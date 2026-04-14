/* ssi_identity.h
 *
 * Self-Sovereign Identity module for SSI-TLS 1.3 on ESP32
 * Based on: Perugini & Vesco (2024), IETF draft-vesco-vcauthtls-01
 *
 * This header provides:
 *   1. Ed25519 key pair generation
 *   2. DID:key generation (W3C DID Core v1.0, did:key method)
 *   3. Self-issued VC creation (W3C VC Data Model v2.0, simplified)
 *   4. VC serialization/deserialization for TLS Certificate message
 *   5. VC verification (signature check, DID extraction)
 *   6. did_methods TLS extension data
 *
 * Design: Header-only, implementation guarded by SSI_IDENTITY_IMPL.
 *         Include in exactly ONE .c file with SSI_IDENTITY_IMPL defined.
 *
 * DID:key format (Multicodec):
 *   did:key:z<base58btc(0xed01 + 32-byte-Ed25519-pubkey)>
 *   0xed = Ed25519 multicodec prefix, 0x01 = multicodec varint
 *
 * VC format (simplified binary for TLS transport):
 *   [2B type_tag][2B did_len][did_bytes][2B pubkey_len][pubkey_bytes]
 *   [2B claims_len][claims_bytes][2B sig_len][sig_bytes]
 *
 * Note: This is a simplified VC for PoC. A production implementation
 *       would use JSON-LD or CBOR-LD encoding per W3C spec.
 *
 * Modified by: Muhammad Ikhwan Maulana (2204111010033) - Universitas Syiah Kuala
 */

#ifndef SSI_IDENTITY_H
#define SSI_IDENTITY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* ==========================================================================
 * Constants
 * ==========================================================================
 */

/* VC binary type tag — identifies this as an SSI-TLS VC payload */
#define SSI_VC_TYPE_TAG          0x5643  /* "VC" in ASCII */

/* DID Method identifiers (from Perugini & Vesco Table) */
#define SSI_DID_METHOD_KEY       0x00    /* did:key (self-certifying, no DLT) */
#define SSI_DID_METHOD_IOTA      0x01    /* did:iota (future extension) */

/* Ed25519 multicodec prefix: 0xed 0x01 (varint encoded) */
#define SSI_MULTICODEC_ED25519_0 0xed
#define SSI_MULTICODEC_ED25519_1 0x01

/* Sizes */
#define SSI_ED25519_PUB_KEY_SIZE  32
#define SSI_ED25519_PRIV_KEY_SIZE 32  /* seed */
#define SSI_ED25519_SIG_SIZE      64
#define SSI_DID_KEY_PREFIX_SIZE   2   /* multicodec prefix */
#define SSI_DID_KEY_RAW_SIZE      (SSI_DID_KEY_PREFIX_SIZE + SSI_ED25519_PUB_KEY_SIZE) /* 34 */

/* Maximum sizes for VC fields */
#define SSI_DID_STRING_MAX        128  /* "did:key:z..." max length */
#define SSI_VC_CLAIMS_MAX         256  /* max claims payload */
#define SSI_VC_MAX_SIZE           512  /* max serialized VC */

/* TLS extension: did_methods (private-use range, per RFC 8446 §4.2)
 * We use 0xFF02 from the private-use range 0xFF00..0xFFFF */
#define TLSX_DID_METHODS          0xFF02

/* Certificate type value for VC — extends RFC 7250 enum.
 * Per IETF draft-vesco-vcauthtls-01, VC = 3.
 * Aligns with wolfSSL's WOLFSSL_CERT_TYPE_X509=0, RPK=2. */
#define WOLFSSL_CERT_TYPE_VC      3

/* ==========================================================================
 * Data structures
 * ==========================================================================
 */

/* SSI Identity — holds the complete identity of one endpoint */
typedef struct SSI_Identity {
    /* Ed25519 key pair */
    ed25519_key     key;
    int             keyInitialized;

    /* Raw public key (32 bytes) */
    byte            pubKey[SSI_ED25519_PUB_KEY_SIZE];
    word32          pubKeyLen;

    /* DID:key string (e.g. "did:key:z6Mk...") */
    char            didString[SSI_DID_STRING_MAX];
    int             didStringLen;

    /* DID:key raw bytes (multicodec prefix + pubkey = 34 bytes) */
    byte            didRaw[SSI_DID_KEY_RAW_SIZE];

    /* Serialized VC (self-issued, for TLS Certificate message) */
    byte            vcBuffer[SSI_VC_MAX_SIZE];
    word32          vcLen;

    /* Claims payload (device info, etc.) */
    byte            claims[SSI_VC_CLAIMS_MAX];
    word32          claimsLen;

    /* RNG for key generation */
    WC_RNG          rng;
    int             rngInitialized;
} SSI_Identity;

/* Parsed VC — result of deserializing a peer's VC */
typedef struct SSI_ParsedVC {
    byte            pubKey[SSI_ED25519_PUB_KEY_SIZE];
    word32          pubKeyLen;
    char            didString[SSI_DID_STRING_MAX];
    int             didStringLen;
    byte            claims[SSI_VC_CLAIMS_MAX];
    word32          claimsLen;
    byte            signature[SSI_ED25519_SIG_SIZE];
    word32          sigLen;
    int             isValid;   /* 1 if signature verified */
} SSI_ParsedVC;

/* did_methods extension data for ClientHello / EncryptedExtensions */
typedef struct SSI_DIDMethods {
    byte            methods[8];     /* list of DID method IDs */
    byte            count;          /* number of methods */
} SSI_DIDMethods;

/* ==========================================================================
 * Function declarations
 * ==========================================================================
 */

/* Initialize/free identity */
int  SSI_Identity_Init(SSI_Identity* id);
void SSI_Identity_Free(SSI_Identity* id);

/* Generate Ed25519 key pair and derive DID:key */
int  SSI_Identity_Generate(SSI_Identity* id);

/* Set claims for VC (device name, firmware version, etc.) */
int  SSI_Identity_SetClaims(SSI_Identity* id, const char* claimsStr);

/* Create self-issued VC (Issuer = Holder = this device) */
int  SSI_Identity_CreateVC(SSI_Identity* id);

/* Serialize VC for TLS Certificate message payload */
int  SSI_VC_Serialize(const SSI_Identity* id, byte* output, word32* outLen);

/* Parse and verify a peer's VC from TLS Certificate message */
int  SSI_VC_ParseAndVerify(const byte* vcData, word32 vcLen,
                           SSI_ParsedVC* parsed);

/* Extract raw public key from parsed VC (for CertificateVerify) */
int  SSI_VC_GetPeerPubKey(const SSI_ParsedVC* parsed,
                          byte* pubKey, word32* pubKeyLen);

/* Base58btc encode/decode for DID:key */
int  SSI_Base58_Encode(const byte* input, int inputLen,
                       char* output, int* outputLen);
int  SSI_Base58_Decode(const char* input, int inputLen,
                       byte* output, int* outputLen);

/* Build did_methods extension payload */
int  SSI_DIDMethods_Init(SSI_DIDMethods* dm);
int  SSI_DIDMethods_Serialize(const SSI_DIDMethods* dm,
                              byte* output, word32* outLen);
int  SSI_DIDMethods_Parse(const byte* input, word32 inputLen,
                          SSI_DIDMethods* dm);

/* ==========================================================================
 * Implementation (include in exactly ONE .c/.cpp file)
 * ==========================================================================
 */
#ifdef SSI_IDENTITY_IMPL

/* Base58btc alphabet (Bitcoin variant) */
static const char SSI_BASE58_ALPHABET[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

int SSI_Base58_Encode(const byte* input, int inputLen,
                      char* output, int* outputLen)
{
    /* Simple base58 encoder — sufficient for 34-byte DID:key encoding.
     * Uses repeated division (not performance-critical, called once). */
    int i, j, carry, maxOut;
    byte temp[64]; /* working buffer — 64 bytes enough for 34-byte input */
    int tempLen = 0;
    int zeros = 0;

    if (input == NULL || output == NULL || outputLen == NULL)
        return BAD_FUNC_ARG;

    maxOut = *outputLen;

    /* Count leading zeros */
    for (i = 0; i < inputLen && input[i] == 0; i++)
        zeros++;

    /* Allocate enough for base58 conversion */
    XMEMSET(temp, 0, sizeof(temp));
    tempLen = 0;

    for (i = zeros; i < inputLen; i++) {
        carry = input[i];
        for (j = 0; j < tempLen; j++) {
            carry += 256 * temp[j];
            temp[j] = carry % 58;
            carry /= 58;
        }
        while (carry > 0) {
            if (tempLen >= (int)sizeof(temp))
                return BUFFER_E;
            temp[tempLen++] = carry % 58;
            carry /= 58;
        }
    }

    /* Check output buffer size */
    if (zeros + tempLen + 1 > maxOut)
        return BUFFER_E;

    /* Leading '1's for zero bytes */
    for (i = 0; i < zeros; i++)
        output[i] = '1';

    /* Reverse and map to alphabet */
    for (j = tempLen - 1; j >= 0; j--)
        output[i++] = SSI_BASE58_ALPHABET[temp[j]];

    output[i] = '\0';
    *outputLen = i;
    return 0;
}

int SSI_Base58_Decode(const char* input, int inputLen,
                      byte* output, int* outputLen)
{
    int i, j, carry, maxOut;
    byte temp[64];
    int tempLen = 0;
    int zeros = 0;

    if (input == NULL || output == NULL || outputLen == NULL)
        return BAD_FUNC_ARG;

    maxOut = *outputLen;
    XMEMSET(temp, 0, sizeof(temp));

    /* Count leading '1's (represent zero bytes) */
    for (i = 0; i < inputLen && input[i] == '1'; i++)
        zeros++;

    for (i = zeros; i < inputLen; i++) {
        /* Find character in Base58 alphabet (manual, XSTRCHR not available) */
        {
            int _found = 0;
            int _k;
            for (_k = 0; _k < 58; _k++) {
                if (SSI_BASE58_ALPHABET[_k] == input[i]) {
                    carry = _k;
                    _found = 1;
                    break;
                }
            }
            if (!_found)
                return ASN_INPUT_E; /* invalid character */
        }
        for (j = 0; j < tempLen; j++) {
            carry += 58 * temp[j];
            temp[j] = carry & 0xFF;
            carry >>= 8;
        }
        while (carry > 0) {
            if (tempLen >= (int)sizeof(temp))
                return BUFFER_E;
            temp[tempLen++] = carry & 0xFF;
            carry >>= 8;
        }
    }

    if (zeros + tempLen > maxOut)
        return BUFFER_E;

    /* Leading zeros */
    XMEMSET(output, 0, zeros);

    /* Reverse */
    for (i = 0; i < tempLen; i++)
        output[zeros + i] = temp[tempLen - 1 - i];

    *outputLen = zeros + tempLen;
    return 0;
}

int SSI_Identity_Init(SSI_Identity* id)
{
    int ret;

    if (id == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(id, 0, sizeof(SSI_Identity));

    ret = wc_InitRng(&id->rng);
    if (ret != 0) return ret;
    id->rngInitialized = 1;

    ret = wc_ed25519_init(&id->key);
    if (ret != 0) return ret;
    id->keyInitialized = 1;

    return 0;
}

void SSI_Identity_Free(SSI_Identity* id)
{
    if (id == NULL) return;

    if (id->keyInitialized) {
        wc_ed25519_free(&id->key);
        id->keyInitialized = 0;
    }
    if (id->rngInitialized) {
        wc_FreeRng(&id->rng);
        id->rngInitialized = 0;
    }
    /* Zero sensitive data */
    XMEMSET(id, 0, sizeof(SSI_Identity));
}

int SSI_Identity_Generate(SSI_Identity* id)
{
    int ret;
    word32 pubLen = SSI_ED25519_PUB_KEY_SIZE;
    char b58Buf[64];
    int b58Len = (int)sizeof(b58Buf);

    if (id == NULL || !id->rngInitialized || !id->keyInitialized)
        return BAD_FUNC_ARG;

    /* Generate Ed25519 key pair */
    ret = wc_ed25519_make_key(&id->rng, ED25519_KEY_SIZE, &id->key);
    if (ret != 0) return ret;

    /* Export public key */
    ret = wc_ed25519_export_public(&id->key, id->pubKey, &pubLen);
    if (ret != 0) return ret;
    id->pubKeyLen = pubLen;

    /* Build DID:key raw bytes: multicodec prefix + pubkey */
    id->didRaw[0] = SSI_MULTICODEC_ED25519_0;
    id->didRaw[1] = SSI_MULTICODEC_ED25519_1;
    XMEMCPY(id->didRaw + 2, id->pubKey, SSI_ED25519_PUB_KEY_SIZE);

    /* Encode as did:key:z<base58btc> */
    b58Len = (int)sizeof(b58Buf);
    ret = SSI_Base58_Encode(id->didRaw, SSI_DID_KEY_RAW_SIZE, b58Buf, &b58Len);
    if (ret != 0) return ret;

    /* Build full DID string: "did:key:z" + base58btc */
    id->didStringLen = XSNPRINTF(id->didString, SSI_DID_STRING_MAX,
                                  "did:key:z%s", b58Buf);
    if (id->didStringLen < 0 || id->didStringLen >= SSI_DID_STRING_MAX)
        return BUFFER_E;

    return 0;
}

int SSI_Identity_SetClaims(SSI_Identity* id, const char* claimsStr)
{
    int len;

    if (id == NULL || claimsStr == NULL)
        return BAD_FUNC_ARG;

    len = (int)XSTRLEN(claimsStr);
    if (len >= SSI_VC_CLAIMS_MAX)
        return BUFFER_E;

    XMEMCPY(id->claims, claimsStr, len);
    id->claimsLen = len;
    return 0;
}

int SSI_Identity_CreateVC(SSI_Identity* id)
{
    /*
     * VC binary format (simplified for TLS transport):
     *
     *   [2B type_tag = 0x5643]
     *   [2B did_len][did_string_bytes]
     *   [2B pubkey_len][pubkey_bytes]
     *   [2B claims_len][claims_bytes]
     *   [2B sig_len][signature_bytes]
     *
     * The signature covers everything from type_tag through claims_bytes
     * (i.e., everything except the signature field itself).
     * This is a self-issued VC: Issuer == Holder == this device.
     */
    int ret;
    word32 idx = 0;
    byte* buf = id->vcBuffer;
    word32 sigLen = SSI_ED25519_SIG_SIZE;
    word32 dataToSignLen;

    if (id == NULL || id->didStringLen == 0)
        return BAD_FUNC_ARG;

    /* Type tag */
    buf[idx++] = (SSI_VC_TYPE_TAG >> 8) & 0xFF;
    buf[idx++] = SSI_VC_TYPE_TAG & 0xFF;

    /* DID string */
    buf[idx++] = (id->didStringLen >> 8) & 0xFF;
    buf[idx++] = id->didStringLen & 0xFF;
    XMEMCPY(buf + idx, id->didString, id->didStringLen);
    idx += id->didStringLen;

    /* Public key */
    buf[idx++] = (id->pubKeyLen >> 8) & 0xFF;
    buf[idx++] = id->pubKeyLen & 0xFF;
    XMEMCPY(buf + idx, id->pubKey, id->pubKeyLen);
    idx += id->pubKeyLen;

    /* Claims */
    buf[idx++] = (id->claimsLen >> 8) & 0xFF;
    buf[idx++] = id->claimsLen & 0xFF;
    if (id->claimsLen > 0) {
        XMEMCPY(buf + idx, id->claims, id->claimsLen);
        idx += id->claimsLen;
    }

    /* Remember where signature data ends */
    dataToSignLen = idx;

    /* Sign everything up to this point with our Ed25519 private key */
    ret = wc_ed25519_sign_msg(buf, dataToSignLen,
                               buf + idx + 2, /* sig goes after 2B length */
                               &sigLen,
                               &id->key);
    if (ret != 0) return ret;

    /* Write signature length */
    buf[idx++] = (sigLen >> 8) & 0xFF;
    buf[idx++] = sigLen & 0xFF;
    idx += sigLen;

    id->vcLen = idx;

    if (idx > SSI_VC_MAX_SIZE)
        return BUFFER_E;

    return 0;
}

int SSI_VC_Serialize(const SSI_Identity* id, byte* output, word32* outLen)
{
    if (id == NULL || output == NULL || outLen == NULL)
        return BAD_FUNC_ARG;

    if (id->vcLen == 0)
        return BAD_STATE_E;

    if (*outLen < id->vcLen)
        return BUFFER_E;

    XMEMCPY(output, id->vcBuffer, id->vcLen);
    *outLen = id->vcLen;
    return 0;
}

int SSI_VC_ParseAndVerify(const byte* vcData, word32 vcLen,
                          SSI_ParsedVC* parsed)
{
    /*
     * Parse the binary VC and verify the self-issued signature.
     * The signature covers bytes [0 .. sigOffset-1].
     */
    int ret;
    word32 idx = 0;
    word16 typeTag, fieldLen;
    word32 sigOffset;
    int verified = 0;
    ed25519_key peerKey;

    if (vcData == NULL || parsed == NULL || vcLen < 10)
        return BAD_FUNC_ARG;

    XMEMSET(parsed, 0, sizeof(SSI_ParsedVC));

    /* Type tag */
    typeTag = ((word16)vcData[idx] << 8) | vcData[idx + 1];
    idx += 2;
    if (typeTag != SSI_VC_TYPE_TAG) {
        return ASN_INPUT_E;  /* not a VC */
    }

    /* DID string */
    if (idx + 2 > vcLen) return BUFFER_ERROR;
    fieldLen = ((word16)vcData[idx] << 8) | vcData[idx + 1];
    idx += 2;
    if (fieldLen == 0 || fieldLen >= SSI_DID_STRING_MAX || idx + fieldLen > vcLen)
        return BUFFER_ERROR;
    XMEMCPY(parsed->didString, vcData + idx, fieldLen);
    parsed->didString[fieldLen] = '\0';
    parsed->didStringLen = fieldLen;
    idx += fieldLen;

    /* Public key */
    if (idx + 2 > vcLen) return BUFFER_ERROR;
    fieldLen = ((word16)vcData[idx] << 8) | vcData[idx + 1];
    idx += 2;
    if (fieldLen != SSI_ED25519_PUB_KEY_SIZE || idx + fieldLen > vcLen)
        return BUFFER_ERROR;
    XMEMCPY(parsed->pubKey, vcData + idx, fieldLen);
    parsed->pubKeyLen = fieldLen;
    idx += fieldLen;

    /* Claims */
    if (idx + 2 > vcLen) return BUFFER_ERROR;
    fieldLen = ((word16)vcData[idx] << 8) | vcData[idx + 1];
    idx += 2;
    if (fieldLen >= SSI_VC_CLAIMS_MAX || idx + fieldLen > vcLen)
        return BUFFER_ERROR;
    if (fieldLen > 0) {
        XMEMCPY(parsed->claims, vcData + idx, fieldLen);
    }
    parsed->claimsLen = fieldLen;
    idx += fieldLen;

    /* Signature offset = everything before signature is what was signed */
    sigOffset = idx;

    /* Signature */
    if (idx + 2 > vcLen) return BUFFER_ERROR;
    fieldLen = ((word16)vcData[idx] << 8) | vcData[idx + 1];
    idx += 2;
    if (fieldLen != SSI_ED25519_SIG_SIZE || idx + fieldLen > vcLen)
        return BUFFER_ERROR;
    XMEMCPY(parsed->signature, vcData + idx, fieldLen);
    parsed->sigLen = fieldLen;
    idx += fieldLen;

    /* Verify signature using the public key embedded in the VC */
    ret = wc_ed25519_init(&peerKey);
    if (ret != 0) return ret;

    ret = wc_ed25519_import_public(parsed->pubKey, parsed->pubKeyLen, &peerKey);
    if (ret != 0) {
        wc_ed25519_free(&peerKey);
        return ret;
    }

    ret = wc_ed25519_verify_msg(parsed->signature, parsed->sigLen,
                                 vcData, sigOffset,
                                 &verified, &peerKey);
    wc_ed25519_free(&peerKey);

    if (ret != 0) return ret;

    parsed->isValid = verified;

    if (!verified)
        return SIG_VERIFY_E;

    return 0;
}

int SSI_VC_GetPeerPubKey(const SSI_ParsedVC* parsed,
                         byte* pubKey, word32* pubKeyLen)
{
    if (parsed == NULL || pubKey == NULL || pubKeyLen == NULL)
        return BAD_FUNC_ARG;

    if (*pubKeyLen < parsed->pubKeyLen)
        return BUFFER_E;

    XMEMCPY(pubKey, parsed->pubKey, parsed->pubKeyLen);
    *pubKeyLen = parsed->pubKeyLen;
    return 0;
}

/* ==========================================================================
 * did_methods extension helpers
 * ==========================================================================
 */

int SSI_DIDMethods_Init(SSI_DIDMethods* dm)
{
    if (dm == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(dm, 0, sizeof(SSI_DIDMethods));

    /* Default: support did:key only */
    dm->methods[0] = SSI_DID_METHOD_KEY;
    dm->count = 1;
    return 0;
}

int SSI_DIDMethods_Serialize(const SSI_DIDMethods* dm,
                             byte* output, word32* outLen)
{
    /*
     * Wire format:
     *   [1B count][count bytes of method IDs]
     */
    if (dm == NULL || output == NULL || outLen == NULL)
        return BAD_FUNC_ARG;

    if (*outLen < (word32)(1 + dm->count))
        return BUFFER_E;

    output[0] = dm->count;
    XMEMCPY(output + 1, dm->methods, dm->count);
    *outLen = 1 + dm->count;
    return 0;
}

int SSI_DIDMethods_Parse(const byte* input, word32 inputLen,
                         SSI_DIDMethods* dm)
{
    if (input == NULL || dm == NULL || inputLen < 1)
        return BAD_FUNC_ARG;

    XMEMSET(dm, 0, sizeof(SSI_DIDMethods));

    dm->count = input[0];
    if (dm->count > 8 || (word32)(1 + dm->count) > inputLen)
        return BUFFER_ERROR;

    XMEMCPY(dm->methods, input + 1, dm->count);
    return 0;
}

#endif /* SSI_IDENTITY_IMPL */

#ifdef __cplusplus
}
#endif

#endif /* SSI_IDENTITY_H */
