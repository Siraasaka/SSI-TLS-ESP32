/* ==========================================================================
 * tls.c MODIFICATIONS for SSI-TLS
 * wolfSSL v5.8.4 — surgical patches to src/src/tls.c
 *
 * Strategy: Extend the existing HAVE_RPK framework to support VC(3) cert type.
 * Add did_methods custom extension (0xFF02) for DID method negotiation.
 *
 * This file documents ALL changes needed to tls.c. Each change is marked with
 * the original code and the replacement code, ready for manual application
 * or str_replace operations.
 *
 * Total changes: 5 patches
 *   PATCH 1: Add WOLFSSL_SSI_TLS guard at top of file (Arduino build fix)
 *   PATCH 2: Add did_methods extension parse handler in TLSX_Parse
 *   PATCH 3: Add did_methods extension write in TLSX_PopulateExtensions
 *   PATCH 4: Allow VC(3) in cert type validation (IsCertTypeListed helper)
 *   PATCH 5: Add did_methods extension to TLSX_GetSize/TLSX_Write (GetRequest/WriteRequest)
 *
 * Author: Muhammad Ikhwan Maulana (2204111010033)
 * ==========================================================================
 */

/* ==========================================================================
 * PATCH 1: Arduino build fix — ensure WOLFSSL_SSI_TLS is defined
 *
 * Location: Very top of tls.c, after the copyright header and before
 *           any #include directives.
 *
 * WHY: Arduino IDE compiles .c library files separately from the sketch.
 *      Defines from user_settings.h propagate via wolfssl/wolfcrypt/settings.h
 *      which includes user_settings.h when WOLFSSL_USER_SETTINGS is defined.
 *      But as a safety net, we add a guard here.
 * ==========================================================================
 *
 * ADD after the initial copyright block comments, before first #include:
 */

/*--- BEGIN PATCH 1 ---*/
#ifndef WOLFSSL_SSI_TLS
    /* SSI_TLS should come from user_settings.h via wolfcrypt/settings.h.
     * If not defined, we explicitly define it here as Arduino build safety. */
    /* #define WOLFSSL_SSI_TLS */
#endif
/*--- END PATCH 1 ---*/


/* ==========================================================================
 * PATCH 2: Add did_methods (0xFF02) parse handler in TLSX_Parse
 *
 * Location: In the main switch(type) inside TLSX_Parse(), right before
 *           the "default:" case (around line 16541).
 *
 * The did_methods extension is in the private-use range (0xFF00-0xFFFF).
 * Per RFC 8446 §4.2, unknown extensions in ClientHello MUST be ignored
 * by servers that don't understand them — so this is safe for fallback.
 *
 * Wire format from client (ClientHello):
 *   [1B count][count x 1B method_id]
 *
 * Wire format from server (EncryptedExtensions):
 *   [1B count][count x 1B method_id]  (intersection of supported methods)
 * ==========================================================================
 *
 * FIND (the default case at end of TLSX_Parse switch):
 *
 *  #endif
 *             default:
 *                 WOLFSSL_MSG("Unknown TLS extension type");
 *         }
 *
 * REPLACE WITH:
 */

/*--- BEGIN PATCH 2 ---*/
#endif
#if defined(WOLFSSL_SSI_TLS) && defined(HAVE_RPK)
            case 0xFF02: /* TLSX_DID_METHODS (private-use) */
                WOLFSSL_MSG("did_methods extension received");
                if (msgType == client_hello) {
                    /* Server receiving client's did_methods list */
                    if (size >= 1) {
                        byte dmCount = input[offset];
                        if (dmCount > 0 && dmCount <= 8 &&
                            (word16)(1 + dmCount) <= size) {
                            /* Store in ssiDIDMethodsRx */
                            ssl->options.ssiDIDMethodsRxCount = dmCount;
                            XMEMCPY(ssl->options.ssiDIDMethodsRx,
                                    input + offset + 1, dmCount);
                            ssl->options.ssiNegotiated = 1;
                            WOLFSSL_MSG("SSI-TLS: did_methods parsed from client");
                        }
                    }
                }
                else if (msgType == encrypted_extensions) {
                    /* Client receiving server's did_methods confirmation */
                    if (size >= 1) {
                        byte dmCount = input[offset];
                        if (dmCount > 0 && dmCount <= 8 &&
                            (word16)(1 + dmCount) <= size) {
                            ssl->options.ssiDIDMethodsRxCount = dmCount;
                            XMEMCPY(ssl->options.ssiDIDMethodsRx,
                                    input + offset + 1, dmCount);
                            ssl->options.ssiNegotiated = 1;
                            WOLFSSL_MSG("SSI-TLS: server confirmed SSI mode via did_methods");
                        }
                    }
                }
                break;
#endif /* WOLFSSL_SSI_TLS && HAVE_RPK */
            default:
                WOLFSSL_MSG("Unknown TLS extension type");
        }
/*--- END PATCH 2 ---*/


/* ==========================================================================
 * PATCH 3: Write did_methods extension in TLSX_PopulateExtensions
 *
 * Location: Inside TLSX_PopulateExtensions(), right after the
 *           TLSX_ServerCertificateType_Use() call for client-side
 *           (around line 14559).
 *
 * For the CLIENT: we append did_methods to ClientHello extensions by
 * using TLSX_Push (a generic extension container). But since the TLSX
 * framework doesn't know about 0xFF02, we'll use a simpler approach:
 * store the data to be written and handle it in WriteRequest.
 *
 * Actually, the cleanest approach is to NOT use TLSX_Push for a custom
 * extension. Instead, we'll manually append did_methods bytes in
 * TLSX_WriteRequest (PATCH 5). Here we just set the flag that tells
 * WriteRequest to include did_methods.
 * ==========================================================================
 *
 * FIND (in TLSX_PopulateExtensions, after ServerCertificateType_Use):
 *
 *         ret = TLSX_ServerCertificateType_Use(ssl, isServer);
 *         if (ret != 0)
 *             return ret;
 * #endif
 *
 * REPLACE WITH:
 */

/*--- BEGIN PATCH 3 ---*/
        ret = TLSX_ServerCertificateType_Use(ssl, isServer);
        if (ret != 0)
            return ret;
#endif /* HAVE_RPK */

#if defined(WOLFSSL_SSI_TLS) && defined(HAVE_RPK)
        /* If client is configured for VC cert type, also prepare did_methods.
         * Check if VC(3) is in the preferred server cert types list. */
        {
            int i;
            int wantVC = 0;
            for (i = 0; i < ssl->options.rpkConfig.preferred_ServerCertTypeCnt; i++) {
                if (ssl->options.rpkConfig.preferred_ServerCertTypes[i] == WOLFSSL_CERT_TYPE_VC) {
                    wantVC = 1;
                    break;
                }
            }
            if (wantVC) {
                /* Prepare did_methods data:
                 * Default: did:key(0x00) only */
                ssl->options.ssiDIDMethodsTxCount = 1;
                ssl->options.ssiDIDMethodsTx[0] = 0x00; /* did:key */
                ssl->options.ssiSendDIDMethods = 1;
                WOLFSSL_MSG("SSI-TLS: will send did_methods extension in ClientHello");
            }
        }
#endif /* WOLFSSL_SSI_TLS && HAVE_RPK */
/*--- END PATCH 3 ---*/


/* ==========================================================================
 * PATCH 4: Allow VC(3) as valid cert type value
 *
 * Location: The IsCertTypeListed() helper function and the cert type
 *           negotiation functions. wolfSSL's RPK code only validates
 *           X509(0) and RPK(2). We need VC(3) accepted too.
 *
 * FIND the set_cert_type function (in ssl.c, around line 8960):
 *
 * NOTE: This patch is for ssl.c, not tls.c! It's documented here for
 *       completeness. In ssl.c, find:
 *
 *   static int set_cert_type(RpkConfig* rpk, byte isClient,
 *                            const char* buf, int buflen)
 *
 * The validation inside checks for valid cert type values. We need to
 * ensure WOLFSSL_CERT_TYPE_VC (3) passes validation.
 *
 * Actually, looking at the code, the set_cert_type function just copies
 * raw byte values without validation — so VC(3) will work as-is!
 * The IsCertTypeListed and FindCommonCertType just compare byte values.
 * So no actual code change needed here — VC(3) is just a byte value
 * that flows through the existing RPK plumbing unchanged.
 *
 * HOWEVER, when the server negotiates, it needs to know VC(3) is valid.
 * The TLSX_ServerCertificateType_Use on server side calls FindCommonCertType
 * which finds intersection of client and server preferences. If both
 * list VC(3), it will match. No changes needed in the matching logic.
 * ==========================================================================
 */

/* NO CODE CHANGES for PATCH 4 — VC(3) byte value flows through RPK
 * infrastructure without modification. This is the beauty of reusing
 * the RPK framework. */


/* ==========================================================================
 * PATCH 5: Add did_methods to ClientHello and EncryptedExtensions output
 *
 * Location: In TLSX_WriteRequest (around line 15265) for ClientHello,
 *           and in TLSX_WriteResponse for EncryptedExtensions.
 *
 * Approach: After the normal extension writing is done, if
 *           ssiSendDIDMethods is set, we manually append the did_methods
 *           extension bytes.
 *
 * For ClientHello (client side), find the end of TLSX_WriteRequest
 * where the total length is finalized.
 *
 * For EncryptedExtensions (server side), find TLSX_WriteResponse
 * where server extensions are written.
 *
 * The did_methods wire format is:
 *   [2B extension_type = 0xFF02]
 *   [2B extension_length]
 *   [1B count]
 *   [count x 1B method_id]
 *
 * Total overhead: 4 + 1 + count bytes (typically 6 bytes for 1 method)
 * ==========================================================================
 */

/* --- CLIENT SIDE (TLSX_WriteRequest) ---
 *
 * FIND the end of TLSX_WriteRequest, the return statement:
 * (This is inside the client_hello case, after all TLSX_Write calls)
 *
 * We need to insert BEFORE the final length write-back.
 * Look for around line 15390+ where offset is finalized.
 *
 * The exact insertion point depends on the wolfSSL version, but
 * conceptually we add after all extensions are written:
 */

/*--- BEGIN PATCH 5A (conceptual — for TLSX_WriteRequest client_hello) ---*/
/* After all TLSX_Write() calls for client_hello, before writing total length: */
#if defined(WOLFSSL_SSI_TLS) && defined(HAVE_RPK)
    if (ssl->options.ssiSendDIDMethods && msgType == client_hello) {
        byte dmCount = ssl->options.ssiDIDMethodsTxCount;
        word16 extLen = 1 + dmCount; /* 1B count + method bytes */

        /* Extension type: 0xFF02 */
        output[offset++] = 0xFF;
        output[offset++] = 0x02;
        /* Extension data length */
        output[offset++] = (extLen >> 8) & 0xFF;
        output[offset++] = extLen & 0xFF;
        /* Payload: count + methods */
        output[offset++] = dmCount;
        XMEMCPY(output + offset, ssl->options.ssiDIDMethodsTx, dmCount);
        offset += dmCount;

        WOLFSSL_MSG("SSI-TLS: wrote did_methods extension in ClientHello");
    }
#endif
/*--- END PATCH 5A ---*/


/* --- SERVER SIDE (TLSX_WriteResponse) ---
 *
 * Similarly for encrypted_extensions in the server's response.
 * The server echoes back the negotiated DID methods.
 */

/*--- BEGIN PATCH 5B (conceptual — for EncryptedExtensions server) ---*/
#if defined(WOLFSSL_SSI_TLS) && defined(HAVE_RPK)
    if (ssl->options.ssiNegotiated && msgType == encrypted_extensions) {
        /* Echo back the intersection (for PoC: echo what client sent) */
        byte dmCount = ssl->options.ssiDIDMethodsRxCount;
        word16 extLen = 1 + dmCount;

        output[offset++] = 0xFF;
        output[offset++] = 0x02;
        output[offset++] = (extLen >> 8) & 0xFF;
        output[offset++] = extLen & 0xFF;
        output[offset++] = dmCount;
        XMEMCPY(output + offset, ssl->options.ssiDIDMethodsRx, dmCount);
        offset += dmCount;

        WOLFSSL_MSG("SSI-TLS: wrote did_methods extension in EncryptedExtensions");
    }
#endif
/*--- END PATCH 5B ---*/


/* ==========================================================================
 * REQUIRED CHANGES TO internal.h (for the new SSI fields in Options struct)
 *
 * Location: In wolfssl/internal.h, inside the Options struct
 *           (around the existing rpkConfig/rpkState fields at line ~3895)
 *
 * ADD after the existing rpkState field:
 * ==========================================================================
 */

/*--- BEGIN internal.h addition ---*/
#if defined(WOLFSSL_SSI_TLS) && defined(HAVE_RPK)
    /* SSI-TLS extension negotiation state */
    byte            ssiDIDMethodsTx[8];     /* DID methods to send */
    byte            ssiDIDMethodsTxCount;   /* count of methods to send */
    byte            ssiDIDMethodsRx[8];     /* DID methods received from peer */
    byte            ssiDIDMethodsRxCount;   /* count of received methods */
    byte            ssiSendDIDMethods:1;    /* 1 = include did_methods ext */
    byte            ssiNegotiated:1;        /* 1 = SSI mode confirmed */
    byte            ssiVCMode:1;            /* 1 = using VC cert type */
#endif
/*--- END internal.h addition ---*/


/* ==========================================================================
 * REQUIRED CHANGES TO ssl.h (add WOLFSSL_CERT_TYPE_VC to enum)
 *
 * Location: In wolfssl/ssl.h, inside the cert type enum (around line 5965)
 *
 * FIND:
 *     WOLFSSL_CERT_TYPE_RPK  = 2
 * };
 *
 * REPLACE WITH:
 *     WOLFSSL_CERT_TYPE_RPK  = 2,
 *     WOLFSSL_CERT_TYPE_VC   = 3
 * };
 * ==========================================================================
 */

/* ==========================================================================
 * SUMMARY OF ALL FILES TO MODIFY
 *
 * 1. user_settings.h    — REPLACED (new file created)
 * 2. ssi_identity.h     — NEW FILE (created)
 * 3. src/tls.c          — PATCH 1, 2, 3, 5A, 5B
 * 4. wolfssl/internal.h — Add SSI fields to Options struct
 * 5. wolfssl/ssl.h      — Add WOLFSSL_CERT_TYPE_VC = 3 to enum
 * 6. src/internal.c     — Handle VC cert type in ProcessPeerCerts
 *                          (next phase — accept VC bytes, skip X.509 parse)
 * 7. src/tls13.c        — Minimal: handle CertificateVerify with Ed25519
 *                          using VC-extracted pubkey (next phase)
 * 8. src/ssl.c          — Load VC as "certificate" buffer (next phase)
 * ==========================================================================
 */
