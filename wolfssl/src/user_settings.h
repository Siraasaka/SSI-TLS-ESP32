/* examples/configs/user_settings_arduino.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* ==========================================================================
 * SSI-TLS 1.3 user_settings.h for ESP32 + wolfSSL v5.8.4
 * Based on: Perugini & Vesco (2024), IETF draft-vesco-vcauthtls-01
 * Strategy: Reuse wolfSSL's existing HAVE_RPK framework (RFC 7250) to
 *           carry VC(3) as a new certificate type alongside X509(0).
 *           No custom message types. No state machine hacks.
 * Modified by: Muhammad Ikhwan Maulana (2204111010033) - Universitas Syiah Kuala
 * ==========================================================================
 */

/* This is a sample Arduino user_settings.h for wolfSSL */

/* Display user settings version in example code: */
#define WOLFSSL_USER_SETTINGS_ID "SSI-TLS v2.0 Arduino user_settings.h (wolfSSL v5.8.4)"

/* ==========================================================================
 * SECTION 1: SSI-TLS specific defines
 * ==========================================================================
 */

/* Master SSI-TLS feature flag.
 * Enables VC cert type (3), did_methods extension, and VC processing hooks.
 * When undefined, the library behaves as stock wolfSSL + HAVE_RPK. */
#define WOLFSSL_SSI_TLS

/* Enable RPK framework — this gives us server_certificate_type (ext 47)
 * and client_certificate_type (ext 48) extensions for FREE.
 * We piggyback VC(3) as a new cert type value in this framework. */
#define HAVE_RPK

/* Ed25519 for DID:key signatures and CertificateVerify */
#define HAVE_ED25519
#define HAVE_ED25519_SIGN
#define HAVE_ED25519_VERIFY
#define HAVE_ED25519_KEY_IMPORT
#define HAVE_ED25519_KEY_EXPORT
#define ED25519_SMALL  /* reduce code size for ESP32 */

/* Curve25519 — required by Ed25519 internally */
#define HAVE_CURVE25519

/* SHA-512 — required by Ed25519 (Ed25519 uses SHA-512 internally) */
#define WOLFSSL_SHA512

/* DH — disable to save memory. TLS 1.3 uses ECDHE, not FFDHE on ESP32.
 * HAVE_FFDHE_2048 is needed to avoid the compile error but DH is disabled. */
#define NO_DH
#define HAVE_FFDHE_2048

/* Disable DSA — not needed */
#define NO_DSA

/* AES-GCM — CRITICAL for TLS 1.3 cipher suites */
#define HAVE_AESGCM
#define WOLFSSL_AES_128
#define WOLFSSL_AES_256

/* Math library */
#define USE_FAST_MATH

/* Single threaded — Arduino is single-threaded */
#define SINGLE_THREADED

/* Low memory optimizations for ESP32 */
#define WOLFSSL_LOW_MEMORY

/* Disable ASN time/date checks — ESP32 has no RTC, time starts at 1970
 * after boot. wolfSSL test certs have validity dates in 2023+ which
 * would fail validation. Not needed for SSI-TLS (VC has no dates). */
#define NO_ASN_TIME

/* Enable loading raw key buffers (for VC bytes and Ed25519 keys) */
#define USE_CERT_BUFFERS_256

/* Allow verify callback override — lets us skip X.509 chain validation
 * and do VC verification in our own callback instead */
#define WOLFSSL_ALWAYS_VERIFY_CB

/* Allow peer cert to be accessed after handshake for inspection */
#define KEEP_PEER_CERT

/* Debug — COMMENT OUT for production/benchmarking */
#define DEBUG_WOLFSSL

/* ==========================================================================
 * SECTION 2: Standard wolfSSL security hardening
 * ==========================================================================
 */

/* Disable wolfcrypt cryptographic security hardening. Comment out to enable: */
/* #define WC_NO_HARDEN */

/* Instead, we harden ECC and RSA */
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* Due to limited build control, we'll ignore file warnings. */
/* See https://github.com/arduino/arduino-cli/issues/631     */
#undef  WOLFSSL_IGNORE_FILE_WARN
#define WOLFSSL_IGNORE_FILE_WARN

#define NO_FILESYSTEM

/* Make sure this is not an ESP-IDF file */
#undef  WOLFSSL_ESPIDF

#define HAVE_ECC

#define WOLFSSL_SMALL_STACK
#define MICRO_SESSION_CACHE

/* RSA — needed for fallback X.509 scenarios */
#define RSA_LOW_MEM

#define NO_OLD_TLS

/* ==========================================================================
 * SECTION 3: Platform-specific configuration (ESP32)
 * ==========================================================================
 */

/* To see board properties & definitions:
 * arduino-cli compile --fqbn [] --show-properties ./sketches/wolfssl_client */

#if defined(ARDUINO_AVR_ETHERNET)
    #define WOLFSSL_NO_TLS13
    #define WOLFSSL_MIN_CONFIG
    #define WOLFSSL_USER_IO
    #define WOLFSSL_NO_WRITEV
    #define NO_FILESYSTEM
    #define WOLFSSL_NO_CERTS
    #define HAVE_TLS
    #define NO_RC4
    #define NO_PSK
    #define NO_SESSION_CACHE
    #define NO_CERT_VERIFY
    #define NO_MAIN_DRIVER
    #define WOLFSSL_NO_SP
    #define WOLFSSL_NO_SIG_WRAPPER
    #define TFM_TIMING_RESISTANT
    #undef WOLFSSL_DTLS
    #undef WOLFSSL_DTLS13
#endif

#if defined(ARDUINO_AVR_LEONARDO_ETH)
    #undef  WOLFSSL_NO_TLS13
    #define WOLFSSL_NO_TLS13
    #define NO_TLS
    #undef  WOLFSSL_TLS13
    #define WOLFSSL_NO_TLS12
#endif

#if defined(ESP8266) || defined(__SAM3X8E__) || \
    defined(ARDUINO_AVR_ETHERNET) || defined(ARDUINO_AVR_LEONARDO_ETH)
    #define WOLFSSL_NO_SOCK
    #undef HAVE_SUPPORTED_CURVES
    /* AVR & small boards: no DTLS */
    #undef  WOLFSSL_DTLS
    #undef  WOLFSSL_DTLS13
#elif defined(ESP32)  || \
    defined(WIFI_101) || defined(WIFI_NINA) || defined(WIFIESPAT) || \
    defined(ETHERNET_H) || defined(ARDUINO_TEENSY41) || \
    defined(ARDUINO_SAMD_MKR1000)

    #define USE_CERT_BUFFERS_2048

    /* Board has networking — enable TLS / DTLS */

    #define HAVE_TLS_EXTENSIONS
    #define HAVE_SUPPORTED_CURVES

    /* Enable TLS 1.3 */
    #define WOLFSSL_TLS13
    #if defined(WOLFSSL_TLS13)
        #define HAVE_TLS_EXTENSIONS
        #define WC_RSA_PSS
        #define HAVE_HKDF
        #define HAVE_AEAD
    #endif

    /* Disable DTLS — not needed for SSI-TLS PoC, saves RAM */
    #undef WOLFSSL_DTLS
    #undef WOLFSSL_DTLS13

#elif defined (__AVR__) || defined(__AVR_ARCH__) || defined(__MEGAAVR__)
    #define WC_16BIT_CPU
    #define NO_TLS
#elif (defined(__SAMD21__) || defined(__SAMD51__)) && defined(ARDUINO_SAMD_ZERO)
    /* No networking on ARDUINO_SAMD_ZERO */
#elif defined(ARDUINO_TEENSY40)
    /* No networking on TEENSY boards */
#else
    /* other / unknown board */
    #define USE_CERT_BUFFERS_1024
#endif

/* Cannot use WOLFSSL_NO_MALLOC with small stack */
/* #define WOLFSSL_NO_MALLOC */

/* ==========================================================================
 * SECTION 4: ESP32 hardware-specific settings
 * ==========================================================================
 */

/* Platform features — ESP32 check */
#if defined(WOLFSSL_ESP32) || defined(WOLFSSL_ESPWROOM32SE)
    #define ESP32_USE_RSA_PRIMITIVE
    #if defined(CONFIG_IDF_TARGET_ESP32)
        /* ESP32 HW Acceleration */
    #endif
#endif

#if defined(CONFIG_IDF_TARGET_ESP32)
    /* wolfSSL HW Acceleration supported on ESP32. Uncomment to disable: */
    /*  #define NO_ESP32_CRYPT                 */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_HASH    */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_AES     */
    /*  #define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI */
    #define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA224 /* no SHA224 HW on ESP32  */
#elif defined(CONFIG_IDF_TARGET_ESP32S2)
    /* ESP32-S2 HW Acceleration */
#elif defined(CONFIG_IDF_TARGET_ESP32S3)
    /* ESP32-S3 HW Acceleration */
#elif defined(CONFIG_IDF_TARGET_ESP32C2) || \
      defined(CONFIG_IDF_TARGET_ESP8684)
    /* ESP32-C2 */
#elif defined(CONFIG_IDF_TARGET_ESP32C3)
    /* ESP32-C3 */
#elif defined(CONFIG_IDF_TARGET_ESP32C6)
    /* ESP32-C6 */
#elif defined(CONFIG_IDF_TARGET_ESP32H2)
    /* ESP32-H2 */
#endif

/* ==========================================================================
 * SECTION 5: Baseline test mode
 * When WOLFSSL_BASELINE_TEST is defined, SSI features are disabled but we
 * still use this modified user_settings.h. This lets us benchmark "modified
 * library, standard TLS" vs "modified library, SSI-TLS".
 * ==========================================================================
 */
#ifdef WOLFSSL_BASELINE_TEST
    #undef  WOLFSSL_SSI_TLS
    /* Keep HAVE_RPK enabled since it's part of the modified library */
    /* Keep HAVE_ED25519 for fair comparison */
#endif

/* ==========================================================================
 * SECTION 6: Sanity checks
 * ==========================================================================
 */

/* Certificate buffer macros for baseline mTLS examples
 * These map to the built-in test certs in wolfssl/certs_test.h */
#if defined(USE_CERT_BUFFERS_2048)
    #include <wolfssl/certs_test.h>
    #define CTX_CA_CERT          ca_cert_der_2048
    #define CTX_CA_CERT_SIZE     sizeof_ca_cert_der_2048
    #define CTX_CA_CERT_TYPE     WOLFSSL_FILETYPE_ASN1

    #define CTX_SERVER_CERT      server_cert_der_2048
    #define CTX_SERVER_CERT_SIZE sizeof_server_cert_der_2048
    #define CTX_SERVER_CERT_TYPE WOLFSSL_FILETYPE_ASN1
    #define CTX_SERVER_KEY       server_key_der_2048
    #define CTX_SERVER_KEY_SIZE  sizeof_server_key_der_2048
    #define CTX_SERVER_KEY_TYPE  WOLFSSL_FILETYPE_ASN1

    #define CTX_CLIENT_CERT      client_cert_der_2048
    #define CTX_CLIENT_CERT_SIZE sizeof_client_cert_der_2048
    #define CTX_CLIENT_CERT_TYPE WOLFSSL_FILETYPE_ASN1
    #define CTX_CLIENT_KEY       client_key_der_2048
    #define CTX_CLIENT_KEY_SIZE  sizeof_client_key_der_2048
    #define CTX_CLIENT_KEY_TYPE  WOLFSSL_FILETYPE_ASN1
#endif

/* SSI-TLS requires TLS 1.3 */
#if defined(WOLFSSL_SSI_TLS) && !defined(WOLFSSL_TLS13)
    #error "WOLFSSL_SSI_TLS requires WOLFSSL_TLS13"
#endif

/* SSI-TLS requires RPK framework (for cert type extensions) */
#if defined(WOLFSSL_SSI_TLS) && !defined(HAVE_RPK)
    #error "WOLFSSL_SSI_TLS requires HAVE_RPK"
#endif

/* SSI-TLS requires Ed25519 (for DID:key signatures) */
#if defined(WOLFSSL_SSI_TLS) && !defined(HAVE_ED25519)
    #error "WOLFSSL_SSI_TLS requires HAVE_ED25519"
#endif

/* TLS extensions required */
#if defined(HAVE_RPK) && !defined(HAVE_TLS_EXTENSIONS)
    #error "HAVE_RPK requires HAVE_TLS_EXTENSIONS"
#endif
