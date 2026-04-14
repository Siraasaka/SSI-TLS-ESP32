# SSI-TLS v2.0 — Clean Reimplementation

## Overview

Integrasi Self-Sovereign Identity (SSI) ke TLS 1.3 handshake pada ESP32 menggunakan wolfSSL v5.8.4.

**Perubahan fundamental dari v1:** Tidak ada custom message types (48/49/51). Semua message TLS 1.3 standar digunakan apa adanya. Kita "menumpang" di atas framework RPK (RFC 7250) yang sudah built-in di wolfSSL.

## Key Discovery

wolfSSL v5.8.4 sudah memiliki **`HAVE_RPK` framework** yang lengkap:
- `server_certificate_type` extension (ext ID 47) — RFC 7250
- `client_certificate_type` extension (ext ID 48) — RFC 7250  
- Enum: `WOLFSSL_CERT_TYPE_X509 = 0`, `WOLFSSL_CERT_TYPE_RPK = 2`
- Full parse/write/negotiate logic di `tls.c`
- Certificate message bypass untuk non-X.509 payload di `internal.c`

**Kita hanya perlu:**
1. Tambah `WOLFSSL_CERT_TYPE_VC = 3` ke enum
2. Enable `HAVE_RPK` di `user_settings.h`
3. Tambah `did_methods` custom extension (0xFF02) untuk DID method negotiation
4. Hook Certificate message processing untuk accept VC bytes

## Handshake Flow

```
Client → Server: ClientHello
                 + server_certificate_type = [VC(3), X509(0)]
                 + client_certificate_type = [VC(3), X509(0)]  
                 + did_methods = [KEY(0)]              ← ext 0xFF02

Server → Client: ServerHello
Server → Client: EncryptedExtensions
                 + server_certificate_type = VC(3)     ← confirmed
                 + did_methods = [KEY(0)]              ← echoed back
Server → Client: CertificateRequest
Server → Client: Certificate     ← carries VC bytes instead of X.509
Server → Client: CertificateVerify ← Ed25519 signature (= DIDVerify)
Server → Client: Finished

Client → Server: Certificate     ← client VC
Client → Server: CertificateVerify ← client Ed25519 sig
Client → Server: Finished
```

**Fallback:** Jika client tidak kirim `server_certificate_type` (wolfSSL original), server fallback ke TLS 1.3 normal. Zero breaking change.

## Files in This Package

### Modified from wolfSSL v5.8.4 original:

| File | Location in Arduino library | Changes |
|------|---------------------------|---------|
| `user_settings.h` | `wolfssl/src/` | REPLACED — adds WOLFSSL_SSI_TLS, HAVE_RPK, HAVE_ED25519 |
| `ssl.h` | `wolfssl/src/wolfssl/` | 1 line: add WOLFSSL_CERT_TYPE_VC = 3 |
| `internal.h` | `wolfssl/src/wolfssl/` | ~10 lines: add SSI fields to Options struct |
| `tls.c` | `wolfssl/src/src/` | ~100 lines: did_methods ext parse/write/size |

### New files:

| File | Location | Purpose |
|------|----------|---------|
| `ssi_identity.h` | `wolfssl/src/` | DID:key, VC creation, Ed25519 sign/verify |

### Reference (not a code file):

| File | Purpose |
|------|---------|
| `tls_c_patches.c` | Documents all tls.c patches with context |

## Installation Steps

1. **Backup** original wolfSSL Arduino library
2. **Replace** `wolfssl/src/user_settings.h` with new version
3. **Copy** `ssi_identity.h` to `wolfssl/src/`
4. **Replace** `wolfssl/src/wolfssl/ssl.h` with patched version
5. **Replace** `wolfssl/src/wolfssl/internal.h` with patched version
6. **Replace** `wolfssl/src/src/tls.c` with patched version
7. **Delete Arduino cache**: `C:\Users\Ikhwan\AppData\Local\Temp\arduino\*`
8. Compile — should build clean with HAVE_RPK + WOLFSSL_SSI_TLS

## Phase Status

### ✅ Phase 1 (this package):
- `user_settings.h` — complete
- `ssi_identity.h` — complete  
- `ssl.h` patch — complete (WOLFSSL_CERT_TYPE_VC)
- `internal.h` patch — complete (SSI fields in Options)
- `tls.c` patches — complete (did_methods extension)

### 🔜 Phase 2 (next):
- `internal.c` — bypass X.509 parse when cert_type == VC(3), accept raw VC bytes
- `ssl.c` — load VC buffer as "certificate", set up verify callback
- `tls13.c` — extract Ed25519 pubkey from VC for CertificateVerify validation

### 🔜 Phase 3 (next):
- Arduino sketches (server + client)
- Benchmark harness
- Baseline comparison

## Architecture Notes

### Why RPK framework works for us:

RPK (RFC 7250) replaces X.509 certificates with raw SubjectPublicKeyInfo in the Certificate message. The framework negotiates cert type via extensions and bypasses X.509 parsing when RPK is selected.

VC is conceptually similar: instead of X.509, we put VC bytes in the Certificate message. The key difference is that VC contains more than just a public key — it also has DID, claims, and a signature. But from wolfSSL's perspective, it's just "non-X.509 bytes in the Certificate message," which the RPK framework already handles.

### did_methods extension (0xFF02):

Per IETF draft-vesco-vcauthtls-01, the SSI handshake needs a way to negotiate DID methods. We use a private-use extension type (0xFF02) that:
- Client sends in ClientHello: list of supported DID methods
- Server echoes in EncryptedExtensions: selected DID method(s)
- Unknown extensions in ClientHello are ignored per RFC 8446 §4.2 → safe fallback

Wire format: `[1B count][count × 1B method_id]`
Currently: `[0x01][0x00]` = 1 method, did:key

### SSI negotiation state machine:

1. Client sets preferred cert types via `wolfSSL_set_server_cert_type(ssl, types, len)` including VC(3)
2. wolfSSL RPK framework sends `server_certificate_type = [VC, X509]` in ClientHello
3. Our code detects VC in preferences → also sends `did_methods` extension
4. Server parses both → if it supports VC and did:key, selects VC(3)
5. Server echoes `server_certificate_type = VC` + `did_methods` in EncryptedExtensions
6. Client parses → sets `ssiNegotiated = 1`
7. Certificate message carries VC bytes (Phase 2 hook)
8. CertificateVerify uses Ed25519 key from VC (Phase 2 hook)
