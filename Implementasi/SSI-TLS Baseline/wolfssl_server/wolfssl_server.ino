/* wolfssl_server.ino
 *
 * ESP32 sebagai TLS 1.3 Server dengan SSI Authentication
 *
 * Penulis  : Muhammad Ikhwan Maulana (2204111010033)
 * Instansi : Universitas Syiah Kuala
 * Konteks  : Skripsi -- Integrasi SSI ke TLS 1.3 di IoT resource-constrained
 *
 * Deskripsi:
 *   ESP32 ini bertindak sebagai TLS 1.3 server yang menerima koneksi dari
 *   ESP32 client. Autentikasi mutual menggunakan Verifiable Credential (VC)
 *   berbasis DID:key + Ed25519, menggantikan X.509 sepenuhnya.
 *
 * Referensi:
 *   Perugini & Vesco (2024), Elsevier Internet of Things
 *
 * Hardware:
 *   - ESP32 DevKit V1
 *   - Terhubung ke WiFi yang sama dengan ESP32 client
 *
 * Cara pakai:
 *   1. Isi WIFI_SSID dan WIFI_PASSWORD sesuai jaringan kamu
 *   2. Upload ke ESP32 yang akan jadi server
 *   3. Catat IP address yang muncul di Serial Monitor
 *   4. Masukkan IP itu ke wolfssl_client.ino
 */

/* Definisikan role sebelum include wolfssl --
 * ini memberitahu user_settings.h untuk tidak disable server code */
#define WOLFSSL_SERVER_EXAMPLE

#include <WiFi.h>
#include <wolfssl.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <ssi_identity.h>

/* ==========================================================================
 * KONFIGURASI -- EDIT BAGIAN INI
 * ========================================================================== */

#define WIFI_SSID       "Tahu"
#define WIFI_PASSWORD   "merekatahu"

/* Port TLS server */
#define TLS_PORT        11111

/* Nama perangkat ini (untuk VC payload) */
#define DEVICE_NAME     "ESP32-SSI-Server-01"
#define DEVICE_CLAIMS   "role=server,type=iot"

/* Timeout koneksi dalam milidetik */
#define CONNECT_TIMEOUT_MS  10000
#define HANDSHAKE_TIMEOUT_MS 5000

/* ==========================================================================
 * VARIABEL GLOBAL
 * ========================================================================== */

WiFiServer tcpServer(TLS_PORT);
WOLFSSL_CTX* ctx   = NULL;
WOLFSSL*     ssl   = NULL;

/* VC perangkat ini -- dibuat sekali saat setup, dikirim ke client */
SSI_VC g_server_vc;

/* Flag untuk benchmark */
unsigned long g_handshake_start_ms = 0;
unsigned long g_handshake_end_ms   = 0;

/* ==========================================================================
 * FUNGSI BANTU
 * ========================================================================== */

/* Cetak error wolfSSL ke Serial */
static void print_wolfssl_error(const char* msg, int err)
{
    char errBuf[80];
    wolfSSL_ERR_error_string(err, errBuf);
    Serial.print("[ERR] ");
    Serial.print(msg);
    Serial.print(": ");
    Serial.println(errBuf);
}

/* Sambung ke WiFi dengan timeout */
static bool wifi_connect(void)
{
    unsigned long start = millis();
    Serial.print("[WiFi] Menghubungkan ke ");
    Serial.print(WIFI_SSID);

    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    while (WiFi.status() != WL_CONNECTED) {
        if (millis() - start > CONNECT_TIMEOUT_MS) {
            Serial.println("\n[WiFi] TIMEOUT!");
            return false;
        }
        delay(500);
        Serial.print(".");
    }

    Serial.println("\n[WiFi] Terhubung!");
    Serial.print("[WiFi] IP Address: ");
    Serial.println(WiFi.localIP());
    Serial.print("[WiFi] MASUKKAN IP INI KE wolfssl_client.ino: ");
    Serial.println(WiFi.localIP());
    return true;
}

/* Setup wolfSSL context untuk TLS 1.3 server dengan SSI */
static bool setup_wolfssl_ctx(void)
{
    int ret;

    wolfSSL_Init();

    /* Gunakan TLS 1.3 only -- tidak fallback ke versi lama */
    WOLFSSL_METHOD* method = wolfTLSv1_3_server_method();
    if (method == NULL) {
        Serial.println("[ERR] Gagal buat TLS 1.3 server method");
        return false;
    }

    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        Serial.println("[ERR] Gagal buat wolfSSL CTX");
        return false;
    }

    /* ===================================================================
     * SSI-TLS: Nonaktifkan verifikasi X.509 sepenuhnya
     *
     * Kita tidak pakai X.509 sama sekali -- identitas diverifikasi
     * lewat VC/DID:key di lapisan aplikasi (setelah handshake).
     * Patch di internal.c sudah bypass cert/key check wolfSSL,
     * jadi server bisa accept handshake tanpa certificate buffer.
     *
     * Catatan: WOLFSSL_CERT_TYPE_RPK dan wolfSSL_CTX_set_server_cert_type
     * tidak tersedia di wolfSSL Arduino v5.8.4 meski WOLFSSL_RPK di-define.
     * Fungsi-fungsi itu ada di header tapi belum di-expose di build ini.
     * =================================================================== */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);

    /* ===================================================================
     * Load Ed25519 private key ke CTX
     *
     * Dibutuhkan wolfSSL untuk sign CertificateVerify di TLS 1.3.
     * Ini bagian sah protokol TLS 1.3 -- server harus prove kepemilikan
     * private key. Key di-export ke DER dari g_ssi_keypair di ssi_identity.h
     * =================================================================== */
    int keyRet = ssi_load_key_to_ctx(ctx);
    if (keyRet != SSI_OK) {
        Serial.print("[ERR] Gagal load Ed25519 key ke CTX: ");
        Serial.println(keyRet);
        return false;
    }
     /*
     * Di wolfSSL Arduino, callback HARUS di-set lewat CTX
     * (wolfSSL_CTX_SetIORecv), bukan per-SSL object (wolfSSL_SetIORecv).
     * Context pointer (WiFiClient*) di-set per-SSL lewat SetIOReadCtx
     * di dalam loop() saat ada koneksi masuk.
     * =================================================================== */
    wolfSSL_CTX_SetIORecv(ctx, [](WOLFSSL* ssl, char* buf, int sz, void* ctx) -> int {
        WiFiClient* client = (WiFiClient*)ctx;
        if (!client || !client->connected()) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        unsigned long start = millis();
        while (client->available() < 1) {
            if (millis() - start > 5000) return WOLFSSL_CBIO_ERR_TIMEOUT;
            delay(1);
        }
        return (int)client->read((uint8_t*)buf, sz);
    });

    wolfSSL_CTX_SetIOSend(ctx, [](WOLFSSL* ssl, char* buf, int sz, void* ctx) -> int {
        WiFiClient* client = (WiFiClient*)ctx;
        if (!client || !client->connected()) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        return (int)client->write((uint8_t*)buf, sz);
    });

    Serial.println("[TLS] wolfSSL CTX siap (TLS 1.3, SSI mode)");
    return true;
}

/* ==========================================================================
 * SETUP
 * ========================================================================== */

void setup(void)
{
    Serial.begin(115200);
    delay(1000);
    Serial.println("\n\n=== ESP32 SSI-TLS Server ===");
    Serial.println("Muhammad Ikhwan Maulana, 2204111010033");
    Serial.println("Universitas Syiah Kuala");
    Serial.println("============================\n");

    /* --- Langkah 1: Inisialisasi SSI identity --- */
    Serial.println("[SSI] Menginisialisasi identitas...");
    int ssiRet = ssi_init();
    if (ssiRet != SSI_OK) {
        Serial.print("[ERR] ssi_init() gagal: ");
        Serial.println(ssiRet);
        while (1) delay(1000); /* halt */
    }
    ssi_print_identity();

    /* Buat VC untuk perangkat ini */
    ssiRet = ssi_create_vc(&g_server_vc, DEVICE_NAME, DEVICE_CLAIMS);
    if (ssiRet != SSI_OK) {
        Serial.print("[ERR] ssi_create_vc() gagal: ");
        Serial.println(ssiRet);
        while (1) delay(1000);
    }
    Serial.println("[SSI] VC server berhasil dibuat");

    /* --- Langkah 2: Sambung WiFi --- */
    if (!wifi_connect()) {
        while (1) delay(1000);
    }

    /* --- Langkah 3: Setup wolfSSL --- */
    if (!setup_wolfssl_ctx()) {
        while (1) delay(1000);
    }

    /* --- Langkah 4: Start TCP server --- */
    tcpServer.begin();
    Serial.print("[Server] Listening di port ");
    Serial.println(TLS_PORT);
    Serial.println("[Server] Menunggu koneksi dari client...");
    Serial.println("[Server] Pastikan client pakai IP: " + WiFi.localIP().toString());
}

/* ==========================================================================
 * LOOP UTAMA
 * ========================================================================== */

void loop(void)
{
    /* Cek apakah ada client yang connect */
    WiFiClient tcpClient = tcpServer.available();
    if (!tcpClient) {
        delay(10);
        return;
    }

    Serial.println("\n[Server] Client terhubung!");
    Serial.print("[Server] IP client: ");
    Serial.println(tcpClient.remoteIP());

    /* ===================================================================
     * Buat SSL object untuk koneksi ini
     * =================================================================== */
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        Serial.println("[ERR] Gagal buat wolfSSL object");
        tcpClient.stop();
        return;
    }

    /* Hubungkan context WiFiClient ke SSL object ini --
     * callback sudah di-set di CTX saat setup, context pointer
     * di-set di sini per-koneksi */
    wolfSSL_SetIOReadCtx(ssl,  &tcpClient);
    wolfSSL_SetIOWriteCtx(ssl, &tcpClient);

    /* ===================================================================
     * TLS 1.3 Handshake
     *
     * Ini adalah momen kunci -- di sinilah SSI extensions yang kita
     * inject di tls.c akan dikirim ke client.
     *
     * Urutan handshake TLS 1.3:
     *   Client → Server : ClientHello (+ SSI extensions kita)
     *   Server → Client : ServerHello + EncryptedExtensions (+ SSI ext)
     *                   + Certificate + CertificateVerify + Finished
     *   Client → Server : Certificate + CertificateVerify + Finished
     *   [Handshake selesai -- koneksi terenkripsi]
     * =================================================================== */
    Serial.println("[TLS] Memulai handshake...");
    g_handshake_start_ms = millis();

    int ret = wolfSSL_accept(ssl); /* server "accept" koneksi TLS */

    g_handshake_end_ms = millis();
    unsigned long handshake_ms = g_handshake_end_ms - g_handshake_start_ms;

    if (ret != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, ret);
        print_wolfssl_error("Handshake gagal", err);
        wolfSSL_free(ssl);
        ssl = NULL;
        tcpClient.stop();
        return;
    }

    /* ===================================================================
     * Handshake berhasil! Cetak info koneksi
     * =================================================================== */
    Serial.println("[TLS] Handshake BERHASIL!");
    Serial.print("[TLS] Waktu handshake: ");
    Serial.print(handshake_ms);
    Serial.println(" ms");
    Serial.print("[TLS] Cipher suite: ");
    Serial.println(wolfSSL_get_cipher_name(ssl));
    Serial.print("[TLS] Versi TLS: ");
    Serial.println(wolfSSL_get_version(ssl));

    /* ===================================================================
     * Exchange VC setelah TLS handshake
     *
     * Setelah handshake selesai, koneksi sudah terenkripsi.
     * Kita exchange VC lewat TLS record untuk mutual authentication
     * di lapisan aplikasi.
     *
     * Protokol exchange:
     *   Server → Client : kirim VC server (serialized, 4 byte prefix panjang)
     *   Client → Server : kirim VC client
     *   Server          : verifikasi VC client
     * =================================================================== */
    Serial.println("[SSI] Memulai VC exchange...");

    /* Serialize VC server */
    byte vcBuf[SSI_VC_MAX_LEN + 10];
    int vcLen = ssi_vc_serialize(vcBuf + 4, sizeof(vcBuf) - 4,
                                 &g_server_vc, ssi_get_pubkey());
    if (vcLen < 0) {
        Serial.println("[ERR] Gagal serialize VC server");
        wolfSSL_free(ssl);
        ssl = NULL;
        tcpClient.stop();
        return;
    }

    /* 4 byte header: panjang VC (big-endian 32bit) */
    vcBuf[0] = (byte)(vcLen >> 24);
    vcBuf[1] = (byte)(vcLen >> 16);
    vcBuf[2] = (byte)(vcLen >>  8);
    vcBuf[3] = (byte)(vcLen & 0xFF);

    /* Kirim VC server ke client */
    ret = wolfSSL_write(ssl, vcBuf, vcLen + 4);
    if (ret <= 0) {
        int err = wolfSSL_get_error(ssl, ret);
        print_wolfssl_error("Gagal kirim VC server", err);
        wolfSSL_free(ssl);
        ssl = NULL;
        tcpClient.stop();
        return;
    }
    Serial.println("[SSI] VC server berhasil dikirim ke client");

    /* Terima VC dari client */
    byte clientVcBuf[SSI_VC_MAX_LEN + 10];
    byte header[4];

    /* Baca 4 byte header dulu */
    ret = wolfSSL_read(ssl, header, 4);
    if (ret != 4) {
        Serial.println("[ERR] Gagal baca header VC client");
        wolfSSL_free(ssl);
        ssl = NULL;
        tcpClient.stop();
        return;
    }

    word32 clientVcLen = ((word32)header[0] << 24) |
                         ((word32)header[1] << 16) |
                         ((word32)header[2] <<  8) |
                         (word32)header[3];

    if (clientVcLen > sizeof(clientVcBuf)) {
        Serial.println("[ERR] VC client terlalu besar");
        wolfSSL_free(ssl);
        ssl = NULL;
        tcpClient.stop();
        return;
    }

    /* Baca VC client */
    ret = wolfSSL_read(ssl, clientVcBuf, (int)clientVcLen);
    if (ret != (int)clientVcLen) {
        Serial.println("[ERR] Gagal baca VC client");
        wolfSSL_free(ssl);
        ssl = NULL;
        tcpClient.stop();
        return;
    }
    Serial.println("[SSI] VC client diterima");

    /* Deserialize dan verifikasi VC client */
    SSI_VC clientVC;
    byte clientPubKey[SSI_ED25519_PUBKEY_SIZE];

    int desRet = ssi_vc_deserialize(&clientVC, clientPubKey,
                                    clientVcBuf, clientVcLen);
    if (desRet != SSI_OK) {
        Serial.println("[ERR] Gagal deserialize VC client");
        wolfSSL_free(ssl);
        ssl = NULL;
        tcpClient.stop();
        return;
    }

    int verRet = ssi_verify_vc(&clientVC, clientPubKey);
    if (verRet != SSI_OK) {
        Serial.println("[ERR] Verifikasi VC client GAGAL -- koneksi ditolak!");
        /* Kirim notifikasi penolakan */
        const char* reject = "SSI_REJECT";
        wolfSSL_write(ssl, reject, strlen(reject));
        wolfSSL_free(ssl);
        ssl = NULL;
        tcpClient.stop();
        return;
    }

    Serial.println("[SSI] VC client VALID -- identitas terverifikasi!");
    Serial.print("[SSI] Payload client: ");
    Serial.println((char*)clientVC.payload);

    /* Kirim konfirmasi ke client */
    const char* ack = "SSI_OK";
    wolfSSL_write(ssl, ack, strlen(ack));

    /* ===================================================================
     * Koneksi SSI-TLS berhasil -- bisa mulai exchange data
     * =================================================================== */
    Serial.println("\n[Server] === KONEKSI SSI-TLS BERHASIL ===");
    Serial.print("[Server] Handshake time : ");
    Serial.print(handshake_ms);
    Serial.println(" ms");
    Serial.println("[Server] Mutual auth   : PASSED (via VC/DID:key)");
    Serial.println("[Server] Enkripsi      : TLS_AES_256_GCM_SHA384");

    /* Loop baca-tulis sederhana untuk verifikasi koneksi */
    Serial.println("[Server] Menunggu pesan dari client...");
    unsigned long loopStart = millis();
    while (tcpClient.connected() && millis() - loopStart < 10000) {
        byte recvBuf[128];
        int bytes = wolfSSL_read(ssl, recvBuf, sizeof(recvBuf) - 1);
        if (bytes > 0) {
            recvBuf[bytes] = '\0';
            Serial.print("[Server] Pesan dari client: ");
            Serial.println((char*)recvBuf);

            /* Echo balik */
            char reply[150];
            snprintf(reply, sizeof(reply), "SERVER_ACK: %s", (char*)recvBuf);
            wolfSSL_write(ssl, reply, strlen(reply));
            break;
        }
        delay(10);
    }

    /* Bersih-bersih */
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    ssl = NULL;
    tcpClient.stop();

    Serial.println("[Server] Koneksi ditutup. Siap menerima koneksi berikutnya.");
    Serial.println("[Server] ----------------------------------------");
}
