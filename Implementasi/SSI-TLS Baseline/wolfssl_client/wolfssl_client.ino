/* wolfssl_client.ino
 *
 * ESP32 sebagai TLS 1.3 Client dengan SSI Authentication
 *
 * Penulis  : Muhammad Ikhwan Maulana (2204111010033)
 * Instansi : Universitas Syiah Kuala
 * Konteks  : Skripsi -- Integrasi SSI ke TLS 1.3 di IoT resource-constrained
 *
 * Deskripsi:
 *   ESP32 ini connect ke ESP32 server dan melakukan mutual authentication
 *   menggunakan Verifiable Credential berbasis DID:key + Ed25519.
 *
 * Cara pakai:
 *   1. Upload wolfssl_server.ino ke ESP32 pertama, catat IP-nya
 *   2. Isi SERVER_IP di bawah dengan IP server tersebut
 *   3. Isi WIFI_SSID dan WIFI_PASSWORD
 *   4. Upload sketch ini ke ESP32 kedua
 */

#define WOLFSSL_CLIENT_EXAMPLE

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

/* IP address ESP32 server -- lihat Serial Monitor server */
#define SERVER_IP       "10.138.2.181"
#define SERVER_PORT     11111

/* Nama perangkat ini */
#define DEVICE_NAME     "ESP32-SSI-Client-01"
#define DEVICE_CLAIMS   "role=client,type=iot"

/* Jumlah percobaan handshake untuk benchmark */
#define BENCHMARK_ROUNDS  10

/* ==========================================================================
 * VARIABEL GLOBAL
 * ========================================================================== */

WOLFSSL_CTX* ctx = NULL;

/* VC perangkat ini */
SSI_VC g_client_vc;

/* Hasil benchmark */
struct {
    unsigned long times[BENCHMARK_ROUNDS];
    int count;
    unsigned long sum;
    unsigned long minTime;
    unsigned long maxTime;
} g_benchmark = {0};

/* ==========================================================================
 * FUNGSI BANTU
 * ========================================================================== */

static void print_wolfssl_error(const char* msg, int err)
{
    char errBuf[80];
    wolfSSL_ERR_error_string(err, errBuf);
    Serial.print("[ERR] ");
    Serial.print(msg);
    Serial.print(": ");
    Serial.println(errBuf);
}

static bool wifi_connect(void)
{
    unsigned long start = millis();
    Serial.print("[WiFi] Menghubungkan ke ");
    Serial.print(WIFI_SSID);

    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    while (WiFi.status() != WL_CONNECTED) {
        if (millis() - start > 10000) {
            Serial.println("\n[WiFi] TIMEOUT!");
            return false;
        }
        delay(500);
        Serial.print(".");
    }

    Serial.println("\n[WiFi] Terhubung!");
    Serial.print("[WiFi] IP client: ");
    Serial.println(WiFi.localIP());
    return true;
}

static bool setup_wolfssl_ctx(void)
{
    wolfSSL_Init();

    WOLFSSL_METHOD* method = wolfTLSv1_3_client_method();
    if (method == NULL) {
        Serial.println("[ERR] Gagal buat TLS 1.3 client method");
        return false;
    }

    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        Serial.println("[ERR] Gagal buat wolfSSL CTX");
        return false;
    }

    /* SSI-TLS: nonaktifkan verifikasi X.509 -- identitas diverifikasi
     * lewat VC/DID:key setelah handshake selesai */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);

    /* Load Ed25519 private key ke CTX -- dibutuhkan untuk CertificateVerify */
    int keyRet = ssi_load_key_to_ctx(ctx);
    if (keyRet != SSI_OK) {
        Serial.print("[ERR] Gagal load Ed25519 key ke CTX: ");
        Serial.println(keyRet);
        return false;
    }

    /* Custom I/O callbacks -- set di CTX, berlaku untuk semua koneksi */
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
 * SATU SIKLUS HANDSHAKE + VC EXCHANGE
 * Dipakai baik untuk test biasa maupun benchmark
 * ========================================================================== */

/* Return: durasi handshake dalam ms, atau -1 jika gagal */
static long do_ssi_tls_handshake(bool verbose)
{
    WiFiClient tcpClient;
    WOLFSSL*   ssl = NULL;
    long       result = -1;

    /* Buka koneksi TCP ke server */
    if (!tcpClient.connect(SERVER_IP, SERVER_PORT)) {
        if (verbose) Serial.println("[ERR] Gagal connect TCP ke server");
        return -1;
    }
    if (verbose) Serial.println("[TCP] Terhubung ke server");

    /* Buat SSL object */
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        if (verbose) Serial.println("[ERR] Gagal buat wolfSSL object");
        tcpClient.stop();
        return -1;
    }

    /* Hubungkan context WiFiClient ke SSL object ini --
     * callback sudah di-set di CTX saat setup */
    wolfSSL_SetIOReadCtx(ssl,  &tcpClient);
    wolfSSL_SetIOWriteCtx(ssl, &tcpClient);

    /* ===================================================================
     * TLS 1.3 Handshake
     *
     * wolfSSL_connect() melakukan seluruh handshake TLS 1.3:
     *   - Kirim ClientHello dengan SSI extensions (0x0013, 0x0014, 0xFF02)
     *   - Terima ServerHello + EncryptedExtensions
     *   - Proses key exchange (X25519)
     *   - Verifikasi identitas server (RPK/VC)
     *   - Kirim Certificate + Finished
     * =================================================================== */
    if (verbose) Serial.println("[TLS] Memulai handshake...");
    unsigned long hsStart = millis();

    int ret = wolfSSL_connect(ssl);

    unsigned long hsDuration = millis() - hsStart;

    if (ret != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, ret);
        if (verbose) print_wolfssl_error("Handshake gagal", err);
        wolfSSL_free(ssl);
        tcpClient.stop();
        return -1;
    }

    if (verbose) {
        Serial.println("[TLS] Handshake BERHASIL!");
        Serial.print("[TLS] Durasi: ");
        Serial.print(hsDuration);
        Serial.println(" ms");
        Serial.print("[TLS] Cipher: ");
        Serial.println(wolfSSL_get_cipher_name(ssl));
        Serial.print("[TLS] Versi : ");
        Serial.println(wolfSSL_get_version(ssl));
    }

    /* ===================================================================
     * VC Exchange -- mutual authentication di lapisan aplikasi
     * =================================================================== */
    if (verbose) Serial.println("[SSI] Memulai VC exchange...");

    /* Terima VC server dulu */
    byte header[4];
    ret = wolfSSL_read(ssl, header, 4);
    if (ret != 4) {
        if (verbose) Serial.println("[ERR] Gagal baca header VC server");
        wolfSSL_free(ssl);
        tcpClient.stop();
        return -1;
    }

    word32 serverVcLen = ((word32)header[0] << 24) |
                         ((word32)header[1] << 16) |
                         ((word32)header[2] <<  8) |
                         (word32)header[3];

    byte serverVcBuf[SSI_VC_MAX_LEN + 10];
    if (serverVcLen > sizeof(serverVcBuf)) {
        if (verbose) Serial.println("[ERR] VC server terlalu besar");
        wolfSSL_free(ssl);
        tcpClient.stop();
        return -1;
    }

    ret = wolfSSL_read(ssl, serverVcBuf, (int)serverVcLen);
    if (ret != (int)serverVcLen) {
        if (verbose) Serial.println("[ERR] Gagal baca VC server");
        wolfSSL_free(ssl);
        tcpClient.stop();
        return -1;
    }

    /* Deserialize dan verifikasi VC server */
    SSI_VC  serverVC;
    byte    serverPubKey[SSI_ED25519_PUBKEY_SIZE];

    int desRet = ssi_vc_deserialize(&serverVC, serverPubKey,
                                    serverVcBuf, serverVcLen);
    if (desRet != SSI_OK || ssi_verify_vc(&serverVC, serverPubKey) != SSI_OK) {
        if (verbose) Serial.println("[ERR] Verifikasi VC server GAGAL!");
        wolfSSL_free(ssl);
        tcpClient.stop();
        return -1;
    }
    if (verbose) {
        Serial.println("[SSI] VC server VALID!");
        Serial.print("[SSI] Server identity: ");
        Serial.println((char*)serverVC.payload);
    }

    /* Kirim VC client ke server */
    byte clientVcBuf[SSI_VC_MAX_LEN + 10];
    int clientVcLen = ssi_vc_serialize(clientVcBuf + 4, sizeof(clientVcBuf) - 4,
                                       &g_client_vc, ssi_get_pubkey());
    if (clientVcLen < 0) {
        if (verbose) Serial.println("[ERR] Gagal serialize VC client");
        wolfSSL_free(ssl);
        tcpClient.stop();
        return -1;
    }

    clientVcBuf[0] = (byte)(clientVcLen >> 24);
    clientVcBuf[1] = (byte)(clientVcLen >> 16);
    clientVcBuf[2] = (byte)(clientVcLen >>  8);
    clientVcBuf[3] = (byte)(clientVcLen & 0xFF);

    ret = wolfSSL_write(ssl, clientVcBuf, clientVcLen + 4);
    if (ret <= 0) {
        if (verbose) Serial.println("[ERR] Gagal kirim VC client");
        wolfSSL_free(ssl);
        tcpClient.stop();
        return -1;
    }
    if (verbose) Serial.println("[SSI] VC client terkirim");

    /* Tunggu konfirmasi dari server */
    byte ackBuf[16];
    ret = wolfSSL_read(ssl, ackBuf, sizeof(ackBuf) - 1);
    if (ret > 0) {
        ackBuf[ret] = '\0';
        if (verbose) {
            Serial.print("[SSI] Konfirmasi server: ");
            Serial.println((char*)ackBuf);
        }
        if (strncmp((char*)ackBuf, "SSI_REJECT", 10) == 0) {
            if (verbose) Serial.println("[ERR] Server menolak VC kita!");
            wolfSSL_free(ssl);
            tcpClient.stop();
            return -1;
        }
    }

    /* Kirim pesan test */
    if (verbose) {
        const char* testMsg = "Hello dari ESP32 SSI-TLS Client!";
        wolfSSL_write(ssl, testMsg, strlen(testMsg));

        /* Tunggu echo dari server */
        byte recvBuf[150];
        int bytes = wolfSSL_read(ssl, recvBuf, sizeof(recvBuf) - 1);
        if (bytes > 0) {
            recvBuf[bytes] = '\0';
            Serial.print("[Client] Echo dari server: ");
            Serial.println((char*)recvBuf);
        }
    }

    result = (long)hsDuration;

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    tcpClient.stop();
    return result;
}

/* ==========================================================================
 * BENCHMARK
 * ========================================================================== */

static void run_benchmark(void)
{
    Serial.println("\n=== BENCHMARK SSI-TLS HANDSHAKE ===");
    Serial.print("Jumlah rounds: ");
    Serial.println(BENCHMARK_ROUNDS);
    Serial.println("Memulai...\n");

    g_benchmark.count  = 0;
    g_benchmark.sum    = 0;
    g_benchmark.minTime = 0xFFFFFFFF;
    g_benchmark.maxTime = 0;

    for (int i = 0; i < BENCHMARK_ROUNDS; i++) {
        Serial.print("[BM] Round ");
        Serial.print(i + 1);
        Serial.print("/");
        Serial.print(BENCHMARK_ROUNDS);
        Serial.print(" ... ");

        /* Jeda antar round supaya server siap */
        delay(500);

        long t = do_ssi_tls_handshake(false); /* false = tidak verbose */

        if (t < 0) {
            Serial.println("GAGAL (skip)");
            continue;
        }

        g_benchmark.times[g_benchmark.count] = (unsigned long)t;
        g_benchmark.sum += (unsigned long)t;
        if ((unsigned long)t < g_benchmark.minTime) g_benchmark.minTime = t;
        if ((unsigned long)t > g_benchmark.maxTime) g_benchmark.maxTime = t;
        g_benchmark.count++;

        Serial.print(t);
        Serial.println(" ms");
    }

    /* Cetak hasil */
    Serial.println("\n=== HASIL BENCHMARK ===");
    Serial.print("Rounds berhasil : ");
    Serial.print(g_benchmark.count);
    Serial.print("/");
    Serial.println(BENCHMARK_ROUNDS);

    if (g_benchmark.count > 0) {
        unsigned long mean = g_benchmark.sum / g_benchmark.count;

        /* Hitung standar deviasi */
        unsigned long variance = 0;
        for (int i = 0; i < g_benchmark.count; i++) {
            long diff = (long)g_benchmark.times[i] - (long)mean;
            variance += (unsigned long)(diff * diff);
        }
        variance /= g_benchmark.count;
        unsigned long stddev = (unsigned long)sqrt((double)variance);

        Serial.print("Mean            : ");
        Serial.print(mean);
        Serial.println(" ms");
        Serial.print("Min             : ");
        Serial.print(g_benchmark.minTime);
        Serial.println(" ms");
        Serial.print("Max             : ");
        Serial.print(g_benchmark.maxTime);
        Serial.println(" ms");
        Serial.print("Std Dev         : ");
        Serial.print(stddev);
        Serial.println(" ms");
        Serial.println("\n[BM] Salin angka di atas ke tabel hasil skripsi.");
        Serial.println("[BM] Bandingkan dengan baseline plain TLS.");
    }
    Serial.println("=======================\n");
}

/* ==========================================================================
 * SETUP
 * ========================================================================== */

void setup(void)
{
    Serial.begin(115200);
    delay(1000);
    Serial.println("\n\n=== ESP32 SSI-TLS Client ===");
    Serial.println("Muhammad Ikhwan Maulana, 2204111010033");
    Serial.println("Universitas Syiah Kuala");
    Serial.println("============================\n");

    /* Inisialisasi SSI */
    Serial.println("[SSI] Menginisialisasi identitas...");
    int ssiRet = ssi_init();
    if (ssiRet != SSI_OK) {
        Serial.print("[ERR] ssi_init() gagal: ");
        Serial.println(ssiRet);
        while (1) delay(1000);
    }
    ssi_print_identity();

    ssiRet = ssi_create_vc(&g_client_vc, DEVICE_NAME, DEVICE_CLAIMS);
    if (ssiRet != SSI_OK) {
        Serial.print("[ERR] ssi_create_vc() gagal: ");
        Serial.println(ssiRet);
        while (1) delay(1000);
    }
    Serial.println("[SSI] VC client berhasil dibuat");

    /* Sambung WiFi */
    if (!wifi_connect()) {
        while (1) delay(1000);
    }

    /* Setup wolfSSL */
    if (!setup_wolfssl_ctx()) {
        while (1) delay(1000);
    }

    Serial.println("\n[Client] Siap. Memulai dalam 3 detik...");
    delay(3000);
}

/* ==========================================================================
 * LOOP UTAMA
 * ========================================================================== */

void loop(void)
{
    static bool firstRun    = true;
    static bool benchmarkDone = false;

    if (firstRun) {
        firstRun = false;

        /* Test handshake pertama -- verbose, untuk debug */
        Serial.println("\n[Client] === TEST HANDSHAKE PERTAMA (verbose) ===");
        long t = do_ssi_tls_handshake(true);

        if (t < 0) {
            Serial.println("[Client] Handshake pertama gagal.");
            Serial.println("[Client] Cek: server sudah running? IP sudah benar?");
            Serial.println("[Client] Retry dalam 5 detik...");
            delay(5000);
            firstRun = true; /* coba lagi */
            return;
        }

        Serial.println("\n[Client] Test pertama BERHASIL!");
        Serial.println("[Client] Memulai benchmark dalam 2 detik...");
        delay(2000);
    }

    if (!benchmarkDone) {
        benchmarkDone = true;
        run_benchmark();
        Serial.println("[Client] Benchmark selesai. Loop berhenti.");
        Serial.println("[Client] Reset ESP32 untuk menjalankan ulang.");
    }

    /* Setelah benchmark selesai, tidak ada lagi yang dilakukan */
    delay(10000);
}
