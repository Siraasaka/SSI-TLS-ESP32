/*
 * baseline_server.ino — Baseline mTLS 1.3 Server (ESP32 + wolfSSL v5.8.4)
 * Standard mutual TLS with X.509 RSA-2048.
 * Uses CTX_* macros from user_settings.h (official wolfSSL pattern).
 * Round 0: debug, Round 1-1000: benchmark
 */

#include <WiFi.h>
#include <wolfssl.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>

const char* WIFI_SSID     = "Tahu";
const char* WIFI_PASSWORD = "merekatahu";
const int   TLS_PORT      = 8443;
const int   TOTAL_ROUNDS  = 151;
const unsigned long HS_TIMEOUT = 30000;

WiFiServer      wifiServer(TLS_PORT);
WOLFSSL_CTX*    ctx = NULL;
int             roundNum = 0;
static WiFiClient* g_client = NULL;

int wifi_send(WOLFSSL* s, char* b, int sz, void* c) {
    (void)s;(void)c;
    if(!g_client||!g_client->connected()) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    int n=g_client->write((uint8_t*)b,sz);
    return n>0?n:WOLFSSL_CBIO_ERR_WANT_WRITE;
}
int wifi_recv(WOLFSSL* s, char* b, int sz, void* c) {
    (void)s;(void)c;
    if(!g_client||!g_client->connected()) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    if(!g_client->available()) return WOLFSSL_CBIO_ERR_WANT_READ;
    int n=g_client->read((uint8_t*)b,sz);
    return n>0?n:WOLFSSL_CBIO_ERR_WANT_READ;
}

void setup() {
    Serial.begin(115200); delay(2000);
    Serial.println("\n====================================");
    Serial.println("Baseline mTLS 1.3 Server");
    Serial.println("(X.509 RSA-2048)");
    Serial.println("====================================");

    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    while(WiFi.status()!=WL_CONNECTED){delay(500);Serial.print(".");}
    Serial.printf("\n[WiFi] IP: %s\n", WiFi.localIP().toString().c_str());

    wolfSSL_Init();

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if(!ctx){Serial.println("CTX fail");return;}

    wolfSSL_CTX_SetIORecv(ctx, wifi_recv);
    wolfSSL_CTX_SetIOSend(ctx, wifi_send);

    /* Server cert — exactly like official wolfSSL example */
    int ret = wolfSSL_CTX_use_certificate_buffer(ctx,
                CTX_SERVER_CERT, CTX_SERVER_CERT_SIZE, CTX_SERVER_CERT_TYPE);
    if(ret != WOLFSSL_SUCCESS){
        Serial.printf("Load server cert fail: %d\n",ret); return;
    }
    Serial.println("[Cert] Server cert loaded OK");

    /* Server key */
    ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx,
                CTX_SERVER_KEY, CTX_SERVER_KEY_SIZE, CTX_SERVER_KEY_TYPE);
    if(ret != WOLFSSL_SUCCESS){
        Serial.printf("Load server key fail: %d\n",ret); return;
    }
    Serial.println("[Cert] Server key loaded OK");

    /* CA cert for client verification */
    ret = wolfSSL_CTX_load_verify_buffer(ctx,
                CTX_CA_CERT, CTX_CA_CERT_SIZE, CTX_CA_CERT_TYPE);
    if(ret != WOLFSSL_SUCCESS){
        Serial.printf("Load CA cert fail: %d\n",ret); return;
    }
    Serial.println("[Cert] CA cert loaded OK");

    /* Require mutual auth */
    wolfSSL_CTX_set_verify(ctx,
        WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    wifiServer.begin();
    Serial.printf("[Server] port %d — Round 0=DEBUG, 1-1000=BENCH\n", TLS_PORT);
    Serial.println("Waiting for client...\n");
}

void loop() {
    if(!ctx||roundNum>=TOTAL_ROUNDS){delay(1000);return;}

    WiFiClient client = wifiServer.available();
    if(!client){delay(10);return;}

    bool dbg = (roundNum == 0);
    if(dbg){
#ifdef DEBUG_WOLFSSL
        wolfSSL_Debugging_ON();
#endif
        Serial.println("\n=== ROUND 0: DEBUG ===");
    } else {
        wolfSSL_Debugging_OFF();
    }

    g_client = &client;
    WOLFSSL* ssl = wolfSSL_new(ctx);
    if(!ssl){
        if(dbg) Serial.println("wolfSSL_new fail");
        client.stop(); g_client=NULL; delay(1000); return;
    }

    unsigned long t0 = millis();
    unsigned long deadline = t0 + HS_TIMEOUT;
    int ret; bool ok = false;

    while(millis() < deadline) {
        ret = wolfSSL_accept(ssl);
        if(ret == WOLFSSL_SUCCESS){ok=true;break;}
        int err = wolfSSL_get_error(ssl, ret);
        if(err==WOLFSSL_ERROR_WANT_READ||err==WOLFSSL_ERROR_WANT_WRITE){
            delay(1); continue;
        }
        if(dbg){
            char eb[80]; wolfSSL_ERR_error_string(err,eb);
            Serial.printf("[TLS] err: %d (%s)\n",err,eb);
        }
        break;
    }

    unsigned long hsTime = millis() - t0;

    if(ok) {
        const char* msg = "OK";
        wolfSSL_write(ssl, msg, 2);

        char buf[32]; int n=0;
        unsigned long rd = millis() + 5000;
        while(millis()<rd){
            n = wolfSSL_read(ssl, buf, sizeof(buf)-1);
            if(n>0) break;
            int e2 = wolfSSL_get_error(ssl,n);
            if(e2==WOLFSSL_ERROR_WANT_READ){delay(10);continue;}
            break;
        }

        if(dbg){
            buf[n>0?n:0]='\0';
            Serial.println("====================================");
            Serial.println("  mTLS HANDSHAKE SUCCESS!");
            Serial.printf("  Time: %lu ms\n", hsTime);
            Serial.printf("  Cipher: %s\n", wolfSSL_get_cipher_name(ssl));
            Serial.printf("  Client: %s\n", buf);
            Serial.println("====================================");
            Serial.println("\nDebug OK. Starting benchmark...\n");
        } else {
            Serial.printf("%d,%lu\n", roundNum, hsTime);
        }
        roundNum++;
    } else {
        if(dbg) Serial.println("[!] Debug round failed, retrying...");
        delay(2000);
    }

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    client.stop();
    g_client = NULL;

    if(roundNum == TOTAL_ROUNDS)
        Serial.println("\n[Server] All rounds done.");
}
