/*
 * ssi_tls_server.ino — SSI-TLS 1.3 Server (ESP32 + wolfSSL v5.8.4)
 * Round 0: debug ON, single handshake verify
 * Round 1-1000: debug OFF, benchmark (handshake time logged per round)
 */

#include <WiFi.h>
#include <wolfssl.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ed25519.h>

#define SSI_IDENTITY_IMPL
#include <ssi_identity.h>

const char* WIFI_SSID     = "Tahu";
const char* WIFI_PASSWORD = "merekatahu";
const int   TLS_PORT      = 8443;
const int   TOTAL_ROUNDS  = 151;          /* 0=debug, 1..1000=bench */
const unsigned long HS_TIMEOUT = 30000;    /* ms */

WiFiServer      wifiServer(TLS_PORT);
WOLFSSL_CTX*    ctx = NULL;
SSI_Identity    identity;
int             ready = 0;
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
static int verify_cb(int pv, WOLFSSL_X509_STORE_CTX* st) {
    (void)pv;(void)st; return 1;
}

void setup() {
    Serial.begin(115200); delay(2000);
    Serial.println("\n====================================");
    Serial.println("SSI-TLS v2.0 Server");
    Serial.println("====================================");

    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    while(WiFi.status()!=WL_CONNECTED){delay(500);Serial.print(".");}
    Serial.printf("\n[WiFi] IP: %s\n", WiFi.localIP().toString().c_str());

    wolfSSL_Init();

    int r = SSI_Identity_Init(&identity);
    if(r!=0){Serial.printf("Init fail %d\n",r);return;}
    r = SSI_Identity_Generate(&identity);
    if(r!=0){Serial.printf("Gen fail %d\n",r);return;}
    Serial.printf("[SSI] DID: %s\n", identity.didString);
    SSI_Identity_SetClaims(&identity, "ESP32-Server;FW:1.0");
    r = SSI_Identity_CreateVC(&identity);
    if(r!=0){Serial.printf("VC fail %d\n",r);return;}
    Serial.printf("[SSI] VC: %d bytes\n", identity.vcLen);
    ready = 1;

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if(!ctx){Serial.println("CTX fail");return;}
    wolfSSL_CTX_SetIORecv(ctx, wifi_recv);
    wolfSSL_CTX_SetIOSend(ctx, wifi_send);
    char st[]={WOLFSSL_CERT_TYPE_VC, WOLFSSL_CERT_TYPE_X509};
    char ct[]={WOLFSSL_CERT_TYPE_VC, WOLFSSL_CERT_TYPE_X509};
    wolfSSL_CTX_set_server_cert_type(ctx, st, 2);
    wolfSSL_CTX_set_client_cert_type(ctx, ct, 2);
    wolfSSL_CTX_set_verify(ctx,
        WOLFSSL_VERIFY_PEER|WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb);

    wifiServer.begin();
    Serial.printf("[Server] port %d — Round 0=DEBUG, 1-1000=BENCH\n", TLS_PORT);
    Serial.println("Waiting for client...\n");
}

void loop() {
    if(!ready||!ctx||roundNum>=TOTAL_ROUNDS){delay(1000);return;}

    WiFiClient client = wifiServer.available();
    if(!client){delay(10);return;}

    bool dbg = (roundNum == 0);

    if(dbg) {
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

    /* Load VC + key */
    byte pk[ED25519_KEY_SIZE], pub[ED25519_PUB_KEY_SIZE];
    word32 pkl=ED25519_KEY_SIZE, publ=ED25519_PUB_KEY_SIZE;
    wolfSSL_SSI_use_VC_buffer(ssl, identity.vcBuffer, identity.vcLen);
    wc_ed25519_export_private_only(&identity.key, pk, &pkl);
    wc_ed25519_export_public(&identity.key, pub, &publ);
    wolfSSL_SSI_use_Ed25519_key(ssl, pk, pub);

    /* Handshake */
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
        /* App data exchange — confirms the channel is live */
        const char* msg = "OK";
        wolfSSL_write(ssl, msg, 2);

        /* Read client ack with timeout */
        char buf[32]; int n=0;
        unsigned long rd = millis() + 5000;
        while(millis()<rd){
            n = wolfSSL_read(ssl, buf, sizeof(buf)-1);
            if(n>0) break;
            int e2 = wolfSSL_get_error(ssl,n);
            if(e2==WOLFSSL_ERROR_WANT_READ){delay(10);continue;}
            break;
        }

        if(dbg) {
            buf[n>0?n:0]='\0';
            Serial.println("====================================");
            Serial.println("  SSI-TLS HANDSHAKE SUCCESS!");
            Serial.printf("  Time: %lu ms\n", hsTime);
            int sct=-1,cct=-1;
            wolfSSL_get_negotiated_server_cert_type(ssl,&sct);
            wolfSSL_get_negotiated_client_cert_type(ssl,&cct);
            Serial.printf("  server_cert_type=%d client_cert_type=%d\n",sct,cct);
            Serial.printf("  Client says: %s\n", buf);
            Serial.println("====================================");
            Serial.println("\nDebug round OK. Starting benchmark...\n");
        } else {
            /* Benchmark: just print round and time */
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

    /* Final summary */
    if(roundNum == TOTAL_ROUNDS) {
        Serial.println("\n[Server] All 1000 benchmark rounds done.");
        Serial.println("See client serial for full stats.");
    }
}
