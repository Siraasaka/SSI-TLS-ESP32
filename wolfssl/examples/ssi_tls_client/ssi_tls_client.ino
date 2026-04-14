/*
 * ssi_tls_client.ino — SSI-TLS 1.3 Client (ESP32 + wolfSSL v5.8.4)
 * Round 0: debug ON, single handshake verify
 * Round 1-1000: debug OFF, benchmark with full stats at end
 */

#include <WiFi.h>
#include <wolfssl.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <math.h>

#define SSI_IDENTITY_IMPL
#include <ssi_identity.h>

const char* WIFI_SSID     = "Tahu";
const char* WIFI_PASSWORD = "merekatahu";
const char* SERVER_IP     = "10.138.2.152";  /* UPDATE if changed */
const int   SERVER_PORT   = 8443;
const int   TOTAL_ROUNDS  = 151;          /* 0=debug, 1..1000=bench */
const unsigned long HS_TIMEOUT = 30000;    /* ms */
const int   DELAY_BETWEEN = 1000;          /* ms between bench rounds */

WOLFSSL_CTX*    ctx = NULL;
SSI_Identity    identity;
int             ready = 0;
int             roundNum = 0;

/* Benchmark data — stored in PSRAM-friendly chunks */
unsigned long   hsTimes[1000];
int             benchCount = 0;

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
    Serial.println("SSI-TLS v2.0 Client");
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
    SSI_Identity_SetClaims(&identity, "ESP32-Client;FW:1.0");
    r = SSI_Identity_CreateVC(&identity);
    if(r!=0){Serial.printf("VC fail %d\n",r);return;}
    Serial.printf("[SSI] VC: %d bytes\n", identity.vcLen);
    ready = 1;

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if(!ctx){Serial.println("CTX fail");return;}
    wolfSSL_CTX_SetIORecv(ctx, wifi_recv);
    wolfSSL_CTX_SetIOSend(ctx, wifi_send);
    char st[]={WOLFSSL_CERT_TYPE_VC, WOLFSSL_CERT_TYPE_X509};
    char ct[]={WOLFSSL_CERT_TYPE_VC, WOLFSSL_CERT_TYPE_X509};
    wolfSSL_CTX_set_server_cert_type(ctx, st, 2);
    wolfSSL_CTX_set_client_cert_type(ctx, ct, 2);
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, verify_cb);

    Serial.printf("[Client] Target: %s:%d\n", SERVER_IP, SERVER_PORT);
    Serial.println("Round 0=DEBUG, 1-1000=BENCH");
    Serial.println("====================================\n");
    delay(5000);  /* Wait for server to be ready */
}

/* ========================================================================== */
/* One handshake round                                                         */
/* ========================================================================== */

bool doRound(int round) {
    bool dbg = (round == 0);

    if(dbg) {
#ifdef DEBUG_WOLFSSL
        wolfSSL_Debugging_ON();
#endif
        Serial.println("\n=== ROUND 0: DEBUG ===");
    } else {
        wolfSSL_Debugging_OFF();
    }

    /* TCP connect */
    WiFiClient client;
    if(!client.connect(SERVER_IP, SERVER_PORT)) {
        if(dbg) Serial.println("[TCP] Connect failed");
        return false;
    }
    g_client = &client;

    WOLFSSL* ssl = wolfSSL_new(ctx);
    if(!ssl) {
        if(dbg) Serial.println("wolfSSL_new fail");
        client.stop(); g_client=NULL; return false;
    }

    /* Load VC + key */
    byte pk[ED25519_KEY_SIZE], pub[ED25519_PUB_KEY_SIZE];
    word32 pkl=ED25519_KEY_SIZE, publ=ED25519_PUB_KEY_SIZE;
    wolfSSL_SSI_use_VC_buffer(ssl, identity.vcBuffer, identity.vcLen);
    wc_ed25519_export_private_only(&identity.key, pk, &pkl);
    wc_ed25519_export_public(&identity.key, pub, &publ);
    wolfSSL_SSI_use_Ed25519_key(ssl, pk, pub);

    /* Handshake — measure only this */
    unsigned long t0 = millis();
    unsigned long deadline = t0 + HS_TIMEOUT;
    int ret; bool ok = false;

    while(millis() < deadline) {
        ret = wolfSSL_connect(ssl);
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
        /* Read server message first, then send ack */
        char buf[32]; int n=0;
        unsigned long rd = millis() + 5000;
        while(millis()<rd){
            n = wolfSSL_read(ssl, buf, sizeof(buf)-1);
            if(n>0) break;
            int e2 = wolfSSL_get_error(ssl,n);
            if(e2==WOLFSSL_ERROR_WANT_READ){delay(10);continue;}
            break;
        }

        /* Send ack */
        wolfSSL_write(ssl, "ACK", 3);

        /* Small delay to let server process our ack */
        delay(100);

        if(dbg) {
            buf[n>0?n:0]='\0';
            Serial.println("====================================");
            Serial.println("  SSI-TLS HANDSHAKE SUCCESS!");
            Serial.printf("  Time: %lu ms\n", hsTime);
            int sct=-1,cct=-1;
            wolfSSL_get_negotiated_server_cert_type(ssl,&sct);
            wolfSSL_get_negotiated_client_cert_type(ssl,&cct);
            Serial.printf("  server_cert_type=%d client_cert_type=%d\n",sct,cct);
            Serial.printf("  Server says: %s\n", buf);
            Serial.println("====================================");
            Serial.println("\nDebug round OK. Starting benchmark...\n");
        } else {
            Serial.printf("%d,%lu\n", round, hsTime);
            /* Store for stats */
            if(benchCount < 1000) {
                hsTimes[benchCount++] = hsTime;
            }
        }
    }

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    client.stop();
    g_client = NULL;

    return ok;
}

/* ========================================================================== */
/* Print benchmark stats                                                       */
/* ========================================================================== */

void printStats() {
    if(benchCount == 0) { Serial.println("No data."); return; }

    Serial.println("\n========================================");
    Serial.println("  SSI-TLS BENCHMARK RESULTS");
    Serial.printf("  Samples: %d\n", benchCount);
    Serial.println("========================================");

    unsigned long total=0, minT=0xFFFFFFFF, maxT=0;
    for(int i=0;i<benchCount;i++){
        total += hsTimes[i];
        if(hsTimes[i]<minT) minT=hsTimes[i];
        if(hsTimes[i]>maxT) maxT=hsTimes[i];
    }

    float mean = (float)total / benchCount;
    float variance = 0;
    for(int i=0;i<benchCount;i++){
        float d = (float)hsTimes[i] - mean;
        variance += d*d;
    }
    float stddev = sqrt(variance / benchCount);

    /* Median (simple: sort a copy) */
    /* For 1000 samples, use insertion sort */
    unsigned long sorted[1000];
    memcpy(sorted, hsTimes, benchCount * sizeof(unsigned long));
    for(int i=1;i<benchCount;i++){
        unsigned long key=sorted[i]; int j=i-1;
        while(j>=0 && sorted[j]>key){sorted[j+1]=sorted[j];j--;}
        sorted[j+1]=key;
    }
    float median;
    if(benchCount%2==0)
        median = (sorted[benchCount/2-1]+sorted[benchCount/2])/2.0f;
    else
        median = sorted[benchCount/2];

    /* Percentiles */
    float p5  = sorted[(int)(benchCount*0.05)];
    float p95 = sorted[(int)(benchCount*0.95)];

    Serial.printf("  Mean:   %.2f ms\n", mean);
    Serial.printf("  Median: %.2f ms\n", median);
    Serial.printf("  Min:    %lu ms\n", minT);
    Serial.printf("  Max:    %lu ms\n", maxT);
    Serial.printf("  StdDev: %.2f ms\n", stddev);
    Serial.printf("  P5:     %.0f ms\n", p5);
    Serial.printf("  P95:    %.0f ms\n", p95);
    Serial.printf("  Total:  %lu ms\n", total);
    Serial.println("========================================");

    /* CSV dump for analysis */
    Serial.println("\n--- CSV DATA (round,ms) ---");
    for(int i=0;i<benchCount;i++){
        Serial.printf("%d,%lu\n", i+1, hsTimes[i]);
    }
    Serial.println("--- END CSV ---");
}

/* ========================================================================== */
/* Main loop                                                                   */
/* ========================================================================== */

void loop() {
    if(!ready||!ctx||roundNum>=TOTAL_ROUNDS){
        if(roundNum==TOTAL_ROUNDS){
            printStats();
            roundNum++; /* prevent re-print */
            Serial.println("\nDone. Halting.");
        }
        delay(10000);
        return;
    }

    bool ok = doRound(roundNum);
    if(ok) {
        roundNum++;
        /* Delay between benchmark rounds (not after debug round) */
        if(roundNum > 1 && roundNum < TOTAL_ROUNDS) {
            delay(DELAY_BETWEEN);
        } else if(roundNum == 1) {
            delay(3000); /* Extra delay after debug round */
        }
    } else {
        Serial.printf("[!] Round %d failed, retry in 3s\n", roundNum);
        delay(3000);
    }

    /* Progress indicator every 100 rounds */
    if(roundNum > 0 && roundNum % 100 == 0 && roundNum < TOTAL_ROUNDS) {
        Serial.printf("--- Progress: %d/%d ---\n", roundNum, TOTAL_ROUNDS-1);
    }
}
