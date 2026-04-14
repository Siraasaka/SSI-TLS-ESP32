/*
 * baseline_client.ino — Baseline mTLS 1.3 Client (ESP32 + wolfSSL v5.8.4)
 * Standard mutual TLS with X.509 RSA-2048.
 * Uses CTX_* macros from user_settings.h (official wolfSSL pattern).
 * Round 0: debug, Round 1-1000: benchmark with stats
 */

#include <WiFi.h>
#include <wolfssl.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>
#include <math.h>

const char* WIFI_SSID     = "Tahu";
const char* WIFI_PASSWORD = "merekatahu";
const char* SERVER_IP     = "10.138.2.152";
const int   SERVER_PORT   = 8443;
const int   TOTAL_ROUNDS  = 151;
const unsigned long HS_TIMEOUT = 30000;
const int   DELAY_BETWEEN = 1000;

WOLFSSL_CTX*    ctx = NULL;
int             roundNum = 0;
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

void setup() {
    Serial.begin(115200); delay(2000);
    Serial.println("\n====================================");
    Serial.println("Baseline mTLS 1.3 Client");
    Serial.println("(X.509 RSA-2048)");
    Serial.println("====================================");

    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    while(WiFi.status()!=WL_CONNECTED){delay(500);Serial.print(".");}
    Serial.printf("\n[WiFi] IP: %s\n", WiFi.localIP().toString().c_str());

    wolfSSL_Init();

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if(!ctx){Serial.println("CTX fail");return;}

    wolfSSL_CTX_SetIORecv(ctx, wifi_recv);
    wolfSSL_CTX_SetIOSend(ctx, wifi_send);

    /* Client cert */
    int ret = wolfSSL_CTX_use_certificate_buffer(ctx,
                CTX_CLIENT_CERT, CTX_CLIENT_CERT_SIZE, CTX_CLIENT_CERT_TYPE);
    if(ret != WOLFSSL_SUCCESS){
        Serial.printf("Load client cert fail: %d\n",ret); return;
    }
    Serial.println("[Cert] Client cert loaded OK");

    /* Client key */
    ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx,
                CTX_CLIENT_KEY, CTX_CLIENT_KEY_SIZE, CTX_CLIENT_KEY_TYPE);
    if(ret != WOLFSSL_SUCCESS){
        Serial.printf("Load client key fail: %d\n",ret); return;
    }
    Serial.println("[Cert] Client key loaded OK");

    /* CA cert for server verification */
    ret = wolfSSL_CTX_load_verify_buffer(ctx,
                CTX_CA_CERT, CTX_CA_CERT_SIZE, CTX_CA_CERT_TYPE);
    if(ret != WOLFSSL_SUCCESS){
        Serial.printf("Load CA cert fail: %d\n",ret); return;
    }
    Serial.println("[Cert] CA cert loaded OK");

    /* Verify server */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);

    Serial.printf("[Client] Target: %s:%d\n", SERVER_IP, SERVER_PORT);
    Serial.println("Round 0=DEBUG, 1-1000=BENCH\n");
    delay(5000);
}

bool doRound(int round) {
    bool dbg = (round == 0);
    if(dbg){
#ifdef DEBUG_WOLFSSL
        wolfSSL_Debugging_ON();
#endif
        Serial.println("\n=== ROUND 0: DEBUG ===");
    } else {
        wolfSSL_Debugging_OFF();
    }

    WiFiClient client;
    if(!client.connect(SERVER_IP, SERVER_PORT)){
        if(dbg) Serial.println("[TCP] Connect failed");
        return false;
    }
    g_client = &client;

    WOLFSSL* ssl = wolfSSL_new(ctx);
    if(!ssl){
        if(dbg) Serial.println("wolfSSL_new fail");
        client.stop(); g_client=NULL; return false;
    }

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

    if(ok){
        char buf[32]; int n=0;
        unsigned long rd = millis() + 5000;
        while(millis()<rd){
            n = wolfSSL_read(ssl, buf, sizeof(buf)-1);
            if(n>0) break;
            int e2 = wolfSSL_get_error(ssl,n);
            if(e2==WOLFSSL_ERROR_WANT_READ){delay(10);continue;}
            break;
        }
        wolfSSL_write(ssl, "ACK", 3);
        delay(100);

        if(dbg){
            buf[n>0?n:0]='\0';
            Serial.println("====================================");
            Serial.println("  mTLS HANDSHAKE SUCCESS!");
            Serial.printf("  Time: %lu ms\n", hsTime);
            Serial.printf("  Cipher: %s\n", wolfSSL_get_cipher_name(ssl));
            Serial.printf("  Server: %s\n", buf);
            Serial.println("====================================");
            Serial.println("\nDebug OK. Starting benchmark...\n");
        } else {
            Serial.printf("%d,%lu\n", round, hsTime);
            if(benchCount < 1000) hsTimes[benchCount++] = hsTime;
        }
    }

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    client.stop();
    g_client = NULL;
    return ok;
}

void printStats() {
    if(benchCount==0){Serial.println("No data.");return;}
    Serial.println("\n========================================");
    Serial.println("  BASELINE mTLS BENCHMARK RESULTS");
    Serial.printf("  Samples: %d\n", benchCount);
    Serial.println("========================================");

    unsigned long total=0, minT=0xFFFFFFFF, maxT=0;
    for(int i=0;i<benchCount;i++){
        total+=hsTimes[i];
        if(hsTimes[i]<minT)minT=hsTimes[i];
        if(hsTimes[i]>maxT)maxT=hsTimes[i];
    }
    float mean=(float)total/benchCount;
    float var=0;
    for(int i=0;i<benchCount;i++){float d=(float)hsTimes[i]-mean;var+=d*d;}
    float sd=sqrt(var/benchCount);

    unsigned long sorted[1000];
    memcpy(sorted,hsTimes,benchCount*sizeof(unsigned long));
    for(int i=1;i<benchCount;i++){
        unsigned long k=sorted[i];int j=i-1;
        while(j>=0&&sorted[j]>k){sorted[j+1]=sorted[j];j--;}
        sorted[j+1]=k;
    }
    float median;
    if(benchCount%2==0) median=(sorted[benchCount/2-1]+sorted[benchCount/2])/2.0f;
    else median=sorted[benchCount/2];

    Serial.printf("  Mean:   %.2f ms\n", mean);
    Serial.printf("  Median: %.2f ms\n", median);
    Serial.printf("  Min:    %lu ms\n", minT);
    Serial.printf("  Max:    %lu ms\n", maxT);
    Serial.printf("  StdDev: %.2f ms\n", sd);
    Serial.printf("  P5:     %lu ms\n", sorted[(int)(benchCount*0.05)]);
    Serial.printf("  P95:    %lu ms\n", sorted[(int)(benchCount*0.95)]);
    Serial.printf("  Total:  %lu ms\n", total);
    Serial.println("========================================");

    Serial.println("\n--- CSV DATA (round,ms) ---");
    for(int i=0;i<benchCount;i++) Serial.printf("%d,%lu\n",i+1,hsTimes[i]);
    Serial.println("--- END CSV ---");
}

void loop() {
    if(!ctx||roundNum>=TOTAL_ROUNDS){
        if(roundNum==TOTAL_ROUNDS){printStats();roundNum++;Serial.println("\nDone. Halting.");}
        delay(10000);return;
    }
    bool ok = doRound(roundNum);
    if(ok){
        roundNum++;
        if(roundNum>1&&roundNum<TOTAL_ROUNDS) delay(DELAY_BETWEEN);
        else if(roundNum==1) delay(3000);
    } else {
        Serial.printf("[!] Round %d failed, retry 3s\n",roundNum);
        delay(3000);
    }
    if(roundNum>0&&roundNum%100==0&&roundNum<TOTAL_ROUNDS)
        Serial.printf("--- Progress: %d/%d ---\n",roundNum,TOTAL_ROUNDS-1);
}
