/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * ShieldNet over-the-air bandwidth benchmark — device side.
 *
 * Joins Wi-Fi, runs a real v3 responder on a UDP socket, and reports the sustained
 * inbound rate as a host driver streams enveloped KCP data at it. Unlike the
 * offline benchmark (benchmark/shieldnet-esp32) this measures the WHOLE path:
 * Wi-Fi PHY/MAC -> lwIP -> the admission/envelope/KCP stack -> the app payload.
 *
 * Credentials come from menuconfig (Kconfig.projbuild) and live only in sdkconfig,
 * which is gitignored for this project.
 *
 * Pair with: goshieldnet's TestWifiBandwidth (see the README).
 */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "nvs_flash.h"
#include <sodium.h>

#include "shieldnet/sn_demux.h"
#include "shieldnet/sn_device.h"
#include "shieldnet/sn_kdf.h"
#include "shieldnet_os.h"
#include "ikcp.h"

static const char *TAG = "wifibench";

#define WIFI_CONNECTED_BIT BIT0
static EventGroupHandle_t s_events;
static esp_netif_t *s_netif;

static struct {
    int fd;
    sn_device dev;
} g;

/* ── Wi-Fi ────────────────────────────────────────────────────────────────── */

static void on_wifi(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg; (void)data;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGW(TAG, "disconnected, retrying");
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        xEventGroupSetBits(s_events, WIFI_CONNECTED_BIT);
    }
}

static void wifi_start(void) {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    s_netif = esp_netif_create_default_wifi_sta();
    s_events = xEventGroupCreate();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_wifi, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, on_wifi, NULL));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

    wifi_config_t sta = {0};
    strlcpy((char *)sta.sta.ssid, CONFIG_SNBENCH_WIFI_SSID, sizeof(sta.sta.ssid));
    strlcpy((char *)sta.sta.password, CONFIG_SNBENCH_WIFI_PASSWORD, sizeof(sta.sta.password));
    sta.sta.threshold.authmode =
        CONFIG_SNBENCH_WIFI_PASSWORD[0] ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta));
    ESP_ERROR_CHECK(esp_wifi_start());
    /* Power save OFF: it costs a lot of throughput and adds latency jitter. */
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

    ESP_LOGI(TAG, "joining \"%s\"...", CONFIG_SNBENCH_WIFI_SSID);
    xEventGroupWaitBits(s_events, WIFI_CONNECTED_BIT, pdFALSE, pdTRUE, portMAX_DELAY);

    esp_netif_ip_info_t ip = {0};
    esp_netif_get_ip_info(s_netif, &ip);
    printf("\nDEVICE_IP " IPSTR "\n", IP2STR(&ip.ip));
    printf("DEVICE_PORT %d\n", CONFIG_SNBENCH_PORT);
    fflush(stdout);
}

/* ── v3 device ────────────────────────────────────────────────────────────── */

/* Transmit to the primary's canonical_source (v4-mapped a16 || port_be). */
static void dev_send(void *ctx, const uint8_t *buf, size_t len, const uint8_t dst[18]) {
    (void)ctx;
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    memcpy(&to.sin_addr.s_addr, dst + 12, 4);
    to.sin_port = htons((uint16_t)((dst[16] << 8) | dst[17]));
    sendto(g.fd, buf, len, 0, (struct sockaddr *)&to, sizeof(to));
}

static int hex2bin(const char *hex, uint8_t *out, size_t n) {
    if (strlen(hex) != 2 * n) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

/* ── the benchmark: report inbound payload rate over 1s windows ───────────── */

void app_main(void) {
    if (sodium_init() < 0) { ESP_LOGE(TAG, "sodium"); return; }
    esp_err_t nv = nvs_flash_init();
    if (nv == ESP_ERR_NVS_NO_FREE_PAGES || nv == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }
    if (CONFIG_SNBENCH_WIFI_SSID[0] == '\0') {
        printf("\nSet the SSID: idf.py menuconfig -> ShieldNet Wi-Fi benchmark\n");
        return;
    }
    wifi_start();

    uint8_t psk[32];
    if (hex2bin(CONFIG_SNBENCH_PSK_HEX, psk, 32) != 0) {
        printf("PSK must be 64 hex chars\n");
        return;
    }
    uint8_t device_id[8] = {0};
    esp_wifi_get_mac(WIFI_IF_STA, device_id); /* MAC-derived, as the firmware does */

    uint8_t cookie_secret[32], admission_epoch[8];
    randombytes_buf(cookie_secret, 32);
    randombytes_buf(admission_epoch, 8);
    admission_epoch[0] = 0;

    /* §4.3 prefix from the live interface. */
    esp_netif_ip_info_t ip = {0};
    esp_netif_get_ip_info(s_netif, &ip);
    sn_prefix local = {0};
    local.a16[10] = 0xff; local.a16[11] = 0xff;
    memcpy(local.a16 + 12, &ip.ip.addr, 4);
    local.is_v4 = 1;
    { uint32_t nm = ntohl(ip.netmask.addr); int b = 0; while (nm & 0x80000000u) { b++; nm <<= 1; }
      local.bits = b ? b : 24; }

    /* The device stores k_dev, never the PSK: sn_provision_kdev derives it and wipes psk. */
    uint8_t k_dev[32];
    if (sn_provision_kdev(psk, device_id, k_dev) != 0 ||
        sn_device_init_kdev(&g.dev, k_dev, device_id, cookie_secret, admission_epoch,
                            &local, 1, shieldnet_os_now_ms64()) != 0) {
        printf("device init failed\n");
        return;
    }
    sn_device_locks_init(&g.dev);
    sn_device_set_send_to(&g.dev, dev_send, NULL);
    { /* a window that can actually hold a burst over Wi-Fi */
        sn_kcp_tuning t = SN_KCP_TUNING_DEFAULT;
        t.snd_wnd = 64; t.rcv_wnd = 64; t.interval = 10;
        sn_device_set_tuning(&g.dev, t);
    }
    sn_device_start_tick(&g.dev, 5);

    g.fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in ba = {0};
    ba.sin_family = AF_INET;
    ba.sin_addr.s_addr = htonl(INADDR_ANY);
    ba.sin_port = htons(CONFIG_SNBENCH_PORT);
    if (bind(g.fd, (struct sockaddr *)&ba, sizeof(ba)) < 0) { ESP_LOGE(TAG, "bind"); return; }
    { /* Short: this single-threaded loop also drains the raw-UDP baseline socket,
       * so a long block here starves it (measured: a 200 ms block capped the raw
       * sink at ~0.4 MB/s regardless of offered load). */
      struct timeval tv = { .tv_sec = 0, .tv_usec = 2000 };
      setsockopt(g.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)); }

    /* Raw-UDP baseline sink on PORT+1: counts bytes with no v3/KCP at all, so we
     * can tell the radio+lwIP ceiling apart from our protocol tuning. */
    int rawfd = socket(AF_INET, SOCK_DGRAM, 0);
    {
        struct sockaddr_in rb = {0};
        rb.sin_family = AF_INET;
        rb.sin_addr.s_addr = htonl(INADDR_ANY);
        rb.sin_port = htons(CONFIG_SNBENCH_PORT + 1);
        bind(rawfd, (struct sockaddr *)&rb, sizeof(rb));
        struct timeval tv = { .tv_sec = 0, .tv_usec = 1000 };
        setsockopt(rawfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    static uint8_t rawbuf[2048];
    uint64_t raw_bytes = 0, raw_t0 = 0, raw_last = 0;

    printf("RAW_PORT %d\n", CONFIG_SNBENCH_PORT + 1);
    printf("READY — waiting for the host driver\n");
    fflush(stdout);

    static uint8_t buf[2048], app[2048];
    uint64_t bytes = 0, datagrams = 0, win_bytes = 0;
    uint64_t t_win = (uint64_t)(esp_timer_get_time() / 1000);
    uint64_t t_first = 0;

    for (;;) {
        struct sockaddr_in from; socklen_t fl = sizeof(from);
        ssize_t n = recvfrom(g.fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fl);
        uint64_t now = (uint64_t)(esp_timer_get_time() / 1000);
        if (n > 0) {
            uint8_t a16[16] = {0};
            a16[10] = 0xff; a16[11] = 0xff;
            memcpy(a16 + 12, &from.sin_addr.s_addr, 4);
            uint16_t port = ntohs(from.sin_port);
            switch (sn_classify(SN_ROLE_DEVICE, 1, a16, &local, 1, buf, (size_t)n)) {
            case SN_CLASS_INIT: {
                uint8_t r[SN_RETRY_LEN];
                if (sn_handle_init(&g.dev, buf, (size_t)n, a16, port, now, r) == SN_RETRY_LEN)
                    sendto(g.fd, r, SN_RETRY_LEN, 0, (struct sockaddr *)&from, fl);
                break;
            }
            case SN_CLASS_FINISH: {
                uint8_t ad[SN_ADMIT_LEN];
                if (sn_handle_finish(&g.dev, buf, (size_t)n, a16, port, now, ad) == SN_ADMIT_LEN)
                    sendto(g.fd, ad, SN_ADMIT_LEN, 0, (struct sockaddr *)&from, fl);
                break;
            }
            case SN_CLASS_ENVELOPE: {
                sn_handle_envelope(&g.dev, buf, (size_t)n, a16, port, now);
                int got;
                while ((got = sn_primary_recv(&g.dev, app, sizeof(app))) > 0) {
                    if (!t_first) { t_first = now; t_win = now; bytes = 0; win_bytes = 0; }
                    bytes += (uint64_t)got;
                    win_bytes += (uint64_t)got;
                    datagrams++;
                }
                break;
            }
            default: break;
            }
        }
        /* raw-UDP baseline: drain whatever is there */
        for (;;) {
            ssize_t rn = recv(rawfd, rawbuf, sizeof(rawbuf), 0);
            if (rn <= 0) break;
            if (!raw_t0) { raw_t0 = now; raw_last = now; raw_bytes = 0; }
            raw_bytes += (uint64_t)rn;
        }
        if (raw_t0 && now - raw_last >= 1000) {
            double r = (double)raw_bytes / (double)(now - raw_last) / 1000.0;
            printf("RAWUDP %.3f MB/s  (%.2f Mbit/s)\n", r, r * 8.0);
            fflush(stdout);
            raw_bytes = 0; raw_last = now;
        }

        /* 1-second reports */
        if (t_first && now - t_win >= 1000) {
            double mbps = (double)win_bytes / (double)(now - t_win) / 1000.0;
            /* DIAG: when the rate collapses, say what the session looks like —
             * is the primary gone, quiesced, its receive queue stuck, or are
             * datagrams arriving but failing to open? */
            unsigned rcvq = 0, rcvbuf = 0, sndq = 0, sndbuf = 0, dead = 0;
            int active = 0, quies = 0;
            if (g.dev.primary.active && g.dev.primary.kcp) {
                active = 1;
                rcvq = g.dev.primary.kcp->nrcv_que;
                rcvbuf = g.dev.primary.kcp->nrcv_buf;
                sndq = g.dev.primary.kcp->nsnd_que;
                sndbuf = g.dev.primary.kcp->nsnd_buf;
                dead = (g.dev.primary.kcp->state == (uint32_t)-1);
                quies = g.dev.primary.quiesced;
            }
            printf("RATE %.3f MB/s  (%.2f Mbit/s)  total %llu KB | dgrams=%llu "
                   "active=%d quiesced=%d dead=%u rcv_que=%u rcv_buf=%u snd_que=%u snd_buf=%u\n",
                   mbps, mbps * 8.0, (unsigned long long)(bytes / 1024),
                   (unsigned long long)datagrams, active, quies, dead,
                   rcvq, rcvbuf, sndq, sndbuf);
            fflush(stdout);
            win_bytes = 0; t_win = now;
        }
    }
}
