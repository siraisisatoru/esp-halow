/*
 * Copyright 2026 siraisisatoru
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * S1G relay root AP.
 *
 * Brings the HaLow interface up as the root node of an mm-iot-sdk S1G relay network, gives the
 * netif a static IPv4 address, logs relay and associated-station status, and optionally echoes
 * UDP datagrams so that a node behind a repeater can test the path end to end.
 */

#include <string.h>

#include "esp_log.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "mmhalow.h"
#include "mmutils.h"
#include "nvs_flash.h"

#define WIFI_SSID   CONFIG_WIFI_SSID
#define WIFI_PSK    CONFIG_WIFI_PSK
#define S1G_CHANNEL CONFIG_S1G_CHANNEL
#define S1G_OPCLASS CONFIG_S1G_OPCLASS

/* How often to log the relay status when nothing changes. */
#define STATUS_PERIOD_MS 30000

static const char *TAG = "relay_root";

enum relay_root_event_type
{
    EVENT_RELAY_STATUS,
    EVENT_AP_STA_STATUS,
};

struct relay_root_event
{
    enum relay_root_event_type type;

    union
    {
        struct mmwlan_relay_status relay;
        struct mmwlan_ap_sta_status sta;
    };
};

/* The morselib callbacks must not block or call mmwlan, so they only queue an event for
 * app_main() to log. */
static QueueHandle_t event_queue;

static void relay_status_cb(const struct mmwlan_relay_status *status, void *arg)
{
    struct relay_root_event evt = { .type = EVENT_RELAY_STATUS, .relay = *status };
    (void)arg;
    (void)xQueueSend(event_queue, &evt, 0);
}

static void ap_sta_status_cb(const struct mmwlan_ap_sta_status *sta_status, void *arg)
{
    struct relay_root_event evt = { .type = EVENT_AP_STA_STATUS, .sta = *sta_status };
    (void)arg;
    (void)xQueueSend(event_queue, &evt, 0);
}

static const char *relay_state_str(enum mmwlan_relay_state state)
{
    switch (state)
    {
        case MMWLAN_RELAY_STATE_DISABLED:
            return "disabled";
        case MMWLAN_RELAY_STATE_ROOT:
            return "root";
        case MMWLAN_RELAY_STATE_STA:
            return "station";
        case MMWLAN_RELAY_STATE_REPEATER:
            return "repeater";
    }
    return "unknown";
}

static const char *ap_sta_state_str(enum mmwlan_ap_sta_state state)
{
    switch (state)
    {
        case MMWLAN_AP_STA_UNKNOWN:
            return "gone";
        case MMWLAN_AP_STA_AUTHENTICATED:
            return "authenticated";
        case MMWLAN_AP_STA_ASSOCIATED:
            return "associated";
        case MMWLAN_AP_STA_AUTHORIZED:
            return "authorized";
    }
    return "unknown";
}

static void log_relay_status(const struct mmwlan_relay_status *status)
{
    if (status->depth == MMWLAN_RELAY_DEPTH_UNKNOWN)
    {
        ESP_LOGI(TAG, "Relay role: %s, depth: detached", relay_state_str(status->state));
    }
    else
    {
        ESP_LOGI(TAG, "Relay role: %s, depth: %u", relay_state_str(status->state), status->depth);
    }
}

static void log_periodic_status(void)
{
    struct mmwlan_relay_status status;
    if (mmwlan_relay_get_status(&status) == MMWLAN_SUCCESS)
    {
        log_relay_status(&status);
    }

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(mmhalow_get_netif(), &ip_info) == ESP_OK)
    {
        ESP_LOGI(TAG,
                 "IPv4 " IPSTR "/" IPSTR ", link %s",
                 IP2STR(&ip_info.ip),
                 IP2STR(&ip_info.netmask),
                 esp_netif_is_netif_up(mmhalow_get_netif()) ? "up" : "down");
    }
}

static void udp_echo_task(void *arg)
{
    const int port = CONFIG_RELAY_ROOT_UDP_ECHO_PORT;
    char buf[256];

    (void)arg;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0)
    {
        ESP_LOGE(TAG, "Unable to create UDP socket");
        vTaskDelete(NULL);
        return;
    }

    struct sockaddr_in local = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(sock, (struct sockaddr *)&local, sizeof(local)) < 0)
    {
        ESP_LOGE(TAG, "Unable to bind UDP port %d", port);
        close(sock);
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "UDP echo listening on port %d", port);

    while (true)
    {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        int len = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&peer, &peer_len);
        if (len < 0)
        {
            continue;
        }

        char peer_str[INET_ADDRSTRLEN];
        inet_ntoa_r(peer.sin_addr, peer_str, sizeof(peer_str));
        ESP_LOGI(TAG, "UDP %d bytes from %s:%u", len, peer_str, ntohs(peer.sin_port));
        (void)sendto(sock, buf, len, 0, (struct sockaddr *)&peer, peer_len);
    }
}

static void set_static_ip(esp_netif_t *netif)
{
    esp_netif_ip_info_t ip_info = { 0 };

    ip_info.ip.addr = esp_ip4addr_aton(CONFIG_RELAY_ROOT_IP_ADDR);
    ip_info.netmask.addr = esp_ip4addr_aton(CONFIG_RELAY_ROOT_NETMASK);

    /* The HaLow netif is created as a DHCP client, and the root has nothing to ask. */
    esp_err_t err = esp_netif_dhcpc_stop(netif);
    if (err != ESP_OK && err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED)
    {
        ESP_ERROR_CHECK(err);
    }
    ESP_ERROR_CHECK(esp_netif_set_ip_info(netif, &ip_info));
    ESP_LOGI(TAG, "Static IPv4 " IPSTR "/" IPSTR, IP2STR(&ip_info.ip), IP2STR(&ip_info.netmask));
}

void app_main(void)
{
    ESP_LOGI(TAG, "Booted. Initialising Wi-Fi HaLow Interface...");
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(esp_netif_init());

    event_queue = xQueueCreate(16, sizeof(struct relay_root_event));
    assert(event_queue != NULL);

    ESP_ERROR_CHECK(mmhalow_init(NULL));
    ESP_LOGI(TAG, "Wi-Fi HaLow Interface Initialised");

    set_static_ip(mmhalow_get_netif());

    if (mmwlan_register_relay_status_cb(relay_status_cb, NULL) != MMWLAN_SUCCESS)
    {
        ESP_LOGW(TAG, "Unable to register the relay status callback");
    }

    struct mmwlan_ap_args ap_args = MMWLAN_AP_ARGS_INIT;

    memcpy(ap_args.ssid, WIFI_SSID, strlen(WIFI_SSID));
    ap_args.ssid_len = strlen(WIFI_SSID);
    if (strlen(WIFI_PSK) > 0)
    {
        memcpy(ap_args.passphrase, WIFI_PSK, strlen(WIFI_PSK));
        ap_args.passphrase_len = strlen(WIFI_PSK);
        ap_args.security_type = MMWLAN_SAE;
        ap_args.pmf_mode = MMWLAN_PMF_REQUIRED;
    }
    else
    {
        ap_args.security_type = MMWLAN_OPEN;
        ap_args.pmf_mode = MMWLAN_PMF_DISABLED;
    }
    ap_args.s1g_chan_num = S1G_CHANNEL;
    ap_args.op_class = S1G_OPCLASS;
    ap_args.max_stas = CONFIG_RELAY_ROOT_MAX_STAS;
    ap_args.sta_status_cb = ap_sta_status_cb;

    struct mmwlan_relay_args relay_args = MMWLAN_RELAY_ARGS_INIT;
    relay_args.forwarding_table_size = CONFIG_RELAY_ROOT_FORWARDING_TABLE_SIZE;
    relay_args.root_ap_args = &ap_args;

    ESP_LOGI(TAG,
             "Starting relay root AP \"%s\" (%s) on S1G channel %d, op class %d",
             WIFI_SSID,
             ap_args.security_type == MMWLAN_SAE ? "SAE" : "open",
             S1G_CHANNEL,
             S1G_OPCLASS);
    ESP_ERROR_CHECK(mmhalow_relay_enable(&relay_args));

    uint8_t bssid[MMWLAN_MAC_ADDR_LEN];
    if (mmwlan_ap_get_bssid(bssid) == MMWLAN_SUCCESS)
    {
        ESP_LOGI(TAG, "Relay root AP up, BSSID " MM_MAC_ADDR_FMT, MM_MAC_ADDR_VAL(bssid));
    }

    if (CONFIG_RELAY_ROOT_UDP_ECHO_PORT != 0)
    {
        xTaskCreate(udp_echo_task, "udp_echo", 4096, NULL, 5, NULL);
    }

    while (true)
    {
        struct relay_root_event evt;
        if (xQueueReceive(event_queue, &evt, pdMS_TO_TICKS(STATUS_PERIOD_MS)) != pdTRUE)
        {
            log_periodic_status();
            continue;
        }

        switch (evt.type)
        {
            case EVENT_RELAY_STATUS:
                log_relay_status(&evt.relay);
                break;

            case EVENT_AP_STA_STATUS:
                ESP_LOGI(TAG,
                         "STA " MM_MAC_ADDR_FMT " (AID %u) %s",
                         MM_MAC_ADDR_VAL(evt.sta.mac_addr),
                         evt.sta.aid,
                         ap_sta_state_str(evt.sta.state));
                break;
        }
    }
}
