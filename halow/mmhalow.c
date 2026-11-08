/*
 * Copyright 2023-2025 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "mmhalow.h"
#include "esp_log.h"
#include "mmlog.h"
#include "mmutils.h"
#include <string.h>

static const char *TAG = "Morse Micro HaLow NetIF";

static esp_netif_t *halow_netif = NULL;

/* VIFs brought up through this API, used to address transmitted frames (see halow_tx_vif()). */
static volatile bool halow_sta_active;
static volatile bool halow_ap_active;
static volatile bool halow_relay_active;

static void mmhalow_link_state(enum mmwlan_link_state link_state, void *arg)
{
    esp_netif_t *esp_netif = (esp_netif_t *)arg;

    if (link_state == MMWLAN_LINK_DOWN)
    {
        ESP_LOGD(TAG, "Link down");
        esp_netif_action_disconnected(esp_netif, NULL, 0, NULL);
    }
    else
    {
        ESP_LOGD(TAG, "Link up");
        esp_netif_action_connected(esp_netif, NULL, 0, NULL);
    }
}

static void mmhalow_free(void *h, void *buffer)
{
    struct mmpktview *pktview = (struct mmpktview *)buffer;
    struct mmpkt *rxpkt = mmpkt_from_view(pktview);
    mmpkt_close(&pktview);
    mmpkt_release(rxpkt);
}

static void halow_rx(struct mmpkt *rxpkt, void *arg)
{
    esp_netif_t *esp_netif = (esp_netif_t *)arg;
    assert(esp_netif);

    struct mmpktview *pktview = mmpkt_open(rxpkt);
    uint32_t data_len = mmpkt_get_data_length(pktview);
    esp_err_t ret =
        esp_netif_receive(halow_netif, mmpkt_get_data_start(pktview), data_len, pktview);

    if (ret != ESP_OK)
    {
        /* esp_netif has already returned the buffer through mmhalow_free() on every error path
         * (netif down, no pbuf, tcpip input queue full), so it must not be released here. Doing
         * so freed the packet twice under heavy receive load. */
        ESP_LOGD(TAG, "esp_netif_receive failed - %d", ret);
    }
}

/*
 * mmwlan_tx_pkt() only infers the VIF for MMWLAN_VIF_UNSPECIFIED when exactly one VIF exists.
 * With both a STA and an AP VIF up (a relay repeater, or STA + AP) it fails with "Unable to infer
 * VIF ID" and drops the frame. Name the VIF of the role this netif was brought up for. If both
 * were started without relay, the netif follows the STA uplink.
 *
 * With relay enabled, umac_relay_update_tx_metadata() runs before that inference and rewrites
 * the VIF of every frame without an RA: to the AP VIF when the destination is an associated STA
 * or is behind a repeater (relay forwarding table), otherwise to the STA VIF. On a repeater or
 * relay STA that is the right routing whatever is passed here.
 */
static enum mmwlan_vif halow_tx_vif(void)
{
    if (halow_sta_active)
    {
        return MMWLAN_VIF_STA;
    }
    if (halow_ap_active)
    {
        return MMWLAN_VIF_AP;
    }
    return MMWLAN_VIF_UNSPECIFIED;
}

static esp_err_t halow_transmit(void *h, void *buffer, size_t len)
{
    struct mmpkt *pkt;
    struct mmpktview *pktview;
    enum mmwlan_status status;
    struct mmwlan_tx_metadata metadata = MMWLAN_TX_METADATA_INIT;
    uint8_t group_ra[MMWLAN_MAC_ADDR_LEN];

    metadata.vif = halow_tx_vif();

    /* On the relay root, umac_relay_update_tx_metadata() would move group-addressed frames
     * (ARP requests, DHCP, mDNS...) to the STA VIF, which the root does not have, so they are
     * dropped. An RA makes it leave the frame alone; the AP datapath maps a group RA to its
     * broadcast station, exactly as for a non-relay AP. */
    if (halow_relay_active &&
        metadata.vif == MMWLAN_VIF_AP &&
        len >= MMWLAN_MAC_ADDR_LEN &&
        mm_mac_addr_is_multicast((const uint8_t *)buffer))
    {
        memcpy(group_ra, buffer, sizeof(group_ra));
        metadata.ra = group_ra;
    }

    status = mmwlan_tx_wait_until_ready(1000);
    if (status != MMWLAN_SUCCESS)
    {
        ESP_LOGE(TAG, "Transmit blocked: %d", status);
        return ESP_FAIL;
    }

    pkt = mmwlan_alloc_mmpkt_for_tx(len, metadata.tid);
    if (pkt == NULL)
    {
        ESP_LOGE(TAG, "Failed to allocate packet for transmit.");
        return ESP_ERR_NO_MEM;
    }
    pktview = mmpkt_open(pkt);
    mmpkt_append_data(pktview, (const uint8_t *)buffer, len);
    mmpkt_close(&pktview);

    status = mmwlan_tx_pkt(pkt, &metadata);
    if (status != MMWLAN_SUCCESS)
    {
        ESP_LOGE(TAG, "Packet failed to send - %d", status);
        return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t halow_transmit_wrap(void *h, void *buffer, size_t len, void *netstack_buf)
{
    return halow_transmit(h, buffer, len);
}

static esp_err_t halow_driver_start(esp_netif_t *esp_netif, void *args)
{
    mmhalow_netif_driver_t *driver = (mmhalow_netif_driver_t *)args;
    driver->base.netif = esp_netif;
    esp_netif_driver_ifconfig_t driver_ifconfig = { .handle = driver,
                                                    .transmit = halow_transmit,
                                                    .transmit_wrap = halow_transmit_wrap,
                                                    .driver_free_rx_buffer = mmhalow_free };
    halow_netif = esp_netif;
    return esp_netif_set_driver_config(esp_netif, &driver_ifconfig);
}

static mmhalow_netif_driver_t *mmhalow_create_if_driver(void)
{
    mmhalow_netif_driver_t *driver = calloc(1, sizeof(mmhalow_netif_driver_t));
    if (driver == NULL)
    {
        ESP_LOGE(TAG, "No memory to create a Wi-Fi interface handle");
        return NULL;
    }
    driver->base.post_attach = halow_driver_start;

    /* Initialise the driver's sta_args structure */
    const struct mmwlan_sta_args sta_args = MMWLAN_STA_ARGS_INIT;
    memcpy(&driver->sta_args, &sta_args, sizeof(struct mmwlan_sta_args));

    return driver;
}

void mmhalow_print_version_info(void)
{
    enum mmwlan_status status;
    struct mmwlan_version version;
    struct mmwlan_bcf_metadata bcf_metadata;

    ESP_LOGI(TAG, "-----------------------------------");

    status = mmwlan_get_bcf_metadata(&bcf_metadata);
    if (status == MMWLAN_SUCCESS)
    {
        ESP_LOGI(TAG,
                 "  BCF API version:         %u.%u.%u",
                 bcf_metadata.version.major,
                 bcf_metadata.version.minor,
                 bcf_metadata.version.patch);
        if (bcf_metadata.build_version[0] != '\0')
        {
            ESP_LOGI(TAG, "  BCF build version:       %s", bcf_metadata.build_version);
        }
        if (bcf_metadata.board_desc[0] != '\0')
        {
            ESP_LOGI(TAG, "  BCF board description:   %s", bcf_metadata.board_desc);
        }
    }
    else
    {
        ESP_LOGE(TAG, "Error occured whilst retrieving BCF metadata - %d", status);
    }

    status = mmwlan_get_version(&version);
    if (status != MMWLAN_SUCCESS)
    {
        ESP_LOGE(TAG, "Error occured whilst retrieving version info - %d", status);
        ESP_LOGI(TAG, "-----------------------------------");
        return;
    }

    ESP_LOGI(TAG, "  Morselib version:        %s", version.morselib_version);
    ESP_LOGI(TAG, "  Morse firmware version:  %s", version.morse_fw_version);
    ESP_LOGI(TAG, "  Morse chip ID:           0x%04lx", version.morse_chip_id);
    ESP_LOGI(TAG, "-----------------------------------");
}

static void wifi_start(void *esp_netif)
{
    uint8_t mac[6];

    mmwlan_get_mac_addr(mac);
    ESP_LOGI(TAG, "Wi-Fi MAC address: " MM_MAC_ADDR_FMT, MM_MAC_ADDR_VAL(mac));

    esp_netif_set_mac(esp_netif, mac);
    esp_netif_action_start(esp_netif, NULL, 0, NULL);
}

esp_err_t mmhalow_init(const wifi_init_config_t *config)
{
    ESP_UNUSED(config);
    assert(halow_netif == NULL);

    /* Initialize Morse subsystems, note that they must be called in this order. */
    mmhal_init();
    mmwlan_init();

    const struct mmwlan_regulatory_db *db = get_regulatory_db();
    const struct mmwlan_s1g_channel_list *channel_list =
        mmwlan_lookup_regulatory_domain(db, CONFIG_HALOW_COUNTRY_CODE);
    ESP_LOGI(TAG, "Setting Channel List %s", CONFIG_HALOW_COUNTRY_CODE);
    mmwlan_set_channel_list(channel_list);

    /* Boot the WLAN interface so that we can retrieve the firmware version. */
    struct mmwlan_boot_args boot_args = MMWLAN_BOOT_ARGS_INIT;
    enum mmwlan_status boot_status = mmwlan_boot(&boot_args);
    if (boot_status != MMWLAN_SUCCESS)
    {
        /* There is no teardown path here, so treat this as fatal for the interface. */
        ESP_LOGE(TAG, "mmwlan_boot failed - %d, transceiver is not usable", boot_status);
        return ESP_FAIL;
    }
    mmhalow_print_version_info();
#if !CONFIG_HALOW_PS_MODE
    mmwlan_set_power_save_mode(MMWLAN_PS_DISABLED);
#endif /* CONFIG_HALOW_PS_MODE */

    enum mmwlan_status status;

    esp_netif_config_t cfg = ESP_NETIF_DEFAULT_WIFI_STA();
    esp_netif_t *netif = esp_netif_new(&cfg);
    assert(netif);
    mmhalow_netif_driver_t *driver = mmhalow_create_if_driver();

    esp_netif_attach(netif, driver);

    status = mmwlan_register_rx_pkt_cb(halow_rx, netif);
    assert(status == MMWLAN_SUCCESS);

    status = mmwlan_register_link_state_cb(mmhalow_link_state, netif);
    assert(status == MMWLAN_SUCCESS);

    wifi_start(netif);

    return status;
}

esp_err_t mmhalow_deinit()
{
    /* Shutdown wlan interface */
    return mmwlan_shutdown();
}

esp_err_t mmhalow_scan(struct mmhalow_scan_args *args)
{
    assert(args);
    struct mmwlan_scan_req scan_req = MMWLAN_SCAN_REQ_INIT;
    scan_req.scan_rx_cb = args->rx_cb;
    scan_req.scan_complete_cb = args->complete_cb;
    scan_req.scan_cb_arg = args->cb_arg;
    return mmwlan_scan_request(&scan_req);
}

/*
 * When passphrase_len is 0, morselib's STA path stores strlen(ssid) as the passphrase length
 * instead of the passphrase's (umac_connection.c), so SAE fails unless both happen to be the
 * same length. A repeater's relay AP also inherits that length. Fill it in from the
 * NUL-terminated passphrase. The AP path computes the length correctly.
 */
static void sta_args_fix_passphrase_len(struct mmwlan_sta_args *args)
{
    if (args->passphrase_len == 0)
    {
        /* An unterminated passphrase gives a length above MMWLAN_PASSPHRASE_MAXLEN, which
         * morselib still rejects. */
        args->passphrase_len = strnlen(args->passphrase, sizeof(args->passphrase));
    }
}

static void set_config_sta(struct mmwlan_sta_args *conf)
{
    mmhalow_netif_driver_t *morse_drv = esp_netif_get_io_driver(halow_netif);
    memcpy(&morse_drv->sta_args, conf, sizeof(*conf));
    sta_args_fix_passphrase_len(&morse_drv->sta_args);
}

static void set_config_ap(struct mmwlan_ap_args *conf)
{
    mmhalow_netif_driver_t *morse_drv = esp_netif_get_io_driver(halow_netif);
    assert(morse_drv);

    memcpy(&morse_drv->ap_args, conf, sizeof(*conf));
}

esp_err_t mmhalow_set_config(wifi_interface_t interface, mmhalow_wifi_config_t *conf)
{
    assert(conf);
    switch (interface)
    {
        case WIFI_IF_STA:
            set_config_sta(&conf->sta);
            break;
        case WIFI_IF_AP:
            set_config_ap(&conf->ap);
            break;
        default:
            return ESP_ERR_NOT_SUPPORTED;
    }
    return ESP_OK;
}

static void get_config_sta(struct mmwlan_sta_args *conf)
{
    mmhalow_netif_driver_t *morse_drv = esp_netif_get_io_driver(halow_netif);
    assert(morse_drv);

    (void)strlcpy((char *)conf->ssid,
                  (char *)morse_drv->sta_args.ssid,
                  sizeof(conf->ssid));

    /* We cannot safely copy password from sta_args.passphrase into conf->password because:
     * sta_args.passphrase == 100 bytes
     * conf->password == 64 bytes
     * GCC complains about truncation
     */
}

esp_err_t mmhalow_get_config(wifi_interface_t interface, mmhalow_wifi_config_t *conf)
{
    assert(conf);
    switch (interface)
    {
        case WIFI_IF_STA:
            get_config_sta(&conf->sta);
            break;
        case WIFI_IF_AP:
        default:
            return ESP_ERR_NOT_SUPPORTED;
    }
    return ESP_OK;
}

esp_err_t mmhalow_connect(mmwlan_sta_status_cb_t cb)
{
    mmhalow_netif_driver_t *morse_drv = esp_netif_get_io_driver(halow_netif);
    assert(morse_drv);

    ESP_LOGI(TAG, "Attempting to connect to: %s", morse_drv->sta_args.ssid);

    halow_sta_active = true;
    enum mmwlan_status status = mmwlan_sta_enable(&morse_drv->sta_args, cb);
    if (status != MMWLAN_SUCCESS)
    {
        halow_sta_active = false;
    }
    return status;
}

esp_err_t mmhalow_disconnect()
{
    halow_sta_active = false;
    return mmwlan_sta_disable();
}

enum mmwlan_status mmhalow_status()
{
    return mmwlan_get_sta_state();
}

void mmhalow_wifi_start(){
    mmhalow_netif_driver_t *morse_drv = esp_netif_get_io_driver(halow_netif);
    halow_ap_active = true;
    enum mmwlan_status status = mmwlan_ap_enable(&morse_drv->ap_args);
    if (status != MMWLAN_SUCCESS)
    {
        ESP_LOGE(TAG, "mmwlan_ap_enable failed - %d", status);
        halow_ap_active = false;
    }
}

esp_netif_t *mmhalow_get_netif(void)
{
    return halow_netif;
}

#if CONFIG_HALOW_RELAY_MODE
static esp_err_t mmhalow_err_from_status(enum mmwlan_status status)
{
    switch (status)
    {
        case MMWLAN_SUCCESS:
        case MMWLAN_SHUTDOWN_BLOCKED:
            return ESP_OK;
        case MMWLAN_INVALID_ARGUMENT:
            return ESP_ERR_INVALID_ARG;
        case MMWLAN_NO_MEM:
            return ESP_ERR_NO_MEM;
        case MMWLAN_TIMED_OUT:
            return ESP_ERR_TIMEOUT;
        case MMWLAN_NOT_FOUND:
            return ESP_ERR_NOT_FOUND;
        case MMWLAN_NOT_SUPPORTED:
            return ESP_ERR_NOT_SUPPORTED;
        case MMWLAN_UNAVAILABLE:
        case MMWLAN_NOT_RUNNING:
        case MMWLAN_NOT_INITIALIZED:
        case MMWLAN_CHANNEL_LIST_NOT_SET:
            return ESP_ERR_INVALID_STATE;
        default:
            return ESP_FAIL;
    }
}

/* While relay mode is enabled the netif link follows one VIF: the root AP on the root node, the
 * relay STA on any other node. A repeater's relay AP is managed by morselib and does not affect
 * the link of this node's own host. */
static enum mmwlan_vif relay_link_vif = MMWLAN_VIF_UNSPECIFIED;
static bool relay_link_up;

static void mmhalow_relay_vif_state(const struct mmwlan_vif_state *state, void *arg)
{
    bool up = (state->link_state == MMWLAN_LINK_UP);

    /* A relay STA reports link up both on association and when its parent advertises a path to
     * the root, so only act on changes. */
    if (state->vif != relay_link_vif || up == relay_link_up)
    {
        return;
    }
    relay_link_up = up;
    mmhalow_link_state(state->link_state, arg);
}

/* Hand the netif link back to the STA link callback that mmhalow_init() registered. */
static void mmhalow_relay_detach_link(void)
{
    mmwlan_register_vif_state_cb(MMWLAN_VIF_UNSPECIFIED, NULL, NULL);
    if (relay_link_up)
    {
        /* Relay teardown normally reports this; make sure the netif agrees if it did not. */
        mmhalow_link_state(MMWLAN_LINK_DOWN, halow_netif);
    }
    relay_link_vif = MMWLAN_VIF_UNSPECIFIED;
    relay_link_up = false;
    mmwlan_register_link_state_cb(mmhalow_link_state, halow_netif);
}
#endif /* CONFIG_HALOW_RELAY_MODE */

esp_err_t mmhalow_relay_enable(const struct mmwlan_relay_args *args)
{
#if CONFIG_HALOW_RELAY_MODE
    if (args == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }
    assert(halow_netif);

    /* morselib rejects a second enable, or one made after STA or AP mode was started, but its
     * failure path calls mmwlan_relay_disable(), which tears down whatever AP is running. Refuse
     * here instead, before the link callbacks or the role flags are touched. */
    if (halow_relay_active || halow_sta_active || halow_ap_active)
    {
        ESP_LOGE(TAG, "Relay must be enabled before STA/AP and only once");
        return ESP_ERR_INVALID_STATE;
    }

    bool is_root = (args->root_ap_args != NULL);

    /* Work on copies so the STA passphrase length can be fixed up without touching the
     * caller's structures; morselib copies them again during mmwlan_relay_enable(). */
    struct mmwlan_relay_args relay_args = *args;
    struct mmwlan_sta_args relay_sta_args;
    if (args->relay_sta_args != NULL)
    {
        relay_sta_args = *args->relay_sta_args;
        sta_args_fix_passphrase_len(&relay_sta_args);
        relay_args.relay_sta_args = &relay_sta_args;
    }

    /* The VIF state callbacks report everything the STA link callback does (it is invoked
     * alongside them) plus the relay STA losing or regaining its path to the root. Detach the
     * link callback so the STA link is not reported twice. */
    mmwlan_register_link_state_cb(NULL, NULL);
    relay_link_vif = is_root ? MMWLAN_VIF_AP : MMWLAN_VIF_STA;
    relay_link_up = false;
    mmwlan_register_vif_state_cb(MMWLAN_VIF_UNSPECIFIED, mmhalow_relay_vif_state, halow_netif);

    ESP_LOGI(TAG, "Enabling S1G relay (%s)", is_root ? "root" : "non-root");

    /* Set before enabling: the root's link (and lwip traffic) can come up before it returns.
     * Neither STA nor AP mode was active (checked above), so clear them again on failure. */
    halow_relay_active = true;
    if (is_root)
    {
        halow_ap_active = true;
    }
    else
    {
        halow_sta_active = true;
    }

    enum mmwlan_status status = mmwlan_relay_enable(&relay_args);
    if (status != MMWLAN_SUCCESS)
    {
        ESP_LOGE(TAG, "mmwlan_relay_enable failed - %d", status);
        halow_relay_active = false;
        halow_sta_active = false;
        halow_ap_active = false;
        mmhalow_relay_detach_link();
        return mmhalow_err_from_status(status);
    }
    return ESP_OK;
#else
    ESP_UNUSED(args);
    ESP_LOGE(TAG, "S1G relay support is disabled (CONFIG_HALOW_RELAY_MODE)");
    return ESP_ERR_NOT_SUPPORTED;
#endif /* CONFIG_HALOW_RELAY_MODE */
}

esp_err_t mmhalow_relay_disable(void)
{
#if CONFIG_HALOW_RELAY_MODE
    /* mmwlan_relay_disable() stops any running AP even when relay mode is not enabled, so leave
     * a plain STA or AP from mmhalow_connect() / mmhalow_wifi_start() alone. */
    if (!halow_relay_active)
    {
        return ESP_OK;
    }

    enum mmwlan_status status = mmwlan_relay_disable();
    if (status != MMWLAN_SUCCESS)
    {
        ESP_LOGE(TAG, "mmwlan_relay_disable failed - %d", status);
    }

    halow_relay_active = false;
    halow_sta_active = false;
    halow_ap_active = false;
    mmhalow_relay_detach_link();
    return mmhalow_err_from_status(status);
#else
    return ESP_ERR_NOT_SUPPORTED;
#endif /* CONFIG_HALOW_RELAY_MODE */
}
