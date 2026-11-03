/*
 * Copyright 2023-2025 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "esp_err.h"
#include "esp_netif.h"
#include "esp_wifi.h"

#include "mmhal_wlan.h"
#include "mmhal_os.h"
#include "mmpkt.h"
#include "mmwlan.h"
#include "mmwlan_stats.h"

#include "mmregdb.h"

typedef struct mmhalow_wifi_config_t{
    union {
        struct mmwlan_sta_args sta;
        struct mmwlan_ap_args ap;
    };
} mmhalow_wifi_config_t;

typedef struct mmhalow_netif_driver
{
    esp_netif_driver_base_t base;

    struct mmwlan_sta_args sta_args;
    struct mmwlan_ap_args ap_args;

    bool sta_conf_set;
} mmhalow_netif_driver_t;

struct mmhalow_scan_args
{
    mmwlan_scan_rx_cb_t rx_cb;
    mmwlan_scan_complete_cb_t complete_cb;
    void *cb_arg;
};

/**
 * Initialize the WLAN interface
 * @warning This must be called only once.
 */
esp_err_t mmhalow_init(const wifi_init_config_t *config);

/**
 * Shut down the WLAN interface
 */
esp_err_t mmhalow_deinit();

/**
 * Scans for APs
 */
esp_err_t mmhalow_scan(struct mmhalow_scan_args *args);

/**
 * Connect to an AP
 */
esp_err_t mmhalow_connect(mmwlan_sta_status_cb_t cb);

/**
 * Disconnect from an AP
 */
esp_err_t mmhalow_disconnect();

/**
 * Set the network configuration
 */
esp_err_t mmhalow_set_config(wifi_interface_t interface, mmhalow_wifi_config_t *conf);

/**
 * Get the network configuration
 */
esp_err_t mmhalow_get_config(wifi_interface_t interface, mmhalow_wifi_config_t *conf);

/**
 * Get the STA State
 */
enum mmwlan_status mmhalow_status();

/**
 * Print BCF/Firmware/Morselib version information
 */
void mmhalow_print_version_info(void);

/**
 * Start an AP interface
 */
void mmhalow_wifi_start();

/**
 * Get the esp_netif that carries HaLow traffic (created by mmhalow_init()).
 *
 * The interface is created as a DHCP client. A node that should use a static address, such as
 * an S1G relay root, can stop the DHCP client and set its address through this handle.
 */
esp_netif_t *mmhalow_get_netif(void);

/**
 * Enable S1G relay mode. Wraps mmwlan_relay_enable().
 *
 * @warning ALPHA NOTICE: The S1G Relay API is an alpha API that is under development; it is not
 *          intended for production use and breaking changes may be introduced.
 *
 * Exactly one role is selected by @p args (see struct mmwlan_relay_args in mmwlan.h):
 * - root: @c root_ap_args set. The netif link is up while the root AP is up.
 * - repeater / relay STA: @c relay_sta_args set, plus @c relay_ap_args for a repeater. The netif
 *   link follows the relay STA, including the relay network reporting that the path to the root
 *   was lost or recovered. @c sta_status_cb is passed through unchanged, and a zero
 *   @c relay_sta_args->passphrase_len is filled in from the passphrase (on a copy).
 *
 * STA and AP mode (mmhalow_connect(), mmhalow_wifi_start()) must not be active. The configuration
 * stored with mmhalow_set_config() is not used.
 *
 * @return ESP_OK on success, ESP_ERR_NOT_SUPPORTED if CONFIG_HALOW_RELAY_MODE is disabled,
 *         ESP_ERR_INVALID_ARG for invalid arguments, ESP_ERR_INVALID_STATE if relay, STA or AP
 *         mode is already active, or another error code on failure.
 */
esp_err_t mmhalow_relay_enable(const struct mmwlan_relay_args *args);

/**
 * Disable S1G relay mode. Wraps mmwlan_relay_disable(). Does nothing if relay mode was not
 * enabled with mmhalow_relay_enable(), so a STA or AP started outside relay mode is left running.
 *
 * @return ESP_OK on success, ESP_ERR_NOT_SUPPORTED if CONFIG_HALOW_RELAY_MODE is disabled, or
 *         another error code on failure.
 */
esp_err_t mmhalow_relay_disable(void);
