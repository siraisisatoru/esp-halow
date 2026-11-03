<!--
Copyright 2026 siraisisatoru

SPDX-License-Identifier: Apache-2.0
-->

# relay_root

Starts the **root AP** of an mm-iot-sdk S1G relay network. Uses SAE security when a
passphrase is set, with PMF required. The root gets a static IPv4 address. The example logs
relay status changes and stations associating with the root, and can echo UDP datagrams back
to their sender so that a node behind a repeater can test the path end to end.

> **ALPHA:** S1G Relay (`CONFIG_HALOW_RELAY_MODE`, `mmwlan_relay_*`) is an alpha API in the
> mm-iot-sdk. It is not intended for production use and may change incompatibly.

A typical topology:

```
  [STA "A"] ~~~ [repeater] ~~~ [root "B": this example]
                 MM6108-EKH05
                 SDK relay_mode
```

- **Repeater:** an MM6108-EKH05 running the mm-iot-sdk `examples/relay_mode` application,
  configured with the same SSID and passphrase (its defaults, `MorseMicro`/`12345678`, match
  this example) and the same country code. The repeater joins the root as a relay STA, then
  starts a relay AP with the same SSID, security and channel. Unless `wlan.ap_bssid` is set,
  the relay AP's BSSID is the repeater's MAC address with the locally administered bit
  (`0x02` of the first octet) flipped.
- **Station:** any HaLow STA that joins the repeater's relay AP. Because the root and the
  repeater advertise the same SSID, pin the STA to the repeater's BSSID
  (`mmwlan_sta_args.bssid`) when the root is also in range. The repeater announces stations
  behind it to the root, so the root can reach them.

The root has no DHCP server. Give the other nodes static addresses in the root's subnet
(default `192.168.12.0/24`, root `192.168.12.1`).

---

## Building
Set the target, layering in the board profile for your board/hat, then configure and
build. See [configs](../../configs/README.md) for the full `SDKCONFIG_DEFAULTS` usage.

Setting the Wi-Fi HaLow country code is required. In `menuconfig` it is under
`Wi-Fi HaLow Connection Manager → Country code to use for Wi-Fi HaLow`
(`CONFIG_HALOW_COUNTRY_CODE`). With `AU`, the default channel is a 2 MHz channel that is
valid in the selected Australian channelisation (`Regulatory Database`):

| Channelisation | `S1G_CHANNEL` | `S1G_OPCLASS` | Centre frequency |
| --- | --- | --- | --- |
| 802.11-2024 / REVMF (default) | 37 | 51 | 920.5 MHz |
| 802.11-2020 | 38 | 69 | 921 MHz |

Use the same channelisation on every node. The mm-iot-sdk uses REVMF by default.

For example, for a Seeed Studio XIAO ESP32-S3 paired with a XIAO Wi-Fi HaLow
(MM6108) hat:

    SDKCONFIG_DEFAULTS="sdkconfig.defaults;managed_components/morsemicro__halow/configs/sdkconfig.defaults.seeed_xiao_esp32s3-seeed_xiao_mm6108" \
        idf.py set-target esp32s3
    idf.py menuconfig build   # set the country code (required)

`sdkconfig.defaults` enables `CONFIG_HALOW_AP_MODE` and `CONFIG_HALOW_RELAY_MODE`. It also
sizes packet memory as the SDK's relay_mode application does: 40 TX/RX blocks and 4 blocks
reserved for management frames (`CONFIG_MMPKTMEM_TX_MGMT_POOL_N_BLOCKS`).

## Running
Flash and open the serial monitor:

    idf.py flash monitor

The root logs its BSSID once the AP is up, then logs relay status, station association
events, and every 30 s its relay role and IPv4 state:

    I (...) relay_root: Relay root AP up, BSSID 02:..:..:..:..:..
    I (...) relay_root: Relay role: root, depth: 0
    I (...) relay_root: STA xx:xx:xx:xx:xx:xx (AID 1) authorized

From a node behind the repeater, `ping 192.168.12.1` or send UDP to port 12345 (the
`sta_connect` example sends there by default). The root echoes each datagram back.

## Configuration
Options under `HaLow relay_root Example Configuration` (`idf.py menuconfig`):

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `CONFIG_WIFI_SSID` | string | `"MorseMicro"` | SSID of the relay network. |
| `CONFIG_WIFI_PSK` | string | `"12345678"` | SAE passphrase; leave empty for an open network. |
| `CONFIG_S1G_CHANNEL` | int | 37 (AU), 44 | S1G channel of the root AP. |
| `CONFIG_S1G_OPCLASS` | int | 51 (AU), 71 | Global operating class of the channel. |
| `CONFIG_RELAY_ROOT_MAX_STAS` | int | 4 | Stations that may associate with the root directly. |
| `CONFIG_RELAY_ROOT_FORWARDING_TABLE_SIZE` | int | 0 (64) | Relay forwarding table entries, one per node behind a repeater. |
| `CONFIG_RELAY_ROOT_IP_ADDR` | string | `"192.168.12.1"` | Static IPv4 address of the root. |
| `CONFIG_RELAY_ROOT_NETMASK` | string | `"255.255.255.0"` | IPv4 netmask. |
| `CONFIG_RELAY_ROOT_UDP_ECHO_PORT` | int | 12345 | UDP echo port; 0 disables the echo server. |

The channel and operating class must be valid for the configured country code.
