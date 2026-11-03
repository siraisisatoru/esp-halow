/*
 * crypto wrapper functions for mbed TLS
 *
 * Adapted from: https://github.com/gstrauss/hostap/blob/mbedtls/src/crypto/crypto_mbedtls.c
 * (revision 216d856f0a3e0702ec9134572a0ab5d3580a70e5).
 *
 * Ported to mbedTLS 4.x / TF-PSA-Crypto 1.x (ESP-IDF >= 6.0). Hashes, HMAC, CMAC, AES-ECB,
 * PBKDF2, ECDH and random numbers use the PSA Crypto API. Bignum and EC point arithmetic (used by
 * SAE, including H2E) still use the legacy mbedtls_mpi / mbedtls_ecp API, which mbedTLS 4 only
 * exposes through its private headers; this mirrors ESP-IDF's own wpa_supplicant crypto port
 * (components/wpa_supplicant/esp_supplicant/src/crypto/crypto_mbedtls*.c).
 *
 * PSA Crypto is initialised by ESP-IDF at startup (mbedtls_psa_crypto_init_fn in
 * components/mbedtls/port/esp_psa_crypto_init.c), before app_main() runs.
 *
 * SPDX-FileCopyrightText: 2022 Glenn Strauss <gstrauss@gluelogic.com>
 * SPDX-FileCopyrightText: 2024 Morse Micro
 * SPDX-FileCopyrightText: 2026 siraisisatoru
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* Required for the mbedtls_mpi / mbedtls_ecp structure members used below. */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include <endian.h>
#include <stdbool.h>
#include <string.h>

#include <mbedtls/version.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/psa_util.h>
#include <psa/crypto.h>

/* Note: this header includes #defines to adjust the names of the global functions in this file
 * to be in the mmint_ namespace to avoid namespace conflicts. */
#include "hostap_morse_common.h"

#include "mmutils.h"
#include "mmosal.h"

#pragma GCC diagnostic ignored "-Wc++-compat"
#pragma GCC diagnostic ignored "-Wunused-parameter"

#define SHA1_MAC_LEN   (20)
#define AES_BLOCK_SIZE (16)

static mbedtls_mpi mpi_sw_A;

#ifdef CRYPTO_MBEDTLS_DEBUG
#define wpa_printf(_lvl, ...) printf(__VA_ARGS__)
#else
#define wpa_printf(_lvl, ...) \
    do {                      \
    } while (0)
#endif

#if MBEDTLS_VERSION_MAJOR < 4
#error mbedtls 4.0.0 or greater required (ESP-IDF >= 6.0)
#endif

#ifndef PSA_WANT_ALG_SHA_1
#error PSA_WANT_ALG_SHA_1 required
#endif

#ifndef PSA_WANT_ALG_SHA_256
#error PSA_WANT_ALG_SHA_256 required
#endif

#ifndef PSA_WANT_ALG_SHA_384
#error PSA_WANT_ALG_SHA_384 required
#endif

#ifndef PSA_WANT_ALG_SHA_512
#error PSA_WANT_ALG_SHA_512 required
#endif

#ifndef PSA_WANT_ALG_HMAC
#error PSA_WANT_ALG_HMAC required
#endif

#ifndef PSA_WANT_ALG_CMAC
#error PSA_WANT_ALG_CMAC required (CONFIG_MBEDTLS_CMAC_C)
#endif

#ifndef PSA_WANT_ALG_PBKDF2_HMAC
#error PSA_WANT_ALG_PBKDF2_HMAC required (WPA2-PSK)
#endif

#ifndef PSA_WANT_ALG_ECB_NO_PADDING
#error PSA_WANT_ALG_ECB_NO_PADDING required
#endif

#ifndef PSA_WANT_ALG_ECDH
#error PSA_WANT_ALG_ECDH required (CONFIG_MBEDTLS_ECDH_C)
#endif

#ifndef MBEDTLS_ECP_DP_SECP256R1_ENABLED
#error MBEDTLS_ECP_DP_SECP256R1_ENABLED required (SAE/OWE group 19)
#endif

/*
 * The following code is extracted from src/utils/const_time.h
 *
 * Copyright (c) 2019, The Linux Foundation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

/**
 * const_time_fill_msb - Fill all bits with MSB value
 * @val: Input value
 * Returns: Value with all the bits set to the MSB of the input val
 */
static inline unsigned int const_time_fill_msb(unsigned int val)
{
    /* Move the MSB to LSB and multiple by -1 to fill in all bits. */
    return (val >> (sizeof(val) * 8 - 1)) * ~0U;
}

/* Returns: -1 if val is zero; 0 if val is not zero */
static inline unsigned int const_time_is_zero(unsigned int val)
{
    /* Set MSB to 1 for 0 and fill rest of bits with the MSB value */
    return const_time_fill_msb(~val & (val - 1));
}

/* Returns: -1 if a == b; 0 if a != b */
static inline unsigned int const_time_eq(unsigned int a, unsigned int b)
{
    return const_time_is_zero(a ^ b);
}

/* Returns: -1 if a == b; 0 if a != b */
static inline uint8_t const_time_eq_u8(unsigned int a, unsigned int b)
{
    return (uint8_t)const_time_eq(a, b);
}

/**
 * const_time_select - Constant time unsigned int selection
 * @mask: 0 (false) or -1 (true) to identify which value to select
 * @true_val: Value to select for the true case
 * @false_val: Value to select for the false case
 * Returns: true_val if mask == -1, false_val if mask == 0
 */
static inline unsigned int const_time_select(unsigned int mask,
                                             unsigned int true_val,
                                             unsigned int false_val)
{
    return (mask & true_val) | (~mask & false_val);
}

/**
 * const_time_select_int - Constant time int selection
 * @mask: 0 (false) or -1 (true) to identify which value to select
 * @true_val: Value to select for the true case
 * @false_val: Value to select for the false case
 * Returns: true_val if mask == -1, false_val if mask == 0
 */
static inline int const_time_select_int(unsigned int mask, int true_val, int false_val)
{
    return (int)const_time_select(mask, (unsigned int)true_val, (unsigned int)false_val);
}

/* End of code extracted from src/utils/const_time.c */

/*
 * The following code is extracted from src/utils/wpabuf.h
 *
 * Copyright (c) 2007-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
struct wpabuf
{
    size_t size; /* total size of the allocated buffer */
    size_t used; /* length of data in the buffer */
    uint8_t *buf; /* pointer to the head of the buffer */
    unsigned int flags;
    /* optionally followed by the allocated buffer */
};

struct wpabuf *wpabuf_alloc(size_t len);

struct wpabuf *wpabuf_alloc_copy(const void *data, size_t len);

void *wpabuf_put(struct wpabuf *buf, size_t len);

void wpabuf_clear_free(struct wpabuf *buf);

static inline void *wpabuf_mhead(struct wpabuf *buf)
{
    return buf->buf;
}

/* End of code extracted from src/utils/wpabuf.c */

/*
 * Random number generation.
 *
 * The PSA RNG (seeded by ESP-IDF from the hardware RNG) replaces the file-local CTR_DRBG that
 * was seeded from mmhal_random_u32(). mbedtls_psa_get_random() is the f_rng callback for the
 * legacy bignum/ECP functions that need one.
 */
#define CRYPTO_MBEDTLS_F_RNG mbedtls_psa_get_random
#define CRYPTO_MBEDTLS_P_RNG MBEDTLS_PSA_RANDOM_STATE

void crypto_unload(void)
{
    mbedtls_mpi_free(&mpi_sw_A);
}

int crypto_get_random(void *buf, size_t len)
{
    return psa_generate_random(buf, len) == PSA_SUCCESS ? 0 : -1;
}

/* sha1.c sha256.c sha384.c sha512.c */

static int digest_vector(psa_algorithm_t alg,
                         size_t num_elem,
                         const uint8_t *addr[],
                         const size_t *len,
                         uint8_t *mac)
{
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    psa_status_t status = psa_hash_setup(&op, alg);
    for (size_t i = 0; i < num_elem && status == PSA_SUCCESS; ++i)
    {
        status = psa_hash_update(&op, addr[i], len[i]);
    }
    if (status == PSA_SUCCESS)
    {
        size_t mac_len;
        status = psa_hash_finish(&op, mac, PSA_HASH_LENGTH(alg), &mac_len);
    }
    psa_hash_abort(&op);
    return status == PSA_SUCCESS ? 0 : -1;
}

int sha512_vector(size_t num_elem, const uint8_t *addr[], const size_t *len, uint8_t *mac)
{
    return digest_vector(PSA_ALG_SHA_512, num_elem, addr, len, mac);
}

int sha384_vector(size_t num_elem, const uint8_t *addr[], const size_t *len, uint8_t *mac)
{
    return digest_vector(PSA_ALG_SHA_384, num_elem, addr, len, mac);
}

int sha256_vector(size_t num_elem, const uint8_t *addr[], const size_t *len, uint8_t *mac)
{
    return digest_vector(PSA_ALG_SHA_256, num_elem, addr, len, mac);
}

int sha1_vector(size_t num_elem, const uint8_t *addr[], const size_t *len, uint8_t *mac)
{
    return digest_vector(PSA_ALG_SHA_1, num_elem, addr, len, mac);
}

/* HMAC (RFC 2104) on top of PSA MAC. */

/**
 * hmac_import_key - Import an HMAC key into a volatile PSA key slot
 * @hash_alg: PSA hash algorithm (e.g. PSA_ALG_SHA_256)
 * @key: Key
 * @key_len: Length of the key in bytes; may be 0
 * @key_id: Returns the imported key
 * Returns: PSA status
 *
 * PSA does not accept zero-length keys, but mbedtls_md_hmac_starts() did. HMAC pads the key with
 * zero octets up to the hash block size, so an empty key and a single zero octet key produce the
 * same MAC; use the latter for key_len == 0.
 */
static psa_status_t hmac_import_key(psa_algorithm_t hash_alg,
                                    const uint8_t *key,
                                    size_t key_len,
                                    psa_key_id_t *key_id)
{
    static const uint8_t zero_key[1] = { 0 };
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(hash_alg));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    if (key_len == 0)
    {
        key = zero_key;
        key_len = sizeof(zero_key);
    }
    psa_status_t status = psa_import_key(&attributes, key, key_len, key_id);
    psa_reset_key_attributes(&attributes);
    return status;
}

static psa_status_t hmac_compute(psa_key_id_t key_id,
                                 psa_algorithm_t hash_alg,
                                 size_t num_elem,
                                 const uint8_t *const addr[],
                                 const size_t *len,
                                 uint8_t *mac)
{
    psa_mac_operation_t op = PSA_MAC_OPERATION_INIT;
    psa_status_t status = psa_mac_sign_setup(&op, key_id, PSA_ALG_HMAC(hash_alg));
    for (size_t i = 0; i < num_elem && status == PSA_SUCCESS; ++i)
    {
        status = psa_mac_update(&op, addr[i], len[i]);
    }
    if (status == PSA_SUCCESS)
    {
        size_t mac_len;
        status = psa_mac_sign_finish(&op, mac, PSA_HASH_LENGTH(hash_alg), &mac_len);
    }
    psa_mac_abort(&op);
    return status;
}

static int hmac_vector(const uint8_t *key,
                       size_t key_len,
                       size_t num_elem,
                       const uint8_t *addr[],
                       const size_t *len,
                       uint8_t *mac,
                       psa_algorithm_t hash_alg)
{
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t status = hmac_import_key(hash_alg, key, key_len, &key_id);
    if (status == PSA_SUCCESS)
    {
        status = hmac_compute(key_id, hash_alg, num_elem, addr, len, mac);
    }
    psa_destroy_key(key_id);
    return status == PSA_SUCCESS ? 0 : -1;
}

int hmac_sha512_vector(const uint8_t *key,
                       size_t key_len,
                       size_t num_elem,
                       const uint8_t *addr[],
                       const size_t *len,
                       uint8_t *mac)
{
    return hmac_vector(key, key_len, num_elem, addr, len, mac, PSA_ALG_SHA_512);
}

int hmac_sha512(const uint8_t *key,
                size_t key_len,
                const uint8_t *data,
                size_t data_len,
                uint8_t *mac)
{
    return hmac_vector(key, key_len, 1, &data, &data_len, mac, PSA_ALG_SHA_512);
}

int hmac_sha384_vector(const uint8_t *key,
                       size_t key_len,
                       size_t num_elem,
                       const uint8_t *addr[],
                       const size_t *len,
                       uint8_t *mac)
{
    return hmac_vector(key, key_len, num_elem, addr, len, mac, PSA_ALG_SHA_384);
}

int hmac_sha384(const uint8_t *key,
                size_t key_len,
                const uint8_t *data,
                size_t data_len,
                uint8_t *mac)
{
    return hmac_vector(key, key_len, 1, &data, &data_len, mac, PSA_ALG_SHA_384);
}

int hmac_sha256_vector(const uint8_t *key,
                       size_t key_len,
                       size_t num_elem,
                       const uint8_t *addr[],
                       const size_t *len,
                       uint8_t *mac)
{
    return hmac_vector(key, key_len, num_elem, addr, len, mac, PSA_ALG_SHA_256);
}

int hmac_sha256(const uint8_t *key,
                size_t key_len,
                const uint8_t *data,
                size_t data_len,
                uint8_t *mac)
{
    return hmac_vector(key, key_len, 1, &data, &data_len, mac, PSA_ALG_SHA_256);
}

int hmac_sha1_vector(const uint8_t *key,
                     size_t key_len,
                     size_t num_elem,
                     const uint8_t *addr[],
                     const size_t *len,
                     uint8_t *mac)
{
    return hmac_vector(key, key_len, num_elem, addr, len, mac, PSA_ALG_SHA_1);
}

int hmac_sha1(const uint8_t *key,
              size_t key_len,
              const uint8_t *data,
              size_t data_len,
              uint8_t *mac)
{
    return hmac_vector(key, key_len, 1, &data, &data_len, mac, PSA_ALG_SHA_1);
}

int hmac_md5(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *mac)
{
    /* Not needed for WPA3. */
    return -1;
}

/* sha256-prf.c sha384-prf.c sha512-prf.c */

/* hmac_prf_bits - IEEE Std 802.11ac-2013, 11.6.1.7.2 Key derivation function */
static int hmac_prf_bits(const uint8_t *key,
                         size_t key_len,
                         const char *label,
                         const uint8_t *data,
                         size_t data_len,
                         uint8_t *buf,
                         size_t buf_len_bits,
                         psa_algorithm_t hash_alg)
{
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    if (hmac_import_key(hash_alg, key, key_len, &key_id) != PSA_SUCCESS)
    {
        return -1;
    }

    /* The counter and the length are both little-endian 16-bit values. */
    uint8_t ctr_le[2];
    uint8_t n_le[2] = { (uint8_t)buf_len_bits, (uint8_t)(buf_len_bits >> 8) };
    const uint8_t *const addr[] = { ctr_le, (uint8_t *)label, data, n_le };
    const size_t len[] = { 2, strlen(label), data_len, 2 };
    const size_t mac_len = PSA_HASH_LENGTH(hash_alg);
    size_t buf_len = (buf_len_bits + 7) / 8;
    uint16_t ctr;
    psa_status_t status = PSA_SUCCESS;
    for (ctr = 1; buf_len >= mac_len && status == PSA_SUCCESS; buf_len -= mac_len, ++ctr)
    {
        ctr_le[0] = (uint8_t)ctr;
        ctr_le[1] = (uint8_t)(ctr >> 8);
        status = hmac_compute(key_id, hash_alg, MM_ARRAY_COUNT(addr), addr, len, buf);
        buf += mac_len;
    }

    if (buf_len && status == PSA_SUCCESS)
    {
        uint8_t hash[PSA_HASH_MAX_SIZE];
        ctr_le[0] = (uint8_t)ctr;
        ctr_le[1] = (uint8_t)(ctr >> 8);
        status = hmac_compute(key_id, hash_alg, MM_ARRAY_COUNT(addr), addr, len, hash);
        memcpy(buf, hash, buf_len);
        buf += buf_len;
        mbedtls_platform_zeroize(hash, mac_len);
    }

    psa_destroy_key(key_id);
    if (status != PSA_SUCCESS)
    {
        return -1;
    }

    /* Mask out unused bits in last octet if it does not use all the bits */
    if ((buf_len_bits &= 0x7))
    {
        buf[-1] &= (uint8_t)(0xff << (8 - buf_len_bits));
    }

    return 0;
}

int sha512_prf(const uint8_t *key,
               size_t key_len,
               const char *label,
               const uint8_t *data,
               size_t data_len,
               uint8_t *buf,
               size_t buf_len)
{
    return hmac_prf_bits(key, key_len, label, data, data_len, buf, buf_len * 8, PSA_ALG_SHA_512);
}

int sha384_prf(const uint8_t *key,
               size_t key_len,
               const char *label,
               const uint8_t *data,
               size_t data_len,
               uint8_t *buf,
               size_t buf_len)
{
    return hmac_prf_bits(key, key_len, label, data, data_len, buf, buf_len * 8, PSA_ALG_SHA_384);
}

int sha256_prf(const uint8_t *key,
               size_t key_len,
               const char *label,
               const uint8_t *data,
               size_t data_len,
               uint8_t *buf,
               size_t buf_len)
{
    return hmac_prf_bits(key, key_len, label, data, data_len, buf, buf_len * 8, PSA_ALG_SHA_256);
}

int sha256_prf_bits(const uint8_t *key,
                    size_t key_len,
                    const char *label,
                    const uint8_t *data,
                    size_t data_len,
                    uint8_t *buf,
                    size_t buf_len_bits)
{
    return hmac_prf_bits(key, key_len, label, data, data_len, buf, buf_len_bits, PSA_ALG_SHA_256);
}

/* sha1-prf.c */

/* sha1_prf - SHA1-based Pseudo-Random Function (PRF) (IEEE 802.11i, 8.5.1.1) */

int sha1_prf(const uint8_t *key,
             size_t key_len,
             const char *label,
             const uint8_t *data,
             size_t data_len,
             uint8_t *buf,
             size_t buf_len)
{
    /*(note: algorithm differs from hmac_prf_bits() */
    /*(note: smaller code size instead of expanding hmac_sha1_vector()
     * as is done in hmac_prf_bits(); not expecting large num of loops) */
    uint8_t counter = 0;
    const uint8_t *addr[] = { (uint8_t *)label, data, &counter };
    const size_t len[] = { strlen(label) + 1, data_len, 1 };

    for (; buf_len >= SHA1_MAC_LEN; buf_len -= SHA1_MAC_LEN, ++counter)
    {
        if (hmac_sha1_vector(key, key_len, 3, addr, len, buf))
        {
            return -1;
        }
        buf += SHA1_MAC_LEN;
    }

    if (buf_len)
    {
        uint8_t hash[SHA1_MAC_LEN];
        if (hmac_sha1_vector(key, key_len, 3, addr, len, hash))
        {
            return -1;
        }
        memcpy(buf, hash, buf_len);
        mbedtls_platform_zeroize(hash, sizeof(hash));
    }

    return 0;
}

int pbkdf2_sha1(const char *passphrase,
                const uint8_t *ssid,
                size_t ssid_len,
                int iterations,
                uint8_t *buf,
                size_t buflen)
{
    if (iterations <= 0)
    {
        return -1;
    }

    /* PSA requires the inputs in this order: cost, salt, password. */
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t status = psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_1));
    if (status == PSA_SUCCESS)
    {
        status = psa_key_derivation_input_integer(&op,
                                                  PSA_KEY_DERIVATION_INPUT_COST,
                                                  (uint64_t)iterations);
    }
    if (status == PSA_SUCCESS)
    {
        status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, ssid, ssid_len);
    }
    if (status == PSA_SUCCESS)
    {
        status = psa_key_derivation_input_bytes(&op,
                                                PSA_KEY_DERIVATION_INPUT_PASSWORD,
                                                (const uint8_t *)passphrase,
                                                strlen(passphrase));
    }
    if (status == PSA_SUCCESS)
    {
        status = psa_key_derivation_output_bytes(&op, buf, buflen);
    }
    psa_key_derivation_abort(&op);
    return status == PSA_SUCCESS ? 0 : -1;
}

/* AES-ECB single block operations. The context is a heap allocated PSA key id. */

static void *aes_crypt_init(psa_key_usage_t usage, const uint8_t *key, size_t len)
{
    psa_key_id_t *key_id = mmosal_malloc(sizeof(*key_id));
    if (!key_id)
    {
        return NULL;
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, usage);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECB_NO_PADDING);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, len * 8);
    psa_status_t status = psa_import_key(&attributes, key, len, key_id);
    psa_reset_key_attributes(&attributes);
    if (status == PSA_SUCCESS)
    {
        return key_id;
    }

    mmosal_free(key_id);
    return NULL;
}

static int aes_crypt(void *ctx, bool encrypt, const uint8_t *in, uint8_t *out)
{
    psa_key_id_t *key_id = ctx;
    psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
    size_t out_len = 0;
    size_t finish_len = 0;
    psa_status_t status = encrypt ? psa_cipher_encrypt_setup(&op, *key_id, PSA_ALG_ECB_NO_PADDING) :
                                    psa_cipher_decrypt_setup(&op, *key_id, PSA_ALG_ECB_NO_PADDING);
    if (status == PSA_SUCCESS)
    {
        status = psa_cipher_update(&op, in, AES_BLOCK_SIZE, out, AES_BLOCK_SIZE, &out_len);
    }
    if (status == PSA_SUCCESS)
    {
        status = psa_cipher_finish(&op, out + out_len, AES_BLOCK_SIZE - out_len, &finish_len);
    }
    psa_cipher_abort(&op);
    return (status == PSA_SUCCESS && out_len + finish_len == AES_BLOCK_SIZE) ? 0 : -1;
}

static void aes_crypt_deinit(void *ctx)
{
    if (ctx)
    {
        psa_destroy_key(*(psa_key_id_t *)ctx);
        mmosal_free(ctx);
    }
}

void *aes_decrypt_init(const uint8_t *key, size_t len)
{
    return aes_crypt_init(PSA_KEY_USAGE_DECRYPT, key, len);
}

int aes_decrypt(void *ctx, const uint8_t *crypt, uint8_t *plain)
{
    return aes_crypt(ctx, false, crypt, plain);
}

void aes_decrypt_deinit(void *ctx)
{
    aes_crypt_deinit(ctx);
}

void *aes_encrypt_init(const uint8_t *key, size_t len)
{
    return aes_crypt_init(PSA_KEY_USAGE_ENCRYPT, key, len);
}

int aes_encrypt(void *ctx, const uint8_t *plain, uint8_t *crypt)
{
    return aes_crypt(ctx, true, plain, crypt);
}

void aes_encrypt_deinit(void *ctx)
{
    aes_crypt_deinit(ctx);
}

/* AES-CMAC (OMAC1) */

int omac1_aes_vector(const uint8_t *key,
                     size_t key_len,
                     size_t num_elem,
                     const uint8_t *addr[],
                     const size_t *len,
                     uint8_t *mac)
{
    if (key_len != 16 && key_len != 24 && key_len != 32)
    {
        return -1;
    }

    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_CMAC);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, key_len * 8);
    psa_status_t status = psa_import_key(&attributes, key, key_len, &key_id);
    psa_reset_key_attributes(&attributes);

    psa_mac_operation_t op = PSA_MAC_OPERATION_INIT;
    if (status == PSA_SUCCESS)
    {
        status = psa_mac_sign_setup(&op, key_id, PSA_ALG_CMAC);
    }
    for (size_t i = 0; i < num_elem && status == PSA_SUCCESS; ++i)
    {
        status = psa_mac_update(&op, addr[i], len[i]);
    }
    if (status == PSA_SUCCESS)
    {
        size_t mac_len;
        status = psa_mac_sign_finish(&op, mac, AES_BLOCK_SIZE, &mac_len);
    }
    psa_mac_abort(&op);
    psa_destroy_key(key_id);
    return status == PSA_SUCCESS ? 0 : -1;
}

int omac1_aes_128(const uint8_t *key, const uint8_t *data, size_t data_len, uint8_t *mac)
{
    return omac1_aes_vector(key, 16, 1, &data, &data_len, mac);
}

/* crypto.h bignum interfaces */

struct crypto_bignum *crypto_bignum_init(void)
{
    mbedtls_mpi *bn = mmosal_malloc(sizeof(*bn));
    if (bn)
    {
        mbedtls_mpi_init(bn);
    }
    return (struct crypto_bignum *)bn;
}

struct crypto_bignum *crypto_bignum_init_set(const uint8_t *buf, size_t len)
{
    mbedtls_mpi *bn = mmosal_malloc(sizeof(*bn));
    if (bn)
    {
        mbedtls_mpi_init(bn);
        if (mbedtls_mpi_read_binary(bn, buf, len) == 0)
        {
            return (struct crypto_bignum *)bn;
        }
    }

    mmosal_free(bn);
    return NULL;
}

struct crypto_bignum *crypto_bignum_init_uint(unsigned int val)
{
    mbedtls_mpi *bn = mmosal_malloc(sizeof(*bn));
    if (bn)
    {
        mbedtls_mpi_init(bn);
        if (mbedtls_mpi_lset(bn, (int)val) == 0)
        {
            return (struct crypto_bignum *)bn;
        }
    }

    mmosal_free(bn);
    return NULL;
}

void crypto_bignum_deinit(struct crypto_bignum *n, int clear)
{
    mbedtls_mpi_free((mbedtls_mpi *)n);
    mmosal_free(n);
}

int crypto_bignum_to_bin(const struct crypto_bignum *a, uint8_t *buf, size_t buflen, size_t padlen)
{
    size_t n = mbedtls_mpi_size((mbedtls_mpi *)a);
    if (n < padlen)
    {
        n = padlen;
    }
    bool error = (n > buflen || mbedtls_mpi_write_binary((mbedtls_mpi *)a, buf, n));
    return error ? -1 : (int)(n);
}

int crypto_bignum_rand(struct crypto_bignum *r, const struct crypto_bignum *m)
{
    /*assert(r != m);*/ /* r must not be same as m for mbedtls_mpi_random()*/
    return mbedtls_mpi_random((mbedtls_mpi *)r,
                              0,
                              (mbedtls_mpi *)m,
                              CRYPTO_MBEDTLS_F_RNG,
                              CRYPTO_MBEDTLS_P_RNG) ?
               -1 :
               0;
}

int crypto_bignum_add(const struct crypto_bignum *a,
                      const struct crypto_bignum *b,
                      struct crypto_bignum *c)
{
    return mbedtls_mpi_add_mpi((mbedtls_mpi *)c, (const mbedtls_mpi *)a, (const mbedtls_mpi *)b) ?
               -1 :
               0;
}

int crypto_bignum_mod(const struct crypto_bignum *a,
                      const struct crypto_bignum *b,
                      struct crypto_bignum *c)
{
    return mbedtls_mpi_mod_mpi((mbedtls_mpi *)c, (const mbedtls_mpi *)a, (const mbedtls_mpi *)b) ?
               -1 :
               0;
}

int crypto_bignum_exptmod(const struct crypto_bignum *a,
                          const struct crypto_bignum *b,
                          const struct crypto_bignum *c,
                          struct crypto_bignum *d)
{
    /* (check if input params match d; d is the result) */
    /* (a == d) is ok in current mbedtls implementation */
    if (b == d || c == d) /*(not ok; store result in intermediate)*/
    {
        mbedtls_mpi R;
        mbedtls_mpi_init(&R);
        int rc = mbedtls_mpi_exp_mod(&R,
                                     (const mbedtls_mpi *)a,
                                     (const mbedtls_mpi *)b,
                                     (const mbedtls_mpi *)c,
                                     NULL) ||
                         mbedtls_mpi_copy((mbedtls_mpi *)d, &R) ?
                     -1 :
                     0;
        mbedtls_mpi_free(&R);
        return rc;
    }
    else
    {
        return mbedtls_mpi_exp_mod((mbedtls_mpi *)d,
                                   (const mbedtls_mpi *)a,
                                   (const mbedtls_mpi *)b,
                                   (const mbedtls_mpi *)c,
                                   NULL) ?
                   -1 :
                   0;
    }
}

int crypto_bignum_inverse(const struct crypto_bignum *a,
                          const struct crypto_bignum *b,
                          struct crypto_bignum *c)
{
    return mbedtls_mpi_inv_mod((mbedtls_mpi *)c, (const mbedtls_mpi *)a, (const mbedtls_mpi *)b) ?
               -1 :
               0;
}

int crypto_bignum_sub(const struct crypto_bignum *a,
                      const struct crypto_bignum *b,
                      struct crypto_bignum *c)
{
    return mbedtls_mpi_sub_mpi((mbedtls_mpi *)c, (const mbedtls_mpi *)a, (const mbedtls_mpi *)b) ?
               -1 :
               0;
}

int crypto_bignum_div(const struct crypto_bignum *a,
                      const struct crypto_bignum *b,
                      struct crypto_bignum *c)
{
    /*(most current use of this crypto.h interface has a == c (result),
     * so store result in an intermediate to avoid overwritten input)*/
    mbedtls_mpi R;
    mbedtls_mpi_init(&R);
    int rc = mbedtls_mpi_div_mpi(&R, NULL, (const mbedtls_mpi *)a, (const mbedtls_mpi *)b) ||
                     mbedtls_mpi_copy((mbedtls_mpi *)c, &R) ?
                 -1 :
                 0;
    mbedtls_mpi_free(&R);
    return rc;
}

int crypto_bignum_addmod(const struct crypto_bignum *a,
                         const struct crypto_bignum *b,
                         const struct crypto_bignum *c,
                         struct crypto_bignum *d)
{
    return mbedtls_mpi_add_mpi((mbedtls_mpi *)d, (const mbedtls_mpi *)a, (const mbedtls_mpi *)b) ||
                   mbedtls_mpi_mod_mpi((mbedtls_mpi *)d, (mbedtls_mpi *)d, (const mbedtls_mpi *)c) ?
               -1 :
               0;
}

int crypto_bignum_mulmod(const struct crypto_bignum *a,
                         const struct crypto_bignum *b,
                         const struct crypto_bignum *c,
                         struct crypto_bignum *d)
{
    return mbedtls_mpi_mul_mpi((mbedtls_mpi *)d, (const mbedtls_mpi *)a, (const mbedtls_mpi *)b) ||
                   mbedtls_mpi_mod_mpi((mbedtls_mpi *)d, (mbedtls_mpi *)d, (const mbedtls_mpi *)c) ?
               -1 :
               0;
}

int crypto_bignum_sqrmod(const struct crypto_bignum *a,
                         const struct crypto_bignum *b,
                         struct crypto_bignum *c)
{
    return crypto_bignum_mulmod(a, a, b, c);
}

int crypto_bignum_rshift(const struct crypto_bignum *a, int n, struct crypto_bignum *r)
{
    return mbedtls_mpi_copy((mbedtls_mpi *)r, (const mbedtls_mpi *)a) ||
                   mbedtls_mpi_shift_r((mbedtls_mpi *)r, n) ?
               -1 :
               0;
}

int crypto_bignum_cmp(const struct crypto_bignum *a, const struct crypto_bignum *b)
{
    return mbedtls_mpi_cmp_mpi((const mbedtls_mpi *)a, (const mbedtls_mpi *)b);
}

int crypto_bignum_is_zero(const struct crypto_bignum *a)
{
#if 0
    /* XXX: src/common/sae.c:sswu() contains comment:
     * "TODO: Make sure crypto_bignum_is_zero() is constant time"
     * Note: mbedtls_mpi_cmp_int() *is not* constant time */
    return (mbedtls_mpi_cmp_int((const mbedtls_mpi *)a, 0) == 0);
#else
    /* XXX: some places in src/common/sae.c require constant time safety */
    /* Access n limbs, but more work needed if n limbs should not leak */
    const mbedtls_mpi_uint *p = ((const mbedtls_mpi *)a)->MBEDTLS_PRIVATE(p);
    size_t n = ((const mbedtls_mpi *)a)->MBEDTLS_PRIVATE(n);
    unsigned int v = 0;
    for (size_t i = 0; i < n; ++i)
    {
        v |= p[i];
    }
    return (v == 0);
#endif
}

int crypto_bignum_is_one(const struct crypto_bignum *a)
{
#if 0
    return (mbedtls_mpi_cmp_int((const mbedtls_mpi *)a, 1) == 0);
#else
    /* XXX: some places in src/common/sae.c require constant time safety */
    /* Access n limbs, but more work needed if n limbs should not leak */
    const mbedtls_mpi_uint *p = ((const mbedtls_mpi *)a)->MBEDTLS_PRIVATE(p);
    mbedtls_mpi_uint v = 0;
    size_t n = ((const mbedtls_mpi *)a)->MBEDTLS_PRIVATE(n);
    for (size_t i = 1; i < n; ++i)
    {
        v |= p[i];
    }
    return n ? ((p[0] == 1) & (v == 0)) : 0; /* n > 0 expected */
#endif
}

int crypto_bignum_is_odd(const struct crypto_bignum *a)
{
    return mbedtls_mpi_get_bit((const mbedtls_mpi *)a, 0);
}

int crypto_bignum_legendre(const struct crypto_bignum *a, const struct crypto_bignum *p)
{
    /* Security Note:
     * mbedtls_mpi_exp_mod() is not documented to run in constant time,
     * though mbedtls/library/bignum.c uses constant_time_internal.h funcs.
     * Compare to crypto_openssl.c:crypto_bignum_legendre()
     * which uses openssl BN_mod_exp_mont_consttime()
     * mbedtls/library/ecp.c has further countermeasures to timing attacks,
     * (but ecp.c funcs are not used here) */

    mbedtls_mpi exp, tmp;
    mbedtls_mpi_init(&exp);
    mbedtls_mpi_init(&tmp);

    /* exp = (p-1) / 2 */
    int res;
    if (mbedtls_mpi_sub_int(&exp, (const mbedtls_mpi *)p, 1) == 0 &&
        mbedtls_mpi_shift_r(&exp, 1) == 0 &&
        mbedtls_mpi_exp_mod(&tmp, (const mbedtls_mpi *)a, &exp, (const mbedtls_mpi *)p, NULL) == 0)
    {
        /*(modified from crypto_openssl.c:crypto_bignum_legendre())*/
        /* Return 1 if tmp == 1, 0 if tmp == 0, or -1 otherwise. Need
         * to use constant time selection to avoid branches here. */
        unsigned int mask;
        res = -1;
        mask = const_time_eq(crypto_bignum_is_one((struct crypto_bignum *)&tmp), 1);
        res = const_time_select_int(mask, 1, res);
        mask = const_time_eq(crypto_bignum_is_zero((struct crypto_bignum *)&tmp), 1);
        res = const_time_select_int(mask, 0, res);
    }
    else
    {
        res = -2;
    }

    mbedtls_mpi_free(&tmp);
    mbedtls_mpi_free(&exp);
    return res;
}

#define CRYPTO_EC_pbits(e) (((const mbedtls_ecp_group *)(e))->pbits)
#define CRYPTO_EC_plen(e)  ((((const mbedtls_ecp_group *)(e))->pbits + 7) >> 3)
#define CRYPTO_EC_P(e)     (&((const mbedtls_ecp_group *)(e))->P)
#define CRYPTO_EC_N(e)     (&((const mbedtls_ecp_group *)(e))->N)
#define CRYPTO_EC_A(e)     (&((const mbedtls_ecp_group *)(e))->A)
#define CRYPTO_EC_B(e)     (&((const mbedtls_ecp_group *)(e))->B)
#define CRYPTO_EC_G(e)     (&((const mbedtls_ecp_group *)(e))->G)

static mbedtls_ecp_group_id crypto_mbedtls_ecp_group_id_from_ike_id(int group)
{
    /* https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml */
    switch (group)
    {
#ifdef MBEDTLS_ECP_DP_SECP256R1_ENABLED
        case 19:
            return MBEDTLS_ECP_DP_SECP256R1;

#endif
#ifdef MBEDTLS_ECP_DP_SECP384R1_ENABLED
        case 20:
            return MBEDTLS_ECP_DP_SECP384R1;

#endif
#ifdef MBEDTLS_ECP_DP_SECP521R1_ENABLED
        case 21:
            return MBEDTLS_ECP_DP_SECP521R1;

#endif
#ifdef MBEDTLS_ECP_DP_SECP192R1_ENABLED
        case 25:
            return MBEDTLS_ECP_DP_SECP192R1;

#endif
#ifdef MBEDTLS_ECP_DP_SECP224R1_ENABLED
        case 26:
            return MBEDTLS_ECP_DP_SECP224R1;

#endif
#ifdef MBEDTLS_ECP_DP_BP256R1_ENABLED
        case 28:
            return MBEDTLS_ECP_DP_BP256R1;

#endif
#ifdef MBEDTLS_ECP_DP_BP384R1_ENABLED
        case 29:
            return MBEDTLS_ECP_DP_BP384R1;

#endif
#ifdef MBEDTLS_ECP_DP_BP512R1_ENABLED
        case 30:
            return MBEDTLS_ECP_DP_BP512R1;

#endif
#ifdef MBEDTLS_ECP_DP_CURVE25519_ENABLED
        case 31:
            return MBEDTLS_ECP_DP_CURVE25519;

#endif
#ifdef MBEDTLS_ECP_DP_CURVE448_ENABLED
        case 32:
            return MBEDTLS_ECP_DP_CURVE448;

#endif
        default:
            return MBEDTLS_ECP_DP_NONE;
    }
}

/*
 * ECDH (used by OWE) on top of PSA.
 *
 * mbedTLS 4 removed mbedtls_ecdh_context; the own key pair now lives in a volatile PSA key slot.
 * Public keys and shared secrets keep the formats of the mbedtls_ecdh based implementation:
 * - Short Weierstrass: public key is X (inc_y == 0) or X || Y (inc_y != 0), big-endian, without
 *   the leading point format octet; a peer key without Y is decompressed assuming even Y
 *   (the x-coordinate of the shared secret does not depend on the sign of Y).
 * - Montgomery: public key is the raw little-endian u-coordinate; inc_y is ignored.
 * - The shared secret is the x-coordinate, prime length octets.
 */
struct crypto_ecdh
{
    psa_key_id_t key_id;
    mbedtls_ecp_group_id grp_id;
    psa_ecc_family_t family;
    size_t bits;
};

static psa_ecc_family_t crypto_mbedtls_psa_ecc_family(mbedtls_ecp_group_id grp_id, size_t *bits)
{
    switch (grp_id)
    {
#ifdef PSA_WANT_ECC_SECP_R1_192
        case MBEDTLS_ECP_DP_SECP192R1:
            *bits = 192;
            return PSA_ECC_FAMILY_SECP_R1;

#endif
#ifdef PSA_WANT_ECC_SECP_R1_224
        case MBEDTLS_ECP_DP_SECP224R1:
            *bits = 224;
            return PSA_ECC_FAMILY_SECP_R1;

#endif
#ifdef PSA_WANT_ECC_SECP_R1_256
        case MBEDTLS_ECP_DP_SECP256R1:
            *bits = 256;
            return PSA_ECC_FAMILY_SECP_R1;

#endif
#ifdef PSA_WANT_ECC_SECP_R1_384
        case MBEDTLS_ECP_DP_SECP384R1:
            *bits = 384;
            return PSA_ECC_FAMILY_SECP_R1;

#endif
#ifdef PSA_WANT_ECC_SECP_R1_521
        case MBEDTLS_ECP_DP_SECP521R1:
            *bits = 521;
            return PSA_ECC_FAMILY_SECP_R1;

#endif
#ifdef PSA_WANT_ECC_BRAINPOOL_P_R1_256
        case MBEDTLS_ECP_DP_BP256R1:
            *bits = 256;
            return PSA_ECC_FAMILY_BRAINPOOL_P_R1;

#endif
#ifdef PSA_WANT_ECC_BRAINPOOL_P_R1_384
        case MBEDTLS_ECP_DP_BP384R1:
            *bits = 384;
            return PSA_ECC_FAMILY_BRAINPOOL_P_R1;

#endif
#ifdef PSA_WANT_ECC_BRAINPOOL_P_R1_512
        case MBEDTLS_ECP_DP_BP512R1:
            *bits = 512;
            return PSA_ECC_FAMILY_BRAINPOOL_P_R1;

#endif
#ifdef PSA_WANT_ECC_MONTGOMERY_255
        case MBEDTLS_ECP_DP_CURVE25519:
            *bits = 255;
            return PSA_ECC_FAMILY_MONTGOMERY;

#endif
#ifdef PSA_WANT_ECC_MONTGOMERY_448
        case MBEDTLS_ECP_DP_CURVE448:
            *bits = 448;
            return PSA_ECC_FAMILY_MONTGOMERY;

#endif
        default:
            *bits = 0;
            return 0;
    }
}

struct crypto_ecdh *crypto_ecdh_init(int group)
{
    mbedtls_ecp_group_id grp_id = crypto_mbedtls_ecp_group_id_from_ike_id(group);
    size_t bits;
    psa_ecc_family_t family = crypto_mbedtls_psa_ecc_family(grp_id, &bits);
    if (family == 0)
    {
        return NULL;
    }

    struct crypto_ecdh *ecdh = mmosal_malloc(sizeof(*ecdh));
    if (ecdh == NULL)
    {
        return NULL;
    }
    ecdh->key_id = PSA_KEY_ID_NULL;
    ecdh->grp_id = grp_id;
    ecdh->family = family;
    ecdh->bits = bits;

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(family));
    psa_set_key_bits(&attributes, bits);
    psa_status_t status = psa_generate_key(&attributes, &ecdh->key_id);
    psa_reset_key_attributes(&attributes);
    if (status == PSA_SUCCESS)
    {
        return ecdh;
    }

    mmosal_free(ecdh);
    return NULL;
}

struct wpabuf *crypto_ecdh_get_pubkey(struct crypto_ecdh *ecdh, int inc_y)
{
    uint8_t buf[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE];
    size_t len;
    if (psa_export_public_key(ecdh->key_id, buf, sizeof(buf), &len) != PSA_SUCCESS)
    {
        return NULL;
    }

    if (ecdh->family == PSA_ECC_FAMILY_MONTGOMERY)
    {
        return wpabuf_alloc_copy(buf, len);
    }

    /* Short Weierstrass export format is 0x04 || X || Y; omit the leading format octet and,
     * unless requested, Y. */
    size_t prime_len = PSA_BITS_TO_BYTES(ecdh->bits);
    if (len != 1 + 2 * prime_len || buf[0] != 0x04)
    {
        return NULL;
    }
    return wpabuf_alloc_copy(buf + 1, inc_y ? 2 * prime_len : prime_len);
}

/**
 * crypto_mbedtls_decompress_point - Derive Y for a short Weierstrass point given only X
 * @grp_id: The curve
 * @x: Big-endian X, prime length octets
 * @prime_len: Length of @x
 * @out: Returns 0x04 || X || Y
 * @out_size: Size of @out (at least 1 + 2 * @prime_len)
 * Returns: 0 on success, -1 on failure (e.g. X is not on the curve)
 */
static int crypto_mbedtls_decompress_point(mbedtls_ecp_group_id grp_id,
                                           const uint8_t *x,
                                           size_t prime_len,
                                           uint8_t *out,
                                           size_t out_size)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point pt;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&pt);

    /* Use the compressed format with even Y (0x02), the same assumption as before. */
    out[0] = 0x02;
    memcpy(out + 1, x, prime_len);
    size_t olen = 0;
    int ret = mbedtls_ecp_group_load(&grp, grp_id) ||
              mbedtls_ecp_point_read_binary(&grp, &pt, out, 1 + prime_len) ||
              mbedtls_ecp_point_write_binary(&grp,
                                             &pt,
                                             MBEDTLS_ECP_PF_UNCOMPRESSED,
                                             &olen,
                                             out,
                                             out_size) ||
              olen != 1 + 2 * prime_len;

    mbedtls_ecp_point_free(&pt);
    mbedtls_ecp_group_free(&grp);
    return ret ? -1 : 0;
}

struct wpabuf *crypto_ecdh_set_peerkey(struct crypto_ecdh *ecdh,
                                       int inc_y,
                                       const uint8_t *key,
                                       size_t len)
{
    if (len == 0) /*(invalid peer key)*/
    {
        return NULL;
    }

    size_t prime_len = PSA_BITS_TO_BYTES(ecdh->bits);
    uint8_t peer[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE];
    const uint8_t *peer_key = key;
    size_t peer_len = len;

    if (ecdh->family != PSA_ECC_FAMILY_MONTGOMERY)
    {
        /* PSA takes the peer public key in uncompressed format: 0x04 || X || Y */
        if (inc_y)
        {
            if (len != 2 * prime_len || sizeof(peer) < 1 + len)
            {
                return NULL;
            }
            peer[0] = 0x04;
            memcpy(peer + 1, key, len);
        }
        else
        {
            if (len != prime_len ||
                sizeof(peer) < 1 + 2 * prime_len ||
                crypto_mbedtls_decompress_point(ecdh->grp_id, key, len, peer, sizeof(peer)))
            {
                return NULL;
            }
        }
        peer_key = peer;
        peer_len = 1 + 2 * prime_len;
    }

    struct wpabuf *buf = wpabuf_alloc(prime_len);
    if (buf == NULL)
    {
        return NULL;
    }

    /* psa_raw_key_agreement() validates the peer public key. */
    size_t secret_len = 0;
    if (psa_raw_key_agreement(PSA_ALG_ECDH,
                              ecdh->key_id,
                              peer_key,
                              peer_len,
                              wpabuf_mhead(buf),
                              prime_len,
                              &secret_len) == PSA_SUCCESS &&
        secret_len == prime_len)
    {
        wpabuf_put(buf, secret_len);
        return buf;
    }

    wpabuf_clear_free(buf);
    return NULL;
}

void crypto_ecdh_deinit(struct crypto_ecdh *ecdh)
{
    if (ecdh == NULL)
    {
        return;
    }
    psa_destroy_key(ecdh->key_id);
    mmosal_free(ecdh);
}

size_t crypto_ecdh_prime_len(struct crypto_ecdh *ecdh)
{
    return PSA_BITS_TO_BYTES(ecdh->bits);
}

struct crypto_ec *crypto_ec_init(int group)
{
    mbedtls_ecp_group_id grp_id = crypto_mbedtls_ecp_group_id_from_ike_id(group);
    if (grp_id == MBEDTLS_ECP_DP_NONE)
    {
        return NULL;
    }
    mbedtls_ecp_group *e = mmosal_malloc(sizeof(*e));
    if (e == NULL)
    {
        return NULL;
    }
    mbedtls_ecp_group_init(e);
    if (mbedtls_ecp_group_load(e, grp_id) == 0)
    {
        return (struct crypto_ec *)e;
    }

    mbedtls_ecp_group_free(e);
    mmosal_free(e);
    return NULL;
}

void crypto_ec_deinit(struct crypto_ec *e)
{
    mbedtls_ecp_group_free((mbedtls_ecp_group *)e);
    mmosal_free(e);
}

size_t crypto_ec_prime_len(struct crypto_ec *e)
{
    return CRYPTO_EC_plen(e);
}

size_t crypto_ec_prime_len_bits(struct crypto_ec *e)
{
    return CRYPTO_EC_pbits(e);
}

size_t crypto_ec_order_len(struct crypto_ec *e)
{
    return (mbedtls_mpi_bitlen(CRYPTO_EC_N(e)) + 7) / 8;
}

const struct crypto_bignum *crypto_ec_get_prime(struct crypto_ec *e)
{
    return (const struct crypto_bignum *)CRYPTO_EC_P(e);
}

const struct crypto_bignum *crypto_ec_get_order(struct crypto_ec *e)
{
    return (const struct crypto_bignum *)CRYPTO_EC_N(e);
}

const struct crypto_bignum *crypto_ec_get_a(struct crypto_ec *e)
{
    static const uint8_t secp256r1_a[] = { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
                                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                           0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
                                           0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc };
#ifdef MBEDTLS_ECP_DP_SECP384R1_ENABLED
    static const uint8_t secp384r1_a[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                           0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                           0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                           0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
                                           0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                                           0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfc };
#endif
#ifdef MBEDTLS_ECP_DP_SECP521R1_ENABLED
    static const uint8_t secp521r1_a[] = {
        0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc
    };
#endif

    const uint8_t *bin = NULL;
    size_t len = 0;

    /* (mbedtls groups matching supported sswu_curve_param() IKE groups) */
    switch (((mbedtls_ecp_group *)e)->id)
    {
#ifdef MBEDTLS_ECP_DP_SECP256R1_ENABLED
        case MBEDTLS_ECP_DP_SECP256R1:
            bin = secp256r1_a;
            len = sizeof(secp256r1_a);
            break;

#endif
#ifdef MBEDTLS_ECP_DP_SECP384R1_ENABLED
        case MBEDTLS_ECP_DP_SECP384R1:
            bin = secp384r1_a;
            len = sizeof(secp384r1_a);
            break;

#endif
#ifdef MBEDTLS_ECP_DP_SECP521R1_ENABLED
        case MBEDTLS_ECP_DP_SECP521R1:
            bin = secp521r1_a;
            len = sizeof(secp521r1_a);
            break;

#endif
#ifdef MBEDTLS_ECP_DP_BP256R1_ENABLED
        case MBEDTLS_ECP_DP_BP256R1:
            return (const struct crypto_bignum *)CRYPTO_EC_A(e);

#endif
#ifdef MBEDTLS_ECP_DP_BP384R1_ENABLED
        case MBEDTLS_ECP_DP_BP384R1:
            return (const struct crypto_bignum *)CRYPTO_EC_A(e);

#endif
#ifdef MBEDTLS_ECP_DP_BP512R1_ENABLED
        case MBEDTLS_ECP_DP_BP512R1:
            return (const struct crypto_bignum *)CRYPTO_EC_A(e);

#endif
#ifdef MBEDTLS_ECP_DP_CURVE25519_ENABLED
        case MBEDTLS_ECP_DP_CURVE25519:
            return (const struct crypto_bignum *)CRYPTO_EC_A(e);

#endif
#ifdef MBEDTLS_ECP_DP_CURVE448_ENABLED
        case MBEDTLS_ECP_DP_CURVE448:
            return (const struct crypto_bignum *)CRYPTO_EC_A(e);

#endif
        default:
            return NULL;
    }

    /*(note: not thread-safe; returns file-scoped static storage)*/
    if (mbedtls_mpi_read_binary(&mpi_sw_A, bin, len) == 0)
    {
        return (const struct crypto_bignum *)&mpi_sw_A;
    }
    return NULL;
}

const struct crypto_bignum *crypto_ec_get_b(struct crypto_ec *e)
{
    return (const struct crypto_bignum *)CRYPTO_EC_B(e);
}

const struct crypto_ec_point *crypto_ec_get_generator(struct crypto_ec *e)
{
    return (const struct crypto_ec_point *)CRYPTO_EC_G(e);
}

struct crypto_ec_point *crypto_ec_point_init(struct crypto_ec *e)
{
    mbedtls_ecp_point *p = mmosal_malloc(sizeof(*p));
    if (p != NULL)
    {
        mbedtls_ecp_point_init(p);
    }
    return (struct crypto_ec_point *)p;
}

void crypto_ec_point_deinit(struct crypto_ec_point *p, int clear)
{
    mbedtls_ecp_point_free((mbedtls_ecp_point *)p);
    mmosal_free(p);
}

int crypto_ec_point_x(struct crypto_ec *e, const struct crypto_ec_point *p, struct crypto_bignum *x)
{
    /* future: to avoid MBEDTLS_PRIVATE(), could write pt to stack buf,
     *         copy x, then wipe stack buf */

    mbedtls_mpi *px = &((mbedtls_ecp_point *)p)->MBEDTLS_PRIVATE(X);
    return mbedtls_mpi_copy((mbedtls_mpi *)x, px) ? -1 : 0;
}

int crypto_ec_point_to_bin(struct crypto_ec *e,
                           const struct crypto_ec_point *point,
                           uint8_t *x,
                           uint8_t *y)
{
    /* future: to avoid MBEDTLS_PRIVATE(), could write pt to stack buf,
     *         copy x and y, then wipe stack buf */

    /* crypto.h documents crypto_ec_point_to_bin() output is big-endian */
    size_t len = CRYPTO_EC_plen(e);
    if (x)
    {
        mbedtls_mpi *px = &((mbedtls_ecp_point *)point)->MBEDTLS_PRIVATE(X);
        if (mbedtls_mpi_write_binary(px, x, len))
        {
            return -1;
        }
    }
    if (y)
    {
#if 0 /*(should not be necessary; py mpi should be in initial state)*/
#ifdef MBEDTLS_ECP_MONTGOMERY_ENABLED
        if (mbedtls_ecp_get_type((mbedtls_ecp_group *)e) ==
            MBEDTLS_ECP_TYPE_MONTGOMERY)
        {
            memset(y, 0, len);
            return 0;
        }
#endif
#endif
        mbedtls_mpi *py = &((mbedtls_ecp_point *)point)->MBEDTLS_PRIVATE(Y);
        if (mbedtls_mpi_write_binary(py, y, len))
        {
            return -1;
        }
    }
    return 0;
}

struct crypto_ec_point *crypto_ec_point_from_bin(struct crypto_ec *e, const uint8_t *val)
{
    size_t len = CRYPTO_EC_plen(e);
    mbedtls_ecp_point *p = mmosal_malloc(sizeof(*p));
    uint8_t buf[1 + MBEDTLS_MPI_MAX_SIZE * 2];
    if (p == NULL)
    {
        return NULL;
    }
    mbedtls_ecp_point_init(p);

#ifdef MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED
    if (mbedtls_ecp_get_type((mbedtls_ecp_group *)e) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS)
    {
#if 0 /* prefer alternative to MBEDTLS_PRIVATE() access */
        mbedtls_mpi *px = &((mbedtls_ecp_point *)p)->MBEDTLS_PRIVATE(X);
        mbedtls_mpi *py = &((mbedtls_ecp_point *)p)->MBEDTLS_PRIVATE(Y);
        mbedtls_mpi *pz = &((mbedtls_ecp_point *)p)->MBEDTLS_PRIVATE(Z);

        if (mbedtls_mpi_read_binary(px, val, len) == 0 &&
            mbedtls_mpi_read_binary(py, val + len, len) == 0 &&
            mbedtls_mpi_lset(pz, 1) == 0)
        {
            return (struct crypto_ec_point *)p;
        }
#else
        buf[0] = 0x04;
        memcpy(buf + 1, val, len * 2);
        if (mbedtls_ecp_point_read_binary((mbedtls_ecp_group *)e, p, buf, 1 + len * 2) == 0)
        {
            return (struct crypto_ec_point *)p;
        }
#endif
    }
#endif
#ifdef MBEDTLS_ECP_MONTGOMERY_ENABLED
    if (mbedtls_ecp_get_type((mbedtls_ecp_group *)e) == MBEDTLS_ECP_TYPE_MONTGOMERY)
    {
        /* crypto.h interface documents crypto_ec_point_from_bin()
         * val is length: prime_len * 2 and is big-endian
         * (Short Weierstrass is assumed by hostap)
         * Reverse to little-endian format for Montgomery */
        for (unsigned int i = 0; i < len; ++i)
        {
            buf[i] = val[len - 1 - i];
        }
        if (mbedtls_ecp_point_read_binary((mbedtls_ecp_group *)e, p, buf, len) == 0)
        {
            return (struct crypto_ec_point *)p;
        }
    }
#endif

    mbedtls_ecp_point_free(p);
    mmosal_free(p);
    return NULL;
}

int crypto_ec_point_add(struct crypto_ec *e,
                        const struct crypto_ec_point *a,
                        const struct crypto_ec_point *b,
                        struct crypto_ec_point *c)
{
    /* mbedtls does not provide an mbedtls_ecp_point add function */
    mbedtls_mpi one;
    mbedtls_mpi_init(&one);
    int ret = mbedtls_mpi_lset(&one, 1) || mbedtls_ecp_muladd((mbedtls_ecp_group *)e,
                                                              (mbedtls_ecp_point *)c,
                                                              &one,
                                                              (const mbedtls_ecp_point *)a,
                                                              &one,
                                                              (const mbedtls_ecp_point *)b) ?
                  -1 :
                  0;
    mbedtls_mpi_free(&one);
    return ret;
}

int crypto_ec_point_mul(struct crypto_ec *e,
                        const struct crypto_ec_point *p,
                        const struct crypto_bignum *b,
                        struct crypto_ec_point *res)
{
    return mbedtls_ecp_mul((mbedtls_ecp_group *)e,
                           (mbedtls_ecp_point *)res,
                           (const mbedtls_mpi *)b,
                           (const mbedtls_ecp_point *)p,
                           CRYPTO_MBEDTLS_F_RNG,
                           CRYPTO_MBEDTLS_P_RNG) ?
               -1 :
               0;
}

int crypto_ec_point_invert(struct crypto_ec *e, struct crypto_ec_point *p)
{
    if (mbedtls_ecp_get_type((mbedtls_ecp_group *)e) == MBEDTLS_ECP_TYPE_MONTGOMERY)
    {
        /* e.g. MBEDTLS_ECP_DP_CURVE25519 and MBEDTLS_ECP_DP_CURVE448 */
        wpa_printf(MSG_ERROR, "%s not implemented for Montgomery curves", __func__);
        return -1;
    }

    /* mbedtls does not provide an mbedtls_ecp_point invert function */
    /* below works for Short Weierstrass; incorrect for Montgomery curves */
    mbedtls_mpi *py = &((mbedtls_ecp_point *)p)->MBEDTLS_PRIVATE(Y);
    return mbedtls_ecp_is_zero((mbedtls_ecp_point *)p) || /*point at infinity*/
                   mbedtls_mpi_cmp_int(py, 0) == 0 || /*point is its own inverse*/
                   mbedtls_mpi_sub_abs(py, CRYPTO_EC_P(e), py) == 0 ?
               0 :
               -1;
}

#ifdef MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED
static int crypto_ec_point_y_sqr_weierstrass(const mbedtls_ecp_group *e,
                                             const mbedtls_mpi *x,
                                             mbedtls_mpi *y2)
{
    /* MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS  y^2 = x^3 + a x + b    */

    /* Short Weierstrass elliptic curve group w/o A set treated as A = -3 */
    /* Attempt to match mbedtls/library/ecp.c:ecp_check_pubkey_sw() behavior
     * and elsewhere in mbedtls/library/ecp.c where if A is not set, it is
     * treated as if A = -3. */

#if 0
    /* y^2 = x^3 + ax + b */
    mbedtls_mpi *A = &e->A;
    mbedtls_mpi t, A_neg3;
    if (&e->A.p == NULL)
    {
        mbedtls_mpi_init(&A_neg3);
        if (mbedtls_mpi_lset(&A_neg3, -3) != 0)
        {
            mbedtls_mpi_free(&A_neg3);
            return -1;
        }
        A = &A_neg3;
    }
    mbedtls_mpi_init(&t);
    int ret = /* x^3 */
        mbedtls_mpi_lset(&t, 3) ||
        mbedtls_mpi_exp_mod(y2, x, &t, &e->P, NULL)
        /* ax */
        || mbedtls_mpi_mul_mpi(y2, y2, A) ||
        mbedtls_mpi_mod_mpi(&t, &t, &e->P)
        /* ax + b */
        || mbedtls_mpi_add_mpi(&t, &t, &e->B) ||
        mbedtls_mpi_mod_mpi(&t, &t, &e->P)
        /* x^3 + ax + b */
        || mbedtls_mpi_add_mpi(&t, &t, y2) || /* ax + b + x^3 */
        mbedtls_mpi_mod_mpi(y2, &t, &e->P);
    mbedtls_mpi_free(&t);
    if (A == &A_neg3)
    {
        mbedtls_mpi_free(&A_neg3);
    }
    return ret; /* 0: success, non-zero: failure */
#else
    /* y^2 = x^3 + ax + b = (x^2 + a)x + b */
    return /* x^2 */
        mbedtls_mpi_mul_mpi(y2, x, x) ||
        mbedtls_mpi_mod_mpi(y2, y2, &e->P)
        /* x^2 + a */
        ||
        (e->A.MBEDTLS_PRIVATE(p) ? mbedtls_mpi_add_mpi(y2, y2, &e->A) :
                                   mbedtls_mpi_sub_int(y2, y2, 3)) ||
        mbedtls_mpi_mod_mpi(y2, y2, &e->P)
        /* (x^2 + a)x */
        ||
        mbedtls_mpi_mul_mpi(y2, y2, x) ||
        mbedtls_mpi_mod_mpi(y2, y2, &e->P)
        /* (x^2 + a)x + b */
        || mbedtls_mpi_add_mpi(y2, y2, &e->B) || mbedtls_mpi_mod_mpi(y2, y2, &e->P);
#endif
}

#endif /* MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */

#if 0 /* not used by hostap */
#ifdef MBEDTLS_ECP_MONTGOMERY_ENABLED
static int
crypto_ec_point_y_sqr_montgomery(const mbedtls_ecp_group *e,
                                 const mbedtls_mpi *x,
                                 mbedtls_mpi *y2)
{
    /* XXX: !!! must be reviewed and audited for correctness !!! */

    /* MBEDTLS_ECP_TYPE_MONTGOMERY         y^2 = x^3 + a x^2 + x  */

    /* y^2 = x^3 + a x^2 + x = (x + a)x^2 + x */
    mbedtls_mpi x2;
    mbedtls_mpi_init(&x2);
    int ret = /* x^2 */
        mbedtls_mpi_mul_mpi(&x2, x, x) ||
        mbedtls_mpi_mod_mpi(&x2, &x2, &e->P)
        /* x + a */
        || mbedtls_mpi_add_mpi(y2, x, &e->A) ||
        mbedtls_mpi_mod_mpi(y2, y2, &e->P)
        /* (x + a)x^2 */
        || mbedtls_mpi_mul_mpi(y2, y2, &x2) ||
        mbedtls_mpi_mod_mpi(y2, y2, &e->P)
        /* (x + a)x^2 + x */
        || mbedtls_mpi_add_mpi(y2, y2, x) ||
        mbedtls_mpi_mod_mpi(y2, y2, &e->P);
    mbedtls_mpi_free(&x2);
    return ret; /* 0: success, non-zero: failure */
}

#endif /* MBEDTLS_ECP_MONTGOMERY_ENABLED */
#endif

struct crypto_bignum *crypto_ec_point_compute_y_sqr(struct crypto_ec *e,
                                                    const struct crypto_bignum *x)
{
    mbedtls_mpi *y2 = mmosal_malloc(sizeof(*y2));
    if (y2 == NULL)
    {
        return NULL;
    }
    mbedtls_mpi_init(y2);

#ifdef MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED
    if (mbedtls_ecp_get_type((const mbedtls_ecp_group *)e) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS &&
        crypto_ec_point_y_sqr_weierstrass((const mbedtls_ecp_group *)e,
                                          (const mbedtls_mpi *)x,
                                          y2) == 0)
    {
        return (struct crypto_bignum *)y2;
    }
#endif
#if 0 /* not used by hostap */
#ifdef MBEDTLS_ECP_MONTGOMERY_ENABLED
    if (mbedtls_ecp_get_type((mbedtls_ecp_group *)e) ==
        MBEDTLS_ECP_TYPE_MONTGOMERY &&
        crypto_ec_point_y_sqr_montgomery((const mbedtls_ecp_group *)e,
                                         (const mbedtls_mpi *)x,
                                         y2) == 0)
    {
        return (struct crypto_bignum *)y2;
    }
#endif
#endif

    mbedtls_mpi_free(y2);
    mmosal_free(y2);
    return NULL;
}

int crypto_ec_point_is_at_infinity(struct crypto_ec *e, const struct crypto_ec_point *p)
{
    return mbedtls_ecp_is_zero((mbedtls_ecp_point *)p);
}

int crypto_ec_point_is_on_curve(struct crypto_ec *e, const struct crypto_ec_point *p)
{
#if 1
    return mbedtls_ecp_check_pubkey((const mbedtls_ecp_group *)e, (const mbedtls_ecp_point *)p) ==
           0;
#else
    /* compute y^2 mod P and compare to y^2 mod P */
    /*(ref: src/eap_common/eap_pwd_common.c:compute_password_element())*/
    const mbedtls_mpi *px = &((const mbedtls_ecp_point *)p)->MBEDTLS_PRIVATE(X);
    mbedtls_mpi *cy2 =
        (mbedtls_mpi *)crypto_ec_point_compute_y_sqr(e, (const struct crypto_bignum *)px);
    if (cy2 == NULL)
    {
        return 0;
    }

    mbedtls_mpi y2;
    mbedtls_mpi_init(&y2);
    const mbedtls_mpi *py = &((const mbedtls_ecp_point *)p)->MBEDTLS_PRIVATE(Y);
    int is_on_curve = mbedtls_mpi_mul_mpi(&y2, py, py) || /* y^2 mod P */
                              mbedtls_mpi_mod_mpi(&y2, &y2, CRYPTO_EC_P(e)) ||
                              mbedtls_mpi_cmp_mpi(&y2, cy2) != 0 ?
                          0 :
                          1;

    mbedtls_mpi_free(&y2);
    mbedtls_mpi_free(cy2);
    mmosal_free(cy2);
    return is_on_curve;
#endif
}

int crypto_ec_point_cmp(const struct crypto_ec *e,
                        const struct crypto_ec_point *a,
                        const struct crypto_ec_point *b)
{
    return mbedtls_ecp_point_cmp((const mbedtls_ecp_point *)a, (const mbedtls_ecp_point *)b);
}

/*
 * aes_wrap - Wrap keys with AES Key Wrap Algorithm (RFC 3394)
 *
 * mbedTLS 4 only provides NIST KW with PSA key ids when MBEDTLS_NIST_KW_C is enabled, and
 * enabling it breaks ESP-IDF's own wpa_supplicant crypto port, so implement the algorithm
 * (as in hostap src/crypto/aes-wrap.c) on top of the AES-ECB primitive above. The matching
 * aes_unwrap() is provided by hostap src/crypto/aes-unwrap.c.
 *
 * @kek: Key encryption key (KEK)
 * @kek_len: Length of KEK in octets
 * @n: Length of the plaintext key in 64-bit units; e.g., 2 = 128-bit = 16 bytes
 * @plain: Plaintext key to be wrapped, n * 64 bits
 * @cipher: Wrapped key, (n + 1) * 64 bits
 * Returns: 0 on success, -1 on failure
 */
int aes_wrap(const uint8_t *kek, size_t kek_len, int n, const uint8_t *plain, uint8_t *cipher)
{
    /* NIST SP 800-38F KW (and the previous mbedtls_nist_kw_wrap() based implementation)
     * requires at least two semiblocks of plaintext. */
    if (n < 2)
    {
        return -1;
    }

    void *ctx = aes_encrypt_init(kek, kek_len);
    if (ctx == NULL)
    {
        return -1;
    }

    uint8_t *a = cipher;
    uint8_t b[AES_BLOCK_SIZE];
    uint8_t enc[AES_BLOCK_SIZE];
    int ret = 0;

    /* 1) Initialize variables. */
    memset(a, 0xa6, 8);
    memcpy(cipher + 8, plain, 8 * n);

    /* 2) Calculate intermediate values.
     * For j = 0 to 5
     *     For i=1 to n
     *         B = AES(K, A | R[i])
     *         A = MSB(64, B) ^ t where t = (n*j)+i
     *         R[i] = LSB(64, B)
     */
    for (int j = 0; j <= 5 && ret == 0; j++)
    {
        uint8_t *r = cipher + 8;
        for (int i = 1; i <= n; i++)
        {
            memcpy(b, a, 8);
            memcpy(b + 8, r, 8);
            if (aes_encrypt(ctx, b, enc))
            {
                ret = -1;
                break;
            }
            memcpy(a, enc, 8);
            uint32_t t = (uint32_t)(n * j + i);
            a[7] ^= (uint8_t)t;
            a[6] ^= (uint8_t)(t >> 8);
            a[5] ^= (uint8_t)(t >> 16);
            a[4] ^= (uint8_t)(t >> 24);
            memcpy(r, enc + 8, 8);
            r += 8;
        }
    }
    aes_encrypt_deinit(ctx);
    mbedtls_platform_zeroize(b, sizeof(b));
    mbedtls_platform_zeroize(enc, sizeof(enc));

    /* 3) Output the results.
     *
     * These are already in @cipher due to the location of temporary
     * variables.
     */

    return ret;
}
