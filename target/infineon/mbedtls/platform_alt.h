/***************************************************************************//**
* \file platform_alt.h
*
* \brief This file contains the definitions and functions of the
*        IFX Mbed TLS platform abstraction layer.
*
********************************************************************************
* \copyright
* Copyright 2022, Cypress Semiconductor Corporation. All rights reserved.
* You may use this file only in accordance with the license, terms, conditions,
* disclaimers, and limitations in the end user license agreement accompanying
* the software package with which this file was provided.
*******************************************************************************/

#ifndef MBEDTLS_PLATFORM_ALT_H
#define MBEDTLS_PLATFORM_ALT_H

#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include "psa/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief   The platform context structure.
 *
 * \note    This structure may be used to assist platform-specific
 *          setup or teardown operations.
 */
typedef struct mbedtls_platform_context
{
    char MBEDTLS_PRIVATE(dummy); /**< A placeholder member, as empty structs are not portable. */
}
mbedtls_platform_context;

/** The CMAC KDF algorithm
 *
 * Key derivation in Counter Mode using CMAC as pseudo random function (PRF)
 * is defined in NIST SP 800-108 section 4.1.
 *
 * This key derivation algorithm uses the following inputs
 * - #PSA_KEY_DERIVATION_INPUT_SECRET is the key derivation key. It is a key
 *   that is used as an input to a key-derivation function (along with other
 *   input data) to derive keying material.
 * - #PSA_KEY_DERIVATION_INPUT_LABEL is a string that identifies the purpose
 *   for the derived keying material, which is encoded as a bit string.
 *   The encoding method for the Label is defined in a larger context,
 *   for example, in the protocol that uses a KDF.
 *   This input is optional.
 * - #PSA_KEY_DERIVATION_INPUT_SEED is a bit string that is used to seed the
 *   PRF. This input is optional.
 */
#define PSA_ALG_KDF_IFX_SE_AES_CMAC                 ((psa_algorithm_t)0x08000600)

/** The storage area located inside IFX SE Runtime Services */
#define PSA_KEY_LOCATION_IFX_SE                     ((psa_key_location_t)0x800001)

/* The slot number used to identify built-in keys.
 * Numbers are only used internally, so any number can be used */
#define PSA_CRYPTO_IFX_SE_HUK_SLOT_NUMBER           (0u)
#define PSA_CRYPTO_IFX_SE_OEM_ROT_SLOT_NUMBER       (1u)
#define PSA_CRYPTO_IFX_SE_SERVICES_UPD_SLOT_NUMBER  (2u)
#define PSA_CRYPTO_IFX_SE_IFX_ROT_SLOT_NUMBER       (3u)
#define PSA_CRYPTO_IFX_SE_DEVICE_PRIV_SLOT_NUMBER   (4u)
#define PSA_CRYPTO_IFX_SE_ATTEST_PRIV_SLOT_NUMBER   (5u)
#define PSA_CRYPTO_IFX_SE_ATTEST_PUB_SLOT_NUMBER    (6u)

/* IDs of supported built-in keys */
#define PSA_CRYPTO_IFX_SE_HUK_KEY_ID                (MBEDTLS_PSA_KEY_ID_BUILTIN_MIN + PSA_CRYPTO_IFX_SE_HUK_SLOT_NUMBER)
#define PSA_CRYPTO_IFX_SE_OEM_ROT_KEY_ID            (MBEDTLS_PSA_KEY_ID_BUILTIN_MIN + PSA_CRYPTO_IFX_SE_OEM_ROT_SLOT_NUMBER)
#define PSA_CRYPTO_IFX_SE_SERVICES_UPD_KEY_ID       (MBEDTLS_PSA_KEY_ID_BUILTIN_MIN + PSA_CRYPTO_IFX_SE_SERVICES_UPD_SLOT_NUMBER)
#define PSA_CRYPTO_IFX_SE_IFX_ROT_KEY_ID            (MBEDTLS_PSA_KEY_ID_BUILTIN_MIN + PSA_CRYPTO_IFX_SE_IFX_ROT_SLOT_NUMBER)
#define PSA_CRYPTO_IFX_SE_DEVICE_KEY_ID             (MBEDTLS_PSA_KEY_ID_BUILTIN_MIN + PSA_CRYPTO_IFX_SE_DEVICE_PRIV_SLOT_NUMBER)
#define PSA_CRYPTO_IFX_SE_ATTEST_PRIV_KEY_ID        (MBEDTLS_PSA_KEY_ID_BUILTIN_MIN + PSA_CRYPTO_IFX_SE_ATTEST_PRIV_SLOT_NUMBER)
#define PSA_CRYPTO_IFX_SE_ATTEST_PUB_KEY_ID         (MBEDTLS_PSA_KEY_ID_BUILTIN_MIN + PSA_CRYPTO_IFX_SE_ATTEST_PUB_SLOT_NUMBER)

/* Extra IDs used for test purposes */
#if defined(TEST_IFX_ADDITIONAL_BUILTIN_KEYS)
#define PSA_CRYPTO_IFX_SE_AES_SLOT_NUMBER           (7u)
#define PSA_CRYPTO_IFX_SE_ECDSA_SLOT_NUMBER         (8u)
#define PSA_CRYPTO_IFX_SE_CMAC128_SLOT_NUMBER       (9u)
#define PSA_CRYPTO_IFX_SE_CMAC256_SLOT_NUMBER       (10u)
#define PSA_CRYPTO_IFX_SE_ECC384_SLOT_NUMBER        (11u)
#define PSA_CRYPTO_IFX_SE_CMACKDF_SLOT_NUMBER       (12u)

#define PSA_CRYPTO_IFX_SE_AES_KEY_ID                (MBEDTLS_PSA_KEY_ID_BUILTIN_MIN + PSA_CRYPTO_IFX_SE_AES_SLOT_NUMBER)
#define PSA_CRYPTO_IFX_SE_ECDSA_KEY_ID              (MBEDTLS_PSA_KEY_ID_BUILTIN_MIN + PSA_CRYPTO_IFX_SE_ECDSA_SLOT_NUMBER)
#define PSA_CRYPTO_IFX_SE_CMAC128_KEY_ID            (MBEDTLS_PSA_KEY_ID_BUILTIN_MIN + PSA_CRYPTO_IFX_SE_CMAC128_SLOT_NUMBER)
#define PSA_CRYPTO_IFX_SE_CMAC256_KEY_ID            (MBEDTLS_PSA_KEY_ID_BUILTIN_MIN + PSA_CRYPTO_IFX_SE_CMAC256_SLOT_NUMBER)
#define PSA_CRYPTO_IFX_SE_ECC384_KEY_ID             (MBEDTLS_PSA_KEY_ID_BUILTIN_MIN + PSA_CRYPTO_IFX_SE_ECC384_SLOT_NUMBER)
#define PSA_CRYPTO_IFX_SE_CMACKDF_KEY_ID            (MBEDTLS_PSA_KEY_ID_BUILTIN_MIN + PSA_CRYPTO_IFX_SE_CMACKDF_SLOT_NUMBER)
#endif /* TEST_IFX_ADDITIONAL_BUILTIN_KEYS */

/**
 * Maximum possible number of bytes a key derivation operation can output.
 *
 * This number is derived from the maximum number of bits which can be represented within
 * \p IFX_SCA_KEY_DERIVATION_CAPACITY_LENGTH bytes.
 */
#define PSA_IFX_SE_KEY_DERIVATION_MAX_CAPACITY      ((size_t)0x0FFFFFFF)

psa_status_t ifx_mbedtls_get_builtin_key(
    psa_drv_slot_number_t slot_number,
    psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length );

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_PLATFORM_ALT_H */
