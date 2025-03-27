/***************************************************************************//**
* \file ifx_mbedtls_builtin_keys.c
*
* \brief
* mbedtls IFX builtin keys implementation
*
* \note
*
********************************************************************************
* \copyright
* Copyright 2022, Cypress Semiconductor Corporation. All rights reserved.
* You may use this file only in accordance with the license, terms, conditions,
* disclaimers, and limitations in the end user license agreement accompanying
* the software package with which this file was provided.
*******************************************************************************/

#include "mbedtls/build_info.h"

/*-----------------------------------------------------------*/

#if defined(MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS)

#include "psa/crypto.h"
#include "mbedtls/platform.h"

#if defined(IFX_PSA_CRYPTO_BUILTIN_KEYS)

#include "ifx_se_psacrypto.h"

typedef struct
{
    psa_key_id_t key_id;                 /* Key id associated to the builtin key */
    psa_drv_slot_number_t slot_number;   /* Slot number for the builtin key in the platform */
    psa_key_lifetime_t lifetime;         /* Lifetime (persistence + location) for the builtin key */
} mbedtls_psa_builtin_key_description_t;

static const mbedtls_psa_builtin_key_description_t builtin_keys[] = {
    /* For using, assign the AES builtin key slot to the boundary values.
     * ECDSA can be exercised on key ID MBEDTLS_PSA_KEY_ID_BUILTIN_MIN + 1. */
    /* HUK */
    { PSA_CRYPTO_IFX_SE_HUK_KEY_ID,
      PSA_CRYPTO_IFX_SE_HUK_SLOT_NUMBER,
      PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
        PSA_KEY_PERSISTENCE_READ_ONLY, PSA_KEY_LOCATION_IFX_SE ) },

    /* OEM ROT key */
    { PSA_CRYPTO_IFX_SE_OEM_ROT_KEY_ID,
      PSA_CRYPTO_IFX_SE_OEM_ROT_SLOT_NUMBER,
            PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
        PSA_KEY_PERSISTENCE_READ_ONLY, PSA_KEY_LOCATION_IFX_SE ) },
    /* IFX_FW_INTEGRITY_KEYx, used for authenticating the SE_RT_SERVICES update image */
    { PSA_CRYPTO_IFX_SE_SERVICES_UPD_KEY_ID,
      PSA_CRYPTO_IFX_SE_SERVICES_UPD_SLOT_NUMBER,
      PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
        PSA_KEY_PERSISTENCE_READ_ONLY, PSA_KEY_LOCATION_IFX_SE ) },
    /* IFX_ROT_KEY, used to verify the signature of RAM Apps */
    { PSA_CRYPTO_IFX_SE_IFX_ROT_KEY_ID,
      PSA_CRYPTO_IFX_SE_IFX_ROT_SLOT_NUMBER,
      PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
        PSA_KEY_PERSISTENCE_READ_ONLY, PSA_KEY_LOCATION_IFX_SE ) },
    /* DICE_DeviceID private key */
    { PSA_CRYPTO_IFX_SE_DEVICE_KEY_ID,
      PSA_CRYPTO_IFX_SE_DEVICE_PRIV_SLOT_NUMBER,
      PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
        PSA_KEY_PERSISTENCE_READ_ONLY, PSA_KEY_LOCATION_IFX_SE ) },
    /* Attestation private key */
    { PSA_CRYPTO_IFX_SE_ATTEST_PRIV_KEY_ID,
      PSA_CRYPTO_IFX_SE_ATTEST_PRIV_SLOT_NUMBER,
      PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
        PSA_KEY_PERSISTENCE_READ_ONLY, PSA_KEY_LOCATION_IFX_SE ) },
    /* Attestation public key */
    { PSA_CRYPTO_IFX_SE_ATTEST_PUB_KEY_ID,
      PSA_CRYPTO_IFX_SE_ATTEST_PUB_SLOT_NUMBER,
      PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
        PSA_KEY_PERSISTENCE_READ_ONLY, PSA_KEY_LOCATION_IFX_SE ) }
};

#if defined(TEST_IFX_ADDITIONAL_BUILTIN_KEYS)
static const mbedtls_psa_builtin_key_description_t builtin_test_keys[] = {
    { PSA_CRYPTO_IFX_SE_AES_KEY_ID,
      PSA_CRYPTO_IFX_SE_AES_SLOT_NUMBER,
      PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
        PSA_KEY_PERSISTENCE_READ_ONLY, PSA_KEY_LOCATION_IFX_SE ) },

    { PSA_CRYPTO_IFX_SE_ECDSA_KEY_ID,
      PSA_CRYPTO_IFX_SE_ECDSA_SLOT_NUMBER,
      PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
        PSA_KEY_PERSISTENCE_READ_ONLY, PSA_KEY_LOCATION_IFX_SE ) },

    { PSA_CRYPTO_IFX_SE_CMAC128_KEY_ID,
      PSA_CRYPTO_IFX_SE_CMAC128_SLOT_NUMBER,
      PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
        PSA_KEY_PERSISTENCE_READ_ONLY, PSA_KEY_LOCATION_IFX_SE ) },

    { PSA_CRYPTO_IFX_SE_CMAC256_KEY_ID,
      PSA_CRYPTO_IFX_SE_CMAC256_SLOT_NUMBER,
      PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
        PSA_KEY_PERSISTENCE_READ_ONLY, PSA_KEY_LOCATION_IFX_SE ) },

    { PSA_CRYPTO_IFX_SE_ECC384_KEY_ID,
      PSA_CRYPTO_IFX_SE_ECC384_SLOT_NUMBER,
      PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
        PSA_KEY_PERSISTENCE_READ_ONLY, PSA_KEY_LOCATION_IFX_SE ) },

    { PSA_CRYPTO_IFX_SE_CMACKDF_KEY_ID,
      PSA_CRYPTO_IFX_SE_CMACKDF_SLOT_NUMBER,
      PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
        PSA_KEY_PERSISTENCE_READ_ONLY, PSA_KEY_LOCATION_IFX_SE ) }
};
#endif /* TEST_IFX_ADDITIONAL_BUILTIN_KEYS */

/** Platform function to obtain the location and slot number of a built-in key.
 *
 * #MBEDTLS_SVC_KEY_ID_GET_KEY_ID(\p key_id) needs to be in the range from
 * #MBEDTLS_PSA_KEY_ID_BUILTIN_MIN to #MBEDTLS_PSA_KEY_ID_BUILTIN_MAX.
 *
 * In a multi-application configuration
 * (\c MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER is defined),
 * this function should check that #MBEDTLS_SVC_KEY_ID_GET_OWNER_ID(\p key_id)
 * is allowed to use the given key.
 *
 * \param key_id                The key ID for which to retrieve the
 *                              location and slot attributes.
 * \param[out] lifetime         On success, the lifetime associated with the key
 *                              corresponding to \p key_id. Lifetime is a
 *                              combination of which driver contains the key,
 *                              and with what persistence level the key is
 *                              intended to be used. If the platform
 *                              implementation does not contain specific
 *                              information about the intended key persistence
 *                              level, the persistence level may be reported as
 *                              #PSA_KEY_PERSISTENCE_DEFAULT.
 * \param[out] slot_number      On success, the slot number known to the driver
 *                              registered at the lifetime location reported
 *                              through \p lifetime which corresponds to the
 *                              requested built-in key.
 *
 * \retval #PSA_SUCCESS
 *         The requested key identifier designates a built-in key.
 *         In a multi-application configuration, the requested owner
 *         is allowed to access it.
 * \retval #PSA_ERROR_DOES_NOT_EXIST
 *         The requested key identifier is not a built-in key which is known
 *         to this function. If a key exists in the key storage with this
 *         identifier, the data from the storage will be used.
 */
psa_status_t mbedtls_psa_platform_get_builtin_key(
    mbedtls_svc_key_id_t key_id,
    psa_key_lifetime_t *lifetime,
    psa_drv_slot_number_t *slot_number )
{
    psa_key_id_t app_key_id = MBEDTLS_SVC_KEY_ID_GET_KEY_ID( key_id );

    const mbedtls_psa_builtin_key_description_t *key_slots = builtin_keys;
    size_t key_slots_size = sizeof(builtin_keys) / sizeof(builtin_keys[0]);

#if defined(TEST_IFX_ADDITIONAL_BUILTIN_KEYS)
    if (app_key_id >= PSA_CRYPTO_IFX_SE_TEST_SLOT_MIN)
    {
        /* Test builtin keys located in the different key data array */
        key_slots = builtin_test_keys;
        key_slots_size = sizeof(builtin_test_keys) / sizeof(builtin_test_keys[0]);
    }
#endif /* TEST_IFX_ADDITIONAL_BUILTIN_KEYS */

    for ( size_t i = 0; i < key_slots_size; i++ )
    {
        if (app_key_id == key_slots[i].key_id)
        {
            *lifetime = key_slots[i].lifetime;
            *slot_number = key_slots[i].slot_number;

            return( PSA_SUCCESS );
        }
    }

    return( PSA_ERROR_DOES_NOT_EXIST );
}

/** Populates key attributes and copies key material to the output buffer.
*
* \param[in]  slot_number           The slot number which corresponds to the
*                                   requested built-in key.
* \param[out] attributes            Attributes of the requested built-in key.
* \param[out] key_buffer            Output buffer where the key material of the
*                                   requested built-in key is copied.
* \param[in]  key_buffer_size       Size of the output buffer.
* \param[out] key_buffer_length     Actual length of the data copied to the
*                                   output buffer.
*
* \return     A status indicating the success/failure of the operation
*******************************************************************************/
psa_status_t ifx_mbedtls_get_builtin_key(
    psa_drv_slot_number_t slot_number,
    psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if( key_buffer_size < sizeof( ifx_se_key_id_fih_t ) )
        return( PSA_ERROR_BUFFER_TOO_SMALL );

    switch( slot_number )
    {
        case PSA_CRYPTO_IFX_SE_HUK_SLOT_NUMBER:
            psa_set_key_type(attributes, PSA_KEY_TYPE_DERIVE);
            psa_set_key_bits( attributes, 256u );
            psa_set_key_usage_flags(
                attributes,
                PSA_KEY_USAGE_DERIVE );
            psa_set_key_algorithm( attributes, PSA_ALG_KDF_IFX_SE_AES_CMAC );

            status = PSA_SUCCESS;
            break;
        case PSA_CRYPTO_IFX_SE_OEM_ROT_SLOT_NUMBER:
            psa_set_key_type(
                attributes,
                PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1) );
            psa_set_key_bits( attributes, 256u );
            psa_set_key_usage_flags(
                attributes,
                PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE |
                PSA_KEY_USAGE_EXPORT );
            psa_set_key_algorithm(
                attributes, PSA_ALG_ECDSA( PSA_ALG_SHA_256 ) );

            status = PSA_SUCCESS;
            break;
        case PSA_CRYPTO_IFX_SE_SERVICES_UPD_SLOT_NUMBER:
            psa_set_key_type(
                attributes,
                PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1) );
            psa_set_key_bits( attributes, 256u );
            psa_set_key_usage_flags(
                attributes,
                PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE |
                PSA_KEY_USAGE_EXPORT );
            psa_set_key_algorithm(
                attributes, PSA_ALG_ECDSA( PSA_ALG_SHA_256 ) );

            status = PSA_SUCCESS;
            break;
        case PSA_CRYPTO_IFX_SE_IFX_ROT_SLOT_NUMBER:
            psa_set_key_type(
                attributes,
                PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1) );
            psa_set_key_bits( attributes, 256u );
            psa_set_key_usage_flags(
                attributes,
                PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE |
                PSA_KEY_USAGE_EXPORT );
            psa_set_key_algorithm(
                attributes, PSA_ALG_ECDSA( PSA_ALG_SHA_256 ) );

            status = PSA_SUCCESS;
            break;
        case PSA_CRYPTO_IFX_SE_DEVICE_PRIV_SLOT_NUMBER:
            psa_set_key_type(
                attributes,
                PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1) );
            psa_set_key_bits( attributes, 256u );
            psa_set_key_usage_flags(
                attributes,
                PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE );
            psa_set_key_algorithm(
                attributes, PSA_ALG_ECDSA( PSA_ALG_ANY_HASH ) );

            status = PSA_SUCCESS;
            break;
        case PSA_CRYPTO_IFX_SE_ATTEST_PRIV_SLOT_NUMBER:
            psa_set_key_type(
                attributes,
                PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1) );
            psa_set_key_bits( attributes, 256u );
            psa_set_key_usage_flags(
                attributes,
                PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE |
                PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE );
            psa_set_key_algorithm(
                attributes, PSA_ALG_ECDSA( PSA_ALG_ANY_HASH ) );

            status = PSA_SUCCESS;
            break;
        case PSA_CRYPTO_IFX_SE_ATTEST_PUB_SLOT_NUMBER:
            psa_set_key_type(
                attributes,
                PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1) );
            psa_set_key_bits( attributes, 256u );
            psa_set_key_usage_flags(
                attributes,
                PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE |
                PSA_KEY_USAGE_EXPORT );
            psa_set_key_algorithm(
                attributes, PSA_ALG_ECDSA( PSA_ALG_SHA_256 ) );

            status = PSA_SUCCESS;
            break;

#if defined(TEST_IFX_ADDITIONAL_BUILTIN_KEYS)
        case PSA_CRYPTO_IFX_SE_AES_SLOT_NUMBER:
            psa_set_key_type( attributes, PSA_KEY_TYPE_AES );
            psa_set_key_bits( attributes, 128u );
            psa_set_key_usage_flags(
                attributes,
                PSA_KEY_USAGE_ENCRYPT |
                PSA_KEY_USAGE_DECRYPT |
                PSA_KEY_USAGE_EXPORT );
            psa_set_key_algorithm( attributes, PSA_ALG_CBC_NO_PADDING );

            status = PSA_SUCCESS;
            break;
        case PSA_CRYPTO_IFX_SE_ECDSA_SLOT_NUMBER:
            psa_set_key_type(
                attributes,
                PSA_KEY_TYPE_ECC_KEY_PAIR( PSA_ECC_FAMILY_SECP_R1 ) );
            psa_set_key_bits( attributes, 256u );
            psa_set_key_usage_flags(
                attributes,
                PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH |
                PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE |
                PSA_KEY_USAGE_EXPORT );
            psa_set_key_algorithm(
                attributes, PSA_ALG_ECDSA( PSA_ALG_ANY_HASH ) );

            status = PSA_SUCCESS;
            break;
        case PSA_CRYPTO_IFX_SE_CMAC128_SLOT_NUMBER:
            psa_set_key_type( attributes, PSA_KEY_TYPE_AES );
            psa_set_key_bits( attributes, 128u );
            psa_set_key_usage_flags(
                attributes,
                PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE |
                PSA_KEY_USAGE_EXPORT );
            psa_set_key_algorithm( attributes, PSA_ALG_CMAC );

            status = PSA_SUCCESS;
            break;
        case PSA_CRYPTO_IFX_SE_CMAC256_SLOT_NUMBER:
            psa_set_key_type( attributes, PSA_KEY_TYPE_AES );
            psa_set_key_bits( attributes, 256u );
            psa_set_key_usage_flags(
                attributes,
                PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE |
                PSA_KEY_USAGE_EXPORT );
            psa_set_key_algorithm( attributes, PSA_ALG_CMAC );

            status = PSA_SUCCESS;
            break;
        case PSA_CRYPTO_IFX_SE_ECC384_SLOT_NUMBER:
            psa_set_key_type(
                attributes,
                PSA_KEY_TYPE_ECC_PUBLIC_KEY( PSA_ECC_FAMILY_SECP_R1 ) );
            psa_set_key_bits( attributes, 384u );
            psa_set_key_usage_flags(
                attributes,
                PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE |
                PSA_KEY_USAGE_EXPORT );
            psa_set_key_algorithm(
                attributes, PSA_ALG_ECDSA( PSA_ALG_SHA_256 ) );

            status = PSA_SUCCESS;
            break;
        case PSA_CRYPTO_IFX_SE_CMACKDF_SLOT_NUMBER:
            psa_set_key_type(attributes, PSA_KEY_TYPE_DERIVE);
            psa_set_key_bits( attributes, 256u );
            psa_set_key_usage_flags(
                attributes,
                PSA_KEY_USAGE_DERIVE );
            psa_set_key_algorithm( attributes, PSA_ALG_KDF_IFX_SE_AES_CMAC );

            status = PSA_SUCCESS;
            break;
#endif /* TEST_IFX_ADDITIONAL_BUILTIN_KEYS */
        default:
            status = PSA_ERROR_DOES_NOT_EXIST;
    }

    if (status == PSA_SUCCESS)
    {
        const mbedtls_psa_builtin_key_description_t *key_slots = builtin_keys;
        psa_drv_slot_number_t slot_id = slot_number;

#if defined(TEST_IFX_ADDITIONAL_BUILTIN_KEYS)
        if (slot_number >= PSA_CRYPTO_IFX_SE_TEST_SLOT_MIN)
        {
            /* Test builtin keys located in the different key data array */
            key_slots = builtin_test_keys;
            slot_id = slot_number - PSA_CRYPTO_IFX_SE_TEST_SLOT_MIN;
        }
#endif /* TEST_IFX_ADDITIONAL_BUILTIN_KEYS */

        *( (ifx_se_key_id_fih_t*) key_buffer ) =
            ifx_se_key_id_fih_make(0, key_slots[slot_id].key_id);
        *key_buffer_length = sizeof( ifx_se_key_id_fih_t );
    }

    return( status );
}
#endif /* IFX_PSA_CRYPTO_BUILTIN_KEYS */

#endif /* MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS */

