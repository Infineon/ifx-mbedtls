/*
 *  Functions to delegate cryptographic operations to an available
 *  and appropriate accelerator.
 *  Warning: This file is now auto-generated.
 */
/*  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */


/* BEGIN-common headers */
#include "common.h"
#include "psa_crypto_aead.h"
#include "psa_crypto_cipher.h"
#include "psa_crypto_core.h"
#include "psa_crypto_driver_wrappers_no_static.h"
#include "psa_crypto_hash.h"
#include "psa_crypto_mac.h"
#include "psa_crypto_pake.h"
#include "psa_crypto_rsa.h"

#include "mbedtls/platform.h"
/* END-common headers */

#if defined(MBEDTLS_PSA_CRYPTO_C)

/* BEGIN-driver headers */
/* Headers for mbedtls_test opaque driver */
#if defined(PSA_CRYPTO_DRIVER_TEST)
#include "test/drivers/test_driver.h"

#endif
/* Headers for mbedtls_test transparent driver */
#if defined(PSA_CRYPTO_DRIVER_TEST)
#include "test/drivers/test_driver.h"

#endif
/* Headers for p256 transparent driver */
#if defined(MBEDTLS_PSA_P256M_DRIVER_ENABLED)
#include "../3rdparty/p256-m/p256-m_driver_entrypoints.h"

#endif

#if defined(IFX_PSA_MXCRYPTO_PRESENT)
#ifndef PSA_CRYPTO_DRIVER_PRESENT
#define PSA_CRYPTO_DRIVER_PRESENT
#endif
#ifndef PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT
#define PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT
#endif
#include "ifx_mxcrypto_transparent_functions.h"
#endif /* IFX_PSA_MXCRYPTO_PRESENT */

#if defined(IFX_PSA_CRYPTOLITE_PRESENT)
#ifndef PSA_CRYPTO_DRIVER_PRESENT
#define PSA_CRYPTO_DRIVER_PRESENT
#endif
#ifndef PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT
#define PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT
#endif
#include "ifx_cryptolite_transparent_functions.h"
#endif /* IFX_PSA_CRYPTOLITE_PRESENT */

/* END-driver headers */

/* Auto-generated values depending on which drivers are registered.
 * ID 0 is reserved for unallocated operations.
 * ID 1 is reserved for the Mbed TLS software driver. */
/* BEGIN-driver id definition */
#define PSA_CRYPTO_MBED_TLS_DRIVER_ID (1)
#define MBEDTLS_TEST_OPAQUE_DRIVER_ID (2)
#define MBEDTLS_TEST_TRANSPARENT_DRIVER_ID (3)
#define P256_TRANSPARENT_DRIVER_ID (4)

#if defined(IFX_PSA_SE_DPA_PRESENT)
#define IFX_SE_DPA_DRIVER_ID (5)
#endif /* IFX_PSA_SE_DPA_PRESENT */

#if defined(IFX_PSA_MXCRYPTO_PRESENT)
#define IFX_MXCRYPTO_TRANSPARENT_DRIVER_ID (6)
#endif /* IFX_PSA_MXCRYPTO_PRESENT */

#if defined(IFX_PSA_CRYPTOLITE_PRESENT)
#define IFX_CRYPTOLITE_TRANSPARENT_DRIVER_ID (7)
#endif /* IFX_PSA_CRYPTOLITE_PRESENT */

/* END-driver id */

/* BEGIN-Common Macro definitions */

/* END-Common Macro definitions */

/* Support the 'old' SE interface when asked to */
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
/* PSA_CRYPTO_DRIVER_PRESENT is defined when either a new-style or old-style
 * SE driver is present, to avoid unused argument errors at compile time. */
#ifndef PSA_CRYPTO_DRIVER_PRESENT
#define PSA_CRYPTO_DRIVER_PRESENT
#endif
#include "psa_crypto_se.h"
#endif

/** Get the key buffer size required to store the key material of a key
 *  associated with an opaque driver.
 *
 * \param[in] attributes  The key attributes.
 * \param[out] key_buffer_size  Minimum buffer size to contain the key material
 *
 * \retval #PSA_SUCCESS
 *         The minimum size for a buffer to contain the key material has been
 *         returned successfully.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         The type and/or the size in bits of the key or the combination of
 *         the two is not supported.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The key is declared with a lifetime not known to us.
 */
psa_status_t psa_driver_wrapper_get_key_buffer_size(
    const psa_key_attributes_t *attributes,
    size_t *key_buffer_size )
{
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION( psa_get_key_lifetime(attributes) );
    psa_key_type_t key_type = psa_get_key_type(attributes);
    size_t key_bits = psa_get_key_bits(attributes);

    *key_buffer_size = 0;
    switch( location )
    {
#if defined(PSA_CRYPTO_DRIVER_TEST)
        case PSA_CRYPTO_TEST_DRIVER_LOCATION:
#if defined(MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS)
            /* Emulate property 'builtin_key_size' */
            if( psa_key_id_is_builtin(
                    MBEDTLS_SVC_KEY_ID_GET_KEY_ID(
                        psa_get_key_id( attributes ) ) ) )
            {
                *key_buffer_size = sizeof( psa_drv_slot_number_t );
                return( PSA_SUCCESS );
            }
#endif /* MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS */
            *key_buffer_size = mbedtls_test_opaque_size_function( key_type,
                                                                  key_bits );
            return( ( *key_buffer_size != 0 ) ?
                    PSA_SUCCESS : PSA_ERROR_NOT_SUPPORTED );
#endif /* PSA_CRYPTO_DRIVER_TEST */
#if defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
#if defined(IFX_PSA_SE_DPA_PRESENT)
        case PSA_KEY_LOCATION_IFX_SE:
            *key_buffer_size = sizeof( ifx_se_key_id_fih_t );
            return( PSA_SUCCESS );
#endif /* IFX_PSA_SE_DPA_PRESENT */
#endif /* PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */

        default:
            (void)key_type;
            (void)key_bits;
            return( PSA_ERROR_INVALID_ARGUMENT );
    }
}

psa_status_t psa_driver_wrapper_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length )

{

    psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(
                                      psa_get_key_lifetime( attributes ) );

    /* Try dynamically-registered SE interface first */
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if( psa_get_se_driver( psa_get_key_lifetime(attributes), &drv, &drv_context ) )
    {
        if( ( drv->key_management == NULL ) ||
            ( drv->key_management->p_export_public == NULL ) )
        {
            return( PSA_ERROR_NOT_SUPPORTED );
        }

        return( drv->key_management->p_export_public(
                    drv_context,
                    *( (psa_key_slot_number_t *)key_buffer ),
                    data, data_size, data_length ) );
    }
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

    switch( location )
    {
        case PSA_KEY_LOCATION_LOCAL_STORAGE:
            /* Key is stored in the slot in export representation, so
             * cycle through all known transparent accelerators */
#if defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)

#if (defined(PSA_CRYPTO_DRIVER_TEST) )
            status = mbedtls_test_transparent_export_public_key
                (attributes,
                                key_buffer,
                                key_buffer_size,
                                data,
                                data_size,
                                data_length
            );

            if( status != PSA_ERROR_NOT_SUPPORTED )
                return( status );
#endif

#if (defined(MBEDTLS_PSA_P256M_DRIVER_ENABLED) )
            status = p256_transparent_export_public_key
                (attributes,
                                key_buffer,
                                key_buffer_size,
                                data,
                                data_size,
                                data_length
            );

            if( status != PSA_ERROR_NOT_SUPPORTED )
                return( status );
#endif

#if defined(IFX_PSA_MXCRYPTO_PRESENT) && defined(IFX_PSA_MXCRYPTO_PUBLIC_KEY_EXPORT)
            status = ifx_mxcrypto_transparent_export_public_key(
                         attributes,
                         key_buffer,
                         key_buffer_size,
                         data,
                         data_size,
                         data_length );
            if( status != PSA_ERROR_NOT_SUPPORTED )
                return( status );
#endif /* IFX_PSA_MXCRYPTO_PRESENT && IFX_PSA_MXCRYPTO_PUBLIC_KEY_EXPORT */
#if defined(IFX_PSA_CRYPTOLITE_PRESENT) && defined(IFX_PSA_CRYPTOLITE_PUBLIC_KEY_EXPORT)
            status = ifx_cryptolite_transparent_export_public_key(
                         attributes,
                         key_buffer,
                         key_buffer_size,
                         data,
                         data_size,
                         data_length );
            if( status != PSA_ERROR_NOT_SUPPORTED )
                return( status );
#endif /* IFX_PSA_CRYPTOLITE_PRESENT && IFX_PSA_CRYPTOLITE_PUBLIC_KEY_EXPORT */
#endif /* PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
            /* Fell through, meaning no accelerator supports this operation */
            return( psa_export_public_key_internal( attributes,
                                                    key_buffer,
                                                    key_buffer_size,
                                                    data,
                                                    data_size,
                                                    data_length ) );

        /* Add cases for opaque driver here */
#if defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)

#if (defined(PSA_CRYPTO_DRIVER_TEST) )
        case 0x7fffff:
            return( mbedtls_test_opaque_export_public_key
            (attributes,
                            key_buffer,
                            key_buffer_size,
                            data,
                            data_size,
                            data_length
        ));
#endif

#if defined(IFX_PSA_SE_DPA_PRESENT)
        case PSA_KEY_LOCATION_IFX_SE:
        {
            ifx_se_key_id_fih_t se_key = IFX_SE_KEY_ID_FIH_INIT;

            memcpy(&se_key, key_buffer, sizeof(se_key));

            return( ifx_se_get_psa_status( ifx_se_export_public_key(
                        se_key,
                        ifx_se_fih_ptr_encode(data),
                        ifx_se_fih_uint_encode(data_size),
                        ifx_se_fih_ptr_encode(data_length),
                        IFX_SE_NULL_CTX)) );
        }
#endif /* IFX_PSA_SE_DPA_PRESENT */
#endif /* PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
        default:
            /* Key is declared with a lifetime not known to us */
            return( status );
    }

}

psa_status_t psa_driver_wrapper_get_builtin_key(
    psa_drv_slot_number_t slot_number,
    psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length )
{

    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION( psa_get_key_lifetime(attributes) );
    switch( location )
    {
#if defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)

#if (defined(PSA_CRYPTO_DRIVER_TEST) )
        case 0x7fffff:
            return( mbedtls_test_opaque_get_builtin_key
            (slot_number,
                            attributes,
                            key_buffer,
                            key_buffer_size,
                            key_buffer_length
        ));
#endif
#if defined(IFX_PSA_SE_DPA_PRESENT) && defined(IFX_PSA_CRYPTO_BUILTIN_KEYS)
        /* Add cases for opaque driver here */
        case PSA_KEY_LOCATION_IFX_SE:
            return( ifx_mbedtls_get_builtin_key(
                        slot_number,
                        attributes,
                        key_buffer, key_buffer_size, key_buffer_length ) );
#endif /* IFX_PSA_SE_DPA_PRESENT && IFX_PSA_CRYPTO_BUILTIN_KEYS */
#endif /* PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
        default:
            (void) slot_number;
            (void) key_buffer;
            (void) key_buffer_size;
            (void) key_buffer_length;
            return( PSA_ERROR_DOES_NOT_EXIST );
    }

}
#endif /* MBEDTLS_PSA_CRYPTO_C */

#if defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
#if defined(IFX_PSA_SE_DPA_PRESENT)
void ifx_se_attributes_psa_to_se(const psa_key_attributes_t *attributes, ifx_se_key_attributes_t *se_attributes)
{
#if defined(MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
    se_attributes->id.key_id = attributes->id.key_id;
    se_attributes->id.owner  = attributes->id.owner;
#else
    se_attributes->id.key_id = attributes->id;
    se_attributes->id.owner = 0;
#endif /* MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER */

    se_attributes->type = attributes->type;
    se_attributes->bits = attributes->bits;
    se_attributes->lifetime = attributes->lifetime;

    memcpy(&se_attributes->policy, &attributes->policy, sizeof(psa_key_policy_t));
}

void ifx_se_attributes_se_to_psa(const ifx_se_key_attributes_t *se_attributes, psa_key_attributes_t *attributes)
{
#if defined(MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
    attributes->id.key_id = se_attributes->id.key_id;
    attributes->id.owner  = se_attributes->id.owner;
#else
    attributes->id = se_attributes->id.key_id;
#endif /* MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER */

    attributes->type = se_attributes->type;
    attributes->bits = se_attributes->bits;
    attributes->lifetime = se_attributes->lifetime;

    memcpy(&attributes->policy, &se_attributes->policy, sizeof(psa_key_policy_t));
}
#endif /* IFX_PSA_SE_DPA_PRESENT */
#endif /* PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
