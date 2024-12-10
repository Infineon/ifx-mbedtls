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
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION( attributes->core.lifetime );
    psa_key_type_t key_type = attributes->core.type;
    size_t key_bits = attributes->core.bits;

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
            *key_buffer_size = sizeof( mbedtls_svc_key_id_t );
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

    if( psa_get_se_driver( attributes->core.lifetime, &drv, &drv_context ) )
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
            mbedtls_svc_key_id_t se_key_id;

            memcpy(&se_key_id, key_buffer, sizeof(mbedtls_svc_key_id_t));

            return( ifx_se_get_psa_status( ifx_se_export_public_key(
                        ifx_se_fih_uint_encode(MBEDTLS_SVC_KEY_ID_GET_KEY_ID(se_key_id)),
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

    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION( attributes->core.lifetime );
    switch( location )
    {
#if defined(PSA_CRYPTO_DRIVER_TEST)

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

#endif /* PSA_CRYPTO_DRIVER_TEST */
#if defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
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

psa_status_t psa_driver_get_tag_len( psa_aead_operation_t *operation,
                                     uint8_t *tag_len )
{
    if( operation == NULL || tag_len == NULL )
        return( PSA_ERROR_INVALID_ARGUMENT );

#if defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
#if defined(PSA_CRYPTO_DRIVER_TEST)
    *tag_len = operation->ctx.transparent_test_driver_ctx.tag_length;
    return ( PSA_SUCCESS );
#endif
#if defined(IFX_PSA_MXCRYPTO_PRESENT) && defined(IFX_PSA_MXCRYPTO_AEAD)
    if( operation->id == IFX_MXCRYPTO_TRANSPARENT_DRIVER_ID )
    {
        *tag_len = operation->ctx.ifx_mxcrypto_ctx.tag_length;
        return ( PSA_SUCCESS );
    }
#endif /* IFX_PSA_MXCRYPTO_PRESENT && IFX_PSA_MXCRYPTO_AEAD */
#if defined(IFX_PSA_CRYPTOLITE_PRESENT) && defined(IFX_PSA_CRYPTOLITE_AEAD)
    if( operation->id == IFX_CRYPTOLITE_TRANSPARENT_DRIVER_ID )
    {
        *tag_len = operation->ctx.ifx_cryptolite_ctx.tag_length;
        return ( PSA_SUCCESS );
    }
#endif /* IFX_PSA_CRYPTOLITE_PRESENT && IFX_PSA_CRYPTOLITE_AEAD */
#if defined(IFX_PSA_SE_DPA_PRESENT)
    if( operation->id == IFX_SE_DPA_DRIVER_ID )
    {
        *tag_len = 16U;
        return ( PSA_SUCCESS );
    }
#endif /* IFX_PSA_ENDEAVOURCL_PRESENT */
#endif
    *tag_len = operation->ctx.mbedtls_ctx.tag_length;
    return ( PSA_SUCCESS );
}

#endif /* MBEDTLS_PSA_CRYPTO_C */

#if defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
#if defined(IFX_PSA_SE_DPA_PRESENT)
void ifx_se_attributes_psa_to_se(const psa_key_attributes_t *attributes, ifx_se_key_attributes_t *se_attributes)
{
#if defined(MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
    se_attributes->core.id = MBEDTLS_SVC_KEY_ID_GET_KEY_ID(attributes->core.id);
    se_attributes->core.type = attributes->core.type;
    se_attributes->core.bits = attributes->core.bits;
    se_attributes->core.lifetime = attributes->core.lifetime;
    se_attributes->core.flags = attributes->core.flags;

    se_attributes->domain_parameters = attributes->domain_parameters;
    se_attributes->domain_parameters_size = attributes->domain_parameters_size;

    memcpy(&se_attributes->core.policy, &attributes->core.policy, sizeof(psa_key_policy_t));
#else
    memcpy(se_attributes, attributes, sizeof(psa_key_attributes_t));
#endif /* MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER */
}

void ifx_se_attributes_se_to_psa(const ifx_se_key_attributes_t *se_attributes, psa_key_attributes_t *attributes)
{
#if defined(MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
    attributes->core.id = mbedtls_svc_key_id_make(0, se_attributes->core.id);
    attributes->core.type = se_attributes->core.type;
    attributes->core.bits = se_attributes->core.bits;
    attributes->core.lifetime = se_attributes->core.lifetime;
    attributes->core.flags = se_attributes->core.flags;

    attributes->domain_parameters = se_attributes->domain_parameters;
    attributes->domain_parameters_size = se_attributes->domain_parameters_size;

    memcpy(&attributes->core.policy, &se_attributes->core.policy, sizeof(psa_key_policy_t));
#else
    memcpy(attributes, se_attributes, sizeof(psa_key_attributes_t));
#endif /* MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER */
}
#endif /* IFX_PSA_SE_DPA_PRESENT */
#endif /* PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
