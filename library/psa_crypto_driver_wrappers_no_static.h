/*
 *  Function signatures for functionality that can be provided by
 *  cryptographic accelerators.
 */
/*  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PSA_CRYPTO_DRIVER_WRAPPERS_NO_STATIC_H
#define PSA_CRYPTO_DRIVER_WRAPPERS_NO_STATIC_H

#include "psa/crypto.h"
#include "psa/crypto_driver_common.h"

#if defined(IFX_PSA_SE_DPA_PRESENT)
#ifndef PSA_CRYPTO_DRIVER_PRESENT
#define PSA_CRYPTO_DRIVER_PRESENT
#endif
#ifndef PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT
#define PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT
#endif
#include "ifx_se_psacrypto.h"
#endif /* IFX_PSA_SE_DPA_PRESENT */

psa_status_t psa_driver_wrapper_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length);

psa_status_t psa_driver_wrapper_get_key_buffer_size(
    const psa_key_attributes_t *attributes,
    size_t *key_buffer_size);

psa_status_t psa_driver_wrapper_get_builtin_key(
    psa_drv_slot_number_t slot_number,
    psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length);

#if defined(IFX_PSA_SE_DPA_PRESENT)
void ifx_se_attributes_psa_to_se(const psa_key_attributes_t *attributes, ifx_se_key_attributes_t *se_attributes);
void ifx_se_attributes_se_to_psa(const ifx_se_key_attributes_t *se_attributes, psa_key_attributes_t *attributes);
#endif /* IFX_PSA_SE_DPA_PRESENT */

#endif /* PSA_CRYPTO_DRIVER_WRAPPERS_NO_STATIC_H */

/* End of automatically generated file. */
