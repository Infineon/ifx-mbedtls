/**
 * \file psc3_mbedtls_user_config.h
 *
 * \brief Configuration options (set of defines)
 *
 *  This set of compile-time options may be used to enable
 *  or disable platform specific features.
 *
 *******************************************************************************
 * \copyright
 * Copyright 2025, Cypress Semiconductor Corporation (an Infineon company).
 * All rights reserved.
 * You may use this file only in accordance with the license, terms, conditions,
 * disclaimers, and limitations in the end user license agreement accompanying
 * the software package with which this file was provided.
 ******************************************************************************/

#ifndef PSC3_MBEDTLS_USER_CONFIG_H
#define PSC3_MBEDTLS_USER_CONFIG_H

#ifdef COMPONENT_MW_CY_MBEDTLS_ACCELERATION
/* Enable CRYPTOLITE transparent driver */
#define IFX_PSA_CRYPTOLITE_PRESENT
#endif /* COMPONENT_MW_CY_MBEDTLS_ACCELERATION */

#endif /* PSC3_MBEDTLS_USER_CONFIG_H */
