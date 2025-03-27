/**
 * \file infineon_platform.h
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

#ifndef INFINEON_PLATFOM_H
#define INFINEON_PLATFOM_H

/* PSC3 platform */
#if defined(COMPONENT_PSC3)
#include "target/infineon/mbedtls/psc3/psc3_mbedtls_user_config.h"
#include "target/infineon/mbedtls/psc3/psc3_mbedtls_config.h"
#elif defined(COMPONENT_PSE84)
/* PSE84 platform */
#include "target/infineon/mbedtls/pse84/pse84_mbedtls_user_config.h"
#include "target/infineon/mbedtls/pse84/pse84_mbedtls_config.h"
#else
/* Using default mbedtls config */
#include "mbedtls/mbedtls_config.h"
#endif

#endif /* INFINEON_PLATFOM_H */
