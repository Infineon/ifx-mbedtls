# ifx-mbedtls

A middleware library for PSoC™ Edge MCU E84 and PSoC™ Control BSP platforms that is a fork of the mbed TLS project (https://github.com/Mbed-TLS/mbedtls).  
It is maintained by Infineon Technologies AG and provides additional features and platform support for Infineon microcontrollers.

### What's Included?
* Complete mbedTLS 3.6.0 cryptographic library implementation with PSA Crypto API
* Hardware acceleration support for Infineon hardware accelerators (MxCrypto, MxCryptolite)
* Platform-specific configurations for:
  - PSoC™ Edge MCU E84 (PSE84)
  - PSoC™ Control BSP (PSC3)
* Secure Enclave Runtime Services (SE RT) integration
* TF-M compatibility for PSA Crypto client configurations
* ModusToolbox™ integration


### What Changed?
#### v3.6.200
* Add support for exporting TLS 1.3 keys and retrieving resumption state
* Enable mbedtls_md_error_from_psa function for PSA Crypto client configurations to support external PSA implementations like TF-M
* Fix warnings in TLS 1.3 code and IAR compiler-related warnings
* Remove placeholders for asymmetric decrypt/encrypt operations for MxCryptolite

#### v3.6.100
* Update mbedTLS to 3.6.0
* Change infineon_platform.h include logic. Now, if user does not define MBEDTLS_CONFIG_FILE and builds PSE84 or PSC3 target, the appropriate platform-specific configuration is automatically included.
* Automatically enable crypto hardware in psa_crypto_init() function by reserving VU hardware acceleration
* Add MxCrypto or MxCryptolite for accelerated PSA key agreement
* Disable unsupported asymmetric cryptography operations for SE RT in psa_crypto_driver_wrappers.h
* Add AES alternative includes for crypto accelerators
* Fix compiler warnings related to mbedTLS 3.6.0 migration

#### v3.5.102
* Initial release (mbedTLS v3.5.2)


### Configuration Specific Options

#### mbedTLS Configuration Paths
* `COMPONENT_MW_IFX_MBEDTLS` - Enable automatic Infineon platform detection. Set automatically by ModusToolbox™ Software Environment.
* `MBEDTLS_CONFIG_FILE` - Path to custom mbedTLS configuration header file. If not defined, ifx-mbedtls automatically uses platform-specific configuration for PSE84/PSC3 targets if `COMPONENT_MW_IFX_MBEDTLS` is present.
* `MBEDTLS_PSA_CRYPTO_CONFIG_FILE` - Path to custom PSA Crypto configuration header file. Defines which PSA Crypto algorithms and key types are supported.
* `MBEDTLS_USER_CONFIG_FILE` - Path to user-specific configuration file that overrides default settings. Applied after platform and PSA configurations.

#### PSA Crypto Configuration
* `MBEDTLS_PSA_CRYPTO_C` - Enable PSA Crypto implementation.
* `MBEDTLS_PSA_CRYPTO_CLIENT` - Enable PSA Crypto client mode for external PSA implementations like TF-M.
* `MBEDTLS_PSA_CRYPTO_CONFIG` - Enable PSA-based cryptographic configuration allowing separate control of PSA API mechanisms from mbedTLS API mechanisms using PSA_WANT_XXX symbols.
* `MBEDTLS_PSA_CRYPTO_DRIVERS` - Enable PSA Crypto driver interface for hardware acceleration (MxCrypto, MxCryptolite) and SE RT.

#### Hardware Acceleration Drivers
* `COMPONENT_MW_CY_MBEDTLS_ACCELERATION` - Enable platform-specific hardware acceleration. MxCrypto for PSE84 and MxCryptolite for PSC3 based on target platform.
* `IFX_PSA_MXCRYPTO_PRESENT` - Enable MxCrypto transparent driver for hardware acceleration.
* `IFX_PSA_CRYPTOLITE_PRESENT` - Enable MxCryptolite transparent driver for hardware acceleration.
* `IFX_PSA_SE_DPA_PRESENT` - Enable Secure Enclave Runtime Services crypto driver for hardware-backed operations.

#### Secure Enclave Configuration
* `IFX_PSA_SHA256_BY_SE_DPA` - Use Secure Enclave Runtime Services to calculate SHA256 digest operations.
* `IFX_PSA_RANDOM_BY_SE_DPA` - Use Secure Enclave Runtime Services to generate cryptographically secure random values.
* `IFX_PSA_CRYPTO_BUILTIN_KEYS` - Enable support for SE RT built-in keys.
* `MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS` - Enable PSA platform built-in key support with keys stored in SE RT Services.

### Supported Software and Tools
This version of ifx-mbedtls was validated for compatibility with the following Software and Tools:

| Software and Tools                        | Version |
| :---                                      | :----:  |
| ModusToolbox™ Software Environment        | 3.6.0   |
| GCC Compiler                              | 14.2.1  |
| IAR Compiler                              | 9.50.2  |
| ARM Compiler                              | 6.22    |


---
© Cypress Semiconductor Corporation (an Infineon company) or an affiliate of Cypress Semiconductor Corporation, 2019-2025.