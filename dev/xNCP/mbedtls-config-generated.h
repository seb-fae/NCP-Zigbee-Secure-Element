/***************************************************************************//**
 * @file mbedtls-config-generated.h
 * @brief mbed TLS configuration file. This file is generated do not modify it directly. Please use the mbed TLS setup instead.
 *
 *******************************************************************************
 * # License
 * <b>Copyright 2018 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of Silicon Labs Master Software License
 * Agreement (MSLA) available at
 * www.silabs.com/about-us/legal/master-software-license-agreement. This
 * software is distributed to you in Source Code format and is governed by the
 * sections of the MSLA applicable to Source Code.
 *
 ******************************************************************************/

#ifndef MBEDTLS_CONFIG_GENERATED_H
#define MBEDTLS_CONFIG_GENERATED_H

#if !defined(EMBER_TEST)
#define MBEDTLS_NO_PLATFORM_ENTROPY

#else
// mbedtls/library/entropy_poll.c needs this,
// implicit declaration of function 'syscall' otherwise
#define _GNU_SOURCE
#endif

// Generated content that is coming from contributor plugins



#define MBEDTLS_AES_C
#define MBEDTLS_ECP_MAX_BITS           256


#define MBEDTLS_MPI_MAX_SIZE    32

#define MBEDTLS_AES_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_CCM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ENTROPY_HARDWARE_ALT
#define MBEDTLS_MD_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_ENTROPY_FORCE_SHA256
#define MBEDTLS_ENTROPY_MAX_SOURCES  2
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_CRL_PARSE_C
#define MBEDTLS_X509_CSR_PARSE_C
#define MBEDTLS_OID_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PSA_CRYPTO_DRIVERS
#define MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDH_LEGACY_CONTEXT


#include "config-device-acceleration.h"

#if !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
#include "sl_malloc.h"

#define MBEDTLS_PLATFORM_FREE_MACRO    sl_free
#define MBEDTLS_PLATFORM_CALLOC_MACRO  sl_calloc
#endif

#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_C


// Inclusion of the Silabs specific device acceleration configuration file.
#if defined(MBEDTLS_DEVICE_ACCELERATION_CONFIG_FILE)
#include MBEDTLS_DEVICE_ACCELERATION_CONFIG_FILE
#endif

// Inclusion of the app specific device acceleration configuration file.
#if defined(MBEDTLS_DEVICE_ACCELERATION_CONFIG_APP_FILE)
#include MBEDTLS_DEVICE_ACCELERATION_CONFIG_APP_FILE
#endif

// Inclusion of the mbed TLS config_check.h header file.
#include "mbedtls/check_config.h"

#endif /* MBEDTLS_CONFIG_GENERATED_H */
