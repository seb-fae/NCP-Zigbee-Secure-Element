#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

/* From mbedtls */
#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"

#include <string.h>

typedef enum {
  SE_MANAGER_IDLE,
  RD_CERT_SIZE,
  RD_DEVICE_CERT,
  PARSE_DEVICE_CERT,
  RD_BATCH_CERT,
  PARSE_BATCH_CERT,
  PARSE_FACTORY_CERT,
  PARSE_ROOT_CERT,
  VERIFY_CERT_CHAIN,
  CREATE_CHALLENGE,
  SIGN_CHALLENGE,
  GET_PUBLIC_DEVICE_KEY,
  VERIFY_SIGNATURE_LOCAL,
  VERIFY_SIGNATURE_REMOTE,
  SE_MANAGER_EXIT
} state_t;

typedef enum {
  CMD_RD_CERT_SIZE,
  CMD_RD_DEVICE_CERT,
  CMD_RD_BATCH_CERT,
  CMD_VERIFY_CERT_CHAIN,
  CMD_SIGN_CHALLENGE,
  CMD_GET_PUBLIC_DEVICE_KEY,
  CMD_VERIFY_SIGNATURE_LOCAL,
  CMD_VERIFY_SIGNATURE_REMOTE,
  CMD_GENERATE_ECDH_KEYPAIR_GENERATE,
  CMD_GENERATE_ECDH_COMPUTE_SHARED
 } cmd_t;
/// Batch ID certificate
#define SL_SE_CERT_BATCH                          0x01
/// SE ID certificate
#define SL_SE_CERT_DEVICE_SE                      0x02
/// Host ID certificate
#define SL_SE_CERT_DEVICE_HOST                    0x03

/// Certificate buffer size
#define CERT_SIZE       (512)

/// Certificate buffer
static uint8_t cert_buf[CERT_SIZE];

/// Certificate size data structure
typedef struct {
  uint32_t batch_id_size;    ///< size in bytes of the Batch certificate
  uint32_t se_id_size;       ///< size in bytes of the SE ID certificate
  uint32_t host_id_size;     ///< size in bytes of the Host ID certificate
} sl_se_cert_size_type_t;

/// Certificate size buffer
static sl_se_cert_size_type_t cert_size_buf;


/// Factory certificate
static const uint8_t factory[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIICEjCCAbmgAwIBAgIIJNx7QAwynAowCgYIKoZIzj0EAwIwQjEXMBUGA1UEAwwO\n"
  "RGV2aWNlIFJvb3QgQ0ExGjAYBgNVBAoMEVNpbGljb24gTGFicyBJbmMuMQswCQYD\n"
  "VQQGEwJVUzAgFw0xODEwMTAxNzMzMDBaGA8yMTE4MDkxNjE3MzIwMFowOzEQMA4G\n"
  "A1UEAwwHRmFjdG9yeTEaMBgGA1UECgwRU2lsaWNvbiBMYWJzIEluYy4xCzAJBgNV\n"
  "BAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEatHnJa9nUyTyJtuY6xgE\n"
  "msybdzjhCbmKo3qMzAt/GQ4/TKIXkCwhw1Ni6kmQzh4qrINPYWP8vnG6tPJUyzUp\n"
  "VKOBnTCBmjASBgNVHRMBAf8ECDAGAQH/AgEBMB8GA1UdIwQYMBaAFBCLCj7NdHWU\n"
  "9EyEIs2OIqSrMaVCMDQGA1UdHwQtMCswKaAnoCWGI2h0dHA6Ly9jYS5zaWxhYnMu\n"
  "Y29tL2RldmljZXJvb3QuY3JsMB0GA1UdDgQWBBRDYoRJaG86aXx20B/lHSr513PR\n"
  "FjAOBgNVHQ8BAf8EBAMCAYYwCgYIKoZIzj0EAwIDRwAwRAIgY34nvceLA1h3xYgt\n"
  "mdzguHn7yNYlJQXDp7F8iNLRTBkCIAwkPej1R90Hw2o48eNvOmJG+QeLAUdVlIGY\n"
  "07PRgSaC\n"
  "-----END CERTIFICATE-----\n";

/// Root certificate
static const uint8_t root[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIICGTCCAcCgAwIBAgIIEuaipZyqJ/kwCgYIKoZIzj0EAwIwQjEXMBUGA1UEAwwO\n"
  "RGV2aWNlIFJvb3QgQ0ExGjAYBgNVBAoMEVNpbGljb24gTGFicyBJbmMuMQswCQYD\n"
  "VQQGEwJVUzAgFw0xODEwMTAxNzMyMDBaGA8yMTE4MDkxNjE3MzIwMFowQjEXMBUG\n"
  "A1UEAwwORGV2aWNlIFJvb3QgQ0ExGjAYBgNVBAoMEVNpbGljb24gTGFicyBJbmMu\n"
  "MQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNAp5f+cr+v9\n"
  "zxfMQMJjxLxaqdBWe4nTrCwHihHtxYZDYsSBgdzZ3VFUu0xTlP07dWsuCL99abzl\n"
  "Qyqak+tdTS2jgZ0wgZowEgYDVR0TAQH/BAgwBgEB/wIBAjAfBgNVHSMEGDAWgBQQ\n"
  "iwo+zXR1lPRMhCLNjiKkqzGlQjA0BgNVHR8ELTArMCmgJ6AlhiNodHRwOi8vY2Eu\n"
  "c2lsYWJzLmNvbS9kZXZpY2Vyb290LmNybDAdBgNVHQ4EFgQUEIsKPs10dZT0TIQi\n"
  "zY4ipKsxpUIwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMCA0cAMEQCIGlwr4G7\n"
  "IkG/9XHHk1WPthnY/yNNIzP9pThZkg2zU88ZAiBkAhsPaMKE7NOwWQIBgxy9nevX\n"
  "c7VKkqNr4UAU5zPbxg==\n"
  "-----END CERTIFICATE-----\n";


