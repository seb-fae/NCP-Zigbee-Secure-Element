#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

/* System Includes */
#include "stdio.h"
#include "stdlib.h"
#include "stdint.h"
#include <string.h>

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

#include "efr32mg21b_mgmt.h"

uint32_t efr32mg21b_build_certificate_chain(mbedtls_x509_crt * cert, mbedtls_pk_context * pkey);

static void my_debug(
    void *ctx, int level, const char *file, int line, const char *str)
{
    (void) level;
    printf("%s:%04d: %s", file, line, str);
}

int efr32mg21_connect(
    const char * endpoint, const char * port, const char * cn,
    const char * cafile)
{
    int ret;
    mbedtls_net_context server_fd;
    const char *pers = "ssl_client1";

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_pk_context pkey;
    mbedtls_x509_crt cert;
    mbedtls_x509_crl crl;
    /*
    * 0. Initialize the RNG and the session data
    */
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&cert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_debug_set_threshold(4);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

    printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0)
    {
        printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    printf(" ok\n");

    /* Set Up Defaults */
    printf("  . Setting up the SSL/TLS structure...");
    fflush(stdout);

    if ((ret = mbedtls_ssl_config_defaults(&conf,
            MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM,
            MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    printf(" ok\n");


    /* Extract the CA certificate and convert to mbedtls cert */
    if (0 != mbedtls_x509_crt_parse_file(&cacert, cafile))
    {
        printf("Failed to parse cert from CA\n");
        goto exit;
    }


    printf("Openning communication with secure element ...\n");
    efr32mg21b_init();


    printf("Build certificate chain ...\n");
    /* Build EFR32MG21B certificate chain */
    efr32mg21b_build_certificate_chain(&cert, &pkey);
	
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);

    /* Attach the certificate chain and private key to the SSL/TLS context */
    printf("  . Set up the client credentials.");
    fflush(stdout);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    if (0 != (ret = mbedtls_ssl_conf_own_cert(&conf, &cert, &pkey)))
    {
        printf(" failed\n ! mbedtls_ssl_conf_own_cert returned %d\r\n", ret);
        goto exit;
    }
    printf(" ok\n");

    /* Set up the "ssl" session */
    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
    {
        printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    printf("set hostname %s\n", cn);
    if ((ret = mbedtls_ssl_set_hostname(&ssl, cn)) != 0)
    {
        printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        goto exit;
    }

    /* Start the connection */
    printf("  . Connecting to tcp/%s/%s...", endpoint, port);
    fflush(stdout);

    if ((ret = mbedtls_net_connect(&server_fd, endpoint, port, MBEDTLS_NET_PROTO_TCP)) != 0)
    {
        printf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
        goto exit;
    }

    printf(" ok\n");

    /* Attach the open handle to the ssl context */
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    /* Start the tls handshake (opens the socket itself) */
    printf("  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
            goto exit;
        }
    }
    printf(" ok\n");

    printf("TLS Session Established and a Socket is ready for an Application\n");


    while( 1 )
    {
      /* Put your code here */
    }
 
    mbedtls_ssl_close_notify(&ssl);

exit:

    mbedtls_net_free(&server_fd);
    mbedtls_pk_free(&pkey);
    mbedtls_x509_crt_free(&cert);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}

int main(int argc, char *argv[])
{
    if (argc < 4)
    {
        printf("\nUsage: %s <server> <port> <cn> <cafile>\n", argv[0]);
        return -1;
    }
    else
    {
        return efr32mg21_connect(argv[1], argv[2], argv[3], argv[4]);
    }
}
