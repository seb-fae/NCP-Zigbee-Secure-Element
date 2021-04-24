#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ECDSA_C)

#include "mbedtls/ecdsa.h"

#ifdef MBEDTLS_ECDSA_SIGN_ALT

int mbedtls_ecdsa_can_do( mbedtls_ecp_group_id gid )
{
  return 1;
}

/*
 * Compute ECDSA signature of a hashed message (SEC1 4.1.3)
 * Obviously, compared to SEC1 4.1.3, we skip step 4 (hash message)
 */
int mbedtls_ecdsa_sign(mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                       const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                       int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = 0;
    return ret;
}

#endif /* MBEDTLS_ECDSA_SIGN_ALT */

#endif /* MBEDTLS_ECDSA_C */

#if defined(MBEDTLS_ECDH_C)

#include "mbedtls/ecdh.h"
#include "mbedtls/platform_util.h"

#ifdef MBEDTLS_ECDH_GEN_PUBLIC_ALT
/** Generate ECDH keypair */
int mbedtls_ecdh_gen_public(mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *Q,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng)
{
    int ret = 0;
    return ret;
}
#endif /* MBEDTLS_ECDH_GEN_PUBLIC_ALT */

#ifdef MBEDTLS_ECDH_COMPUTE_SHARED_ALT
/*
 * Compute shared secret (SEC1 3.3.1)
 */
int mbedtls_ecdh_compute_shared(mbedtls_ecp_group *grp, mbedtls_mpi *z,
                                const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng)
{

    int ret = 0;
    return ret;
}
#endif /* MBEDTLS_ECDH_COMPUTE_SHARED_ALT */

#endif /* MBEDTLS_ECDH_C */

#include "efr32mg21b_mgmt.h"
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#define MAX 80
#define PORT 8080
#define SA struct sockaddr

int sockfd, connfd, len;
struct sockaddr_in servaddr, cli;

void open_socket_client()
{
    // socket create and varification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(PORT);

    // connect the client socket to server socket
    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) {
        printf("connection with the server failed...\n");
        exit(0);
    }
    else
        printf("connected to the server..\n");

}

uint8_t socket_buffer[1024];
void close_socket()
{
	// After chatting close the socket
	close(sockfd);
}

void print_socket_rsp(uint32_t size)
{
  for (uint32_t i = 0; i< size; i++)
    {
      if ((i%8) == 0)
        printf("0x%x\n", socket_buffer[i]);
      else
        printf("0x%x ", socket_buffer[i]);
    }
  printf("\n");
}

uint32_t read_cert_size(sl_se_cert_size_type_t * bsize)
{
  /* Send command on socket */
  socket_buffer[0] = 1;
  write(sockfd, socket_buffer, 1);
  /* Read from socket */
  uint32_t rsize = read(sockfd, bsize, sizeof(sl_se_cert_size_type_t));
  if (rsize > 0)
    /* Print receive buffer */
    print_socket_rsp(rsize);
}

uint32_t read_cert_data(uint8_t *buf, uint8_t cert_type)
{
}


uint32_t efr32mg21b_init()
{
  open_socket_client();
}

/***************************************************************************//**
 * Get the public key in device certificate.
 ******************************************************************************/
int32_t get_pub_device_key(mbedtls_x509_crt * cert, mbedtls_pk_context * pkey)
{
  int32_t ret = 0;
  mbedtls_ecp_keypair *ecp;

  if (!pkey)
   {
       ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
   }
 
   if (!ret)
   {
       mbedtls_pk_init(pkey);
       ret = mbedtls_pk_setup(pkey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
   }
 
   if (!ret)
   {
       ecp = mbedtls_pk_ec(*pkey);
       mbedtls_ecp_keypair_init(ecp);
       ret = mbedtls_ecp_group_load(&ecp->grp, MBEDTLS_ECP_DP_SECP256R1);
   }

   // Copy public key in device certificate to an ECP key-pair structure
   ret = mbedtls_ecp_copy(&ecp->Q, &mbedtls_pk_ec(cert->pk)->Q);

   return ret;
}

/***************************************************************************//**
 * Get certificate size.
 ******************************************************************************/
uint32_t get_cert_size(uint8_t cert_type)
{
  if (cert_type == SL_SE_CERT_BATCH) {
    return cert_size_buf.batch_id_size;
  } else if (cert_type == SL_SE_CERT_DEVICE_SE) {
    return cert_size_buf.se_id_size;
  } else if (cert_type == SL_SE_CERT_DEVICE_HOST) {
    return cert_size_buf.host_id_size;
  } else {
    return 0;
  }
}


uint32_t efr32mg21b_build_certificate_chain(mbedtls_x509_crt * cert, mbedtls_pk_context * pkey)
{
  state_t state = RD_CERT_SIZE; 
  while(1)
  {
    switch (state) {
       case RD_CERT_SIZE:
	/* We consider that SE is initialized here */
        state = SE_MANAGER_EXIT;
        printf("\n  . Secure Vault device:\n");
        printf("  + Read size of on-chip certificates... ");
        if (read_cert_size(&cert_size_buf) == 0) {
          state = RD_DEVICE_CERT;
        }
        break;

      case RD_DEVICE_CERT:
        state = SE_MANAGER_EXIT;
        printf("  + Read on-chip device certificate... ");
        if (read_cert_data(cert_buf, SL_SE_CERT_DEVICE_HOST) == 0) {
          state = PARSE_DEVICE_CERT;
        }
        break;
  
      case PARSE_DEVICE_CERT:
        state = SE_MANAGER_EXIT;
        printf("  + Parse the device certificate (DER format)... ");
        if (mbedtls_x509_crt_parse_der(cert, (const uint8_t *)cert_buf, get_cert_size(SL_SE_CERT_DEVICE_HOST)) == 0)
	  {
            if (get_pub_device_key(cert, pkey) == 0) {
              printf("OK\n");
            state = RD_BATCH_CERT;
	  }	  

        break;
  
      case RD_BATCH_CERT:
        state = SE_MANAGER_EXIT;
        printf("  + Read on-chip batch certificate... ");
        if (read_cert_data(cert_buf, SL_SE_CERT_BATCH) == 0) {
          state = PARSE_BATCH_CERT;
        }
        break;
  
      case PARSE_BATCH_CERT:
        state = SE_MANAGER_EXIT;
        printf("  + Parse the batch certificate (DER format)... ");
        if (mbedtls_x509_crt_parse_der(cert, (const uint8_t *)cert_buf, get_cert_size(SL_SE_CERT_BATCH)))
          state = PARSE_FACTORY_CERT;
        break;
  
      case PARSE_FACTORY_CERT:
        state = SE_MANAGER_EXIT;
        printf("\n  . Remote device:\n");
        printf("  + Parse the factory certificate (PEM format)... ");
        if (mbedtls_x509_crt_parse_der(cert, factory, sizeof(factory)))
          state = PARSE_ROOT_CERT;
        break;
  
      case PARSE_ROOT_CERT:
        state = SE_MANAGER_EXIT;
        printf("  + Parse the root certificate (PEM format)... ");
        if (mbedtls_x509_crt_parse_der(cert, root, sizeof(root)))
          state = VERIFY_CERT_CHAIN;
        }
        break;
      }     
  }
}


