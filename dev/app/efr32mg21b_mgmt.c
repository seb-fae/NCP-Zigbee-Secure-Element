#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#define SL_SE_APPLICATION_ATTESTATION_KEY 0
#define SL_SE_APPLICATION_ECDH_KEY 1

#define PUB_KEY_SIZE 64
#define SHARED_KEY_SIZE 32

#if defined(MBEDTLS_ECDSA_C)

#include "mbedtls/ecdsa.h"

#ifdef MBEDTLS_ECDSA_SIGN_ALT

int mbedtls_ecdsa_can_do( mbedtls_ecp_group_id gid )
{
    printf("\ncando\n");
    switch( gid )
    {
#ifdef MBEDTLS_ECP_DP_CURVE25519_ENABLED
        case MBEDTLS_ECP_DP_CURVE25519: return 0;
#endif
    default: return 1;
    }
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
    printf("\nsign %d\n", *(uint16_t*)d->p);
    return ret;
}

#endif /* MBEDTLS_ECDSA_SIGN_ALT */

#endif /* MBEDTLS_ECDSA_C */

#if defined(MBEDTLS_ECDH_C)

#include "mbedtls/ecdh.h"
#include "mbedtls/platform_util.h"

#include "message_queue.h"
#include "efr32mg21b_mgmt.h"

MessageQBuffer_t message_in;
MessageQBuffer_t message_out;

#ifdef MBEDTLS_ECDH_GEN_PUBLIC_ALT
/** Generate ECDH keypair */
int mbedtls_ecdh_gen_public(mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *Q,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng)
{
  printf("\ngenerate ecdh keypair %d\n", grp->id);

  int ret = 0;
  uint8_t temp = 1;

  if (!grp || !d || !Q)
  {
      return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
  }

  if (grp->id != MBEDTLS_ECP_DP_SECP256R1)
  {
      return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
  }

  ret = mbedtls_mpi_lset(d, SL_SE_APPLICATION_ECDH_KEY);

  if (ret)
    return ret;	    

  /* Send message */  
  message_out.mtype = 1;
  message_out.mtext[0] = CMD_GENERATE_ECDH_KEYPAIR_GENERATE;
  send_message(&message_out, 1);
  /* Read message */
  ssize_t rsize = read_message(&message_in);
  print_buffer(message_in.mtext, rsize);

  ret = mbedtls_mpi_read_binary(&(Q->X), message_in.mtext, PUB_KEY_SIZE / 2);

  if (ret)
    return ret;	   

  ret = mbedtls_mpi_read_binary(&(Q->Y), message_in.mtext + (PUB_KEY_SIZE / 2), PUB_KEY_SIZE / 2);
  
  if (ret)
    return ret;	   

  ret = mbedtls_mpi_read_binary(&(Q->Z), &temp, 1);

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
  printf("\ncompute shared %d %d\n", grp->id, *(uint16_t*)d->p);


  if (!grp || !z || !Q || !d)
    return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

  if (grp->id != MBEDTLS_ECP_DP_SECP256R1)
    return  MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;

  /* Send message */  
  message_out.mtype = 1;
  message_out.mtext[0] = CMD_GENERATE_ECDH_COMPUTE_SHARED;

  ret = mbedtls_mpi_write_binary(&(Q->X), message_out.mtext + 1, PUB_KEY_SIZE / 2);

  if (ret)
    return ret;	

  ret = mbedtls_mpi_write_binary(&(Q->Y), message_out.mtext + (PUB_KEY_SIZE / 2) + 1, PUB_KEY_SIZE / 2);
  
  if (ret)
    return ret;

  send_message(&message_out, 1);
  /* Read message */
  ssize_t rsize = read_message(&message_in);
  print_buffer(message_in.mtext, rsize);
 
  ret = mbedtls_mpi_read_binary(z, message_in.mtext, SHARED_KEY_SIZE);
  
  return ret;
}
#endif /* MBEDTLS_ECDH_COMPUTE_SHARED_ALT */

#endif /* MBEDTLS_ECDH_C */

int32_t read_cert_size(sl_se_cert_size_type_t * bsize)
{
  /* Send message */  
  message_out.mtype = 1;
  message_out.mtext[0] = CMD_RD_CERT_SIZE;
  send_message(&message_out, 1);
  /* Read message */
  ssize_t rsize = read_message(&message_in);

  if (rsize != sizeof(sl_se_cert_size_type_t))
    return -1;

  print_buffer(message_in.mtext, rsize);
  memcpy(&cert_size_buf, message_in.mtext, rsize);
  return 0;
}

uint32_t read_cert_data(uint8_t *buf, uint8_t cert_type)
{
  /* Send message */  
  message_out.mtype = 1;

  switch (cert_type)
  {
    case SL_SE_CERT_DEVICE_HOST:
      message_out.mtext[0] = CMD_RD_DEVICE_CERT;
      break; 
    default:
      message_out.mtext[0] = CMD_RD_BATCH_CERT;
      break;
  }

  send_message(&message_out, 1);
  /* Read message */
  ssize_t rsize = read_message(&message_in);

  print_buffer(message_in.mtext, rsize);
  memcpy(buf, message_in.mtext, rsize);
  return 0;
}


uint32_t efr32mg21b_init()
{
  init_message_queue();
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

   if (!ret)
   // Copy public key in device certificate to an ECP key-pair structure
     ret = mbedtls_ecp_copy(&ecp->Q, &mbedtls_pk_ec(cert->pk)->Q);

   if (!ret)
     ret = mbedtls_mpi_lset(&ecp->d, SL_SE_APPLICATION_ATTESTATION_KEY);

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
static int verify_callback(void *data,
                           mbedtls_x509_crt *crt,
                           int depth,
                           uint32_t *flags)
{
  (void) data;
  char buf[1024];
  int32_t i;
  int32_t ret;

  // Get information about the certificate
  ret = mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "      ", crt);
  printf("  + Verify requested for (Depth %d) ... ok\n", depth);
  for (i = 0; i < ret; i++) {
    printf("%c", buf[i]);
  }

  // Get the verification status of a certificate
  if ((*flags) != 0) {
    ret = mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", *flags);
    for (i = 0; i < ret; i++) {
      printf("%c", buf[i]);
    }
  }
  if (depth == 0) {
    printf("  + Verify the certificate chain with root certificate... ");
  }
  return 0;
}

uint32_t efr32mg21b_build_certificate_chain(mbedtls_x509_crt * cert, mbedtls_pk_context * pkey)
{
  uint32_t flags;	
  state_t state = RD_CERT_SIZE;
  mbedtls_x509_crt cacert;

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
          printf("ok\n");
        }
        break;

      case RD_DEVICE_CERT:
        state = SE_MANAGER_EXIT;
        printf("  + Read on-chip device certificate... ");
        if (read_cert_data(cert_buf, SL_SE_CERT_DEVICE_HOST) == 0) {
          state = PARSE_DEVICE_CERT;
          printf("ok\n");
        }
        break;
  
      case PARSE_DEVICE_CERT:
        state = SE_MANAGER_EXIT;
        printf("  + Parse the device certificate (DER format)... ");
        if (mbedtls_x509_crt_parse_der(cert, (const uint8_t *)cert_buf, get_cert_size(SL_SE_CERT_DEVICE_HOST)) == 0)
	  {
            if (get_pub_device_key(cert, pkey) == 0) {
              printf("ok\n");
              state = RD_BATCH_CERT;}
	  }	  
	else 
          printf("error\n");

        break;
  
      case RD_BATCH_CERT:
        state = SE_MANAGER_EXIT;
        printf("  + Read on-chip batch certificate... ");
        if (read_cert_data(cert_buf, SL_SE_CERT_BATCH) == 0)
	{	
          printf("ok\n");
          state = PARSE_BATCH_CERT;
	}
        break;
  
      case PARSE_BATCH_CERT:
        state = SE_MANAGER_EXIT;
        printf("  + Parse the batch certificate (DER format)... ");
        if (mbedtls_x509_crt_parse_der(cert, (const uint8_t *)cert_buf, get_cert_size(SL_SE_CERT_BATCH)) == 0)
	{
          printf("ok\n");
          state = PARSE_FACTORY_CERT;
	}
	else 
          printf("error\n");
        break;

/*  --------------------------------------------------------------- */

      case PARSE_FACTORY_CERT:
        state = SE_MANAGER_EXIT;
        printf("\n  . Remote device:\n");
        printf("  + Parse the factory certificate (PEM format)... ");
        if (mbedtls_x509_crt_parse(cert, factory, sizeof(factory)) == 0)
	{
          state = PARSE_ROOT_CERT;
          printf("ok\n");
	}
	else 
          printf("error\n");
        break;

      case PARSE_ROOT_CERT:
        state = SE_MANAGER_EXIT;
        printf("  + Parse the root certificate (PEM format)... ");
        mbedtls_x509_crt_init(&cacert);
        if (mbedtls_x509_crt_parse(&cacert, root, sizeof(root)) == 0)
	{
          state = VERIFY_CERT_CHAIN;
          printf("ok\n");
	}
	else 
          printf("error\n");
        break;

    case VERIFY_CERT_CHAIN:
      printf("  + Verify the certificate chain with root certificate... \n");
      if (mbedtls_x509_crt_verify(cert, &cacert, NULL, NULL, &flags, verify_callback, NULL) == 0) 
        printf("ok\n");
      else 
        printf("error\n");
      return;
    }     
  }
}


