# NCP-Zigbee-Secure-Element

## Compile Mbedtls

We want to delegate ECC cryptographic operation to EFR32MG21B. For that we are going to use alternate definitions for ECC operations.

```
export PROJECT_LOC=/path/to/NCP-Zigbee-Secure-Element
cd mbedtls
CFLAGS="-I$PROJECT_LOC/dev -DMBEDTLS_CONFIG_FILE=\<mbedtls_config.h\>" make no_test
```
You should otbain linking error for mbedtls_ecdh_gen_public, mbedtls_ecdsa_sign, mbedtls_ecdh_compute_shared, mbedtls_ecdsa_can_do.
This is normal.

## Compile application

```
gcc dev/app/efr32mg21b_mgmt.c dev/app/connect_hw.c dev/app/message_queue.c -o connect -I$PROJECT_LOC/mbedtls/include/ -I$PROJECT_LOC/dev/app -DMBEDTLS_CONFIG_FILE=\<mbedtls_config.h\> -L $PROJECT_LOC/mbedtls/library/ -lmbedtls -lmbedx509 -lmbedcrypto
```
