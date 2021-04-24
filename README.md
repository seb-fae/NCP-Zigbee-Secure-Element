# NCP-Zigbee-Secure-Element

## Compile Mbedtls

We want to delegate ECC cryptographic operation to EFR32MG21B. For that we are going to use alternate definitions for ECC operations.

```
export PROJECT_PATH=/path/to/NCP-Zigbee-Secure-Element
cd mbedtls
CFLAGS="-I$PROJECT_PATH/dev -DMBEDTLS_CONFIG_FILE=\<mbedtls_config.h\>" make no_test
```
You should otbain linking error for mbedtls_ecdh_gen_public, mbedtls_ecdsa_sign, mbedtls_ecdh_compute_shared, mbedtls_ecdsa_can_do.
This is normal.

## Compile application

```
gcc dev/efr32mg21b_mgmt.c dev/connect_hw.c -o connect -I$PROJECT_PATH/mbedtls/include/ -I$PROJECT_PATH/dev -DMBEDTLS_CONFIG_FILE='<mbedtls_config.h>' -L $PROJECT_PATH/mbedtls/library -lmbedtls -lmbedx509 -lmbedcrypto
```
