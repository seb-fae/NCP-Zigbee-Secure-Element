# NCP-Zigbee-Secure-Element

## Compile Mbedtls

We want to delegate ECC cryptographic operation to EFR32MG21B. For that we are going to use alternate definitions for ECC operations.

```
export PROJECT_LOC=/path/to/NCP-Zigbee-Secure-Element
cd mbedtls
CFLAGS="-I$PROJECT_LOC/dev -DMBEDTLS_CONFIG_FILE=\<mbedtls_config.h\>" make no_test
```
You should otbain linking error for
* mbedtls_ecdh_gen_public 
* mbedtls_ecdsa_sign 
* mbedtls_ecdh_compute_shared 
* mbedtls_ecdsa_can_do.
This is normal.

## Compile application and link with mbetls libraries

```
cd $PROJECT_LOC
gcc dev/app/efr32mg21b_mgmt.c dev/app/connect_hw.c dev/app/message_queue.c -o connect -I$PROJECT_LOC/mbedtls/include/ -I$PROJECT_LOC/dev/app -DMBEDTLS_CONFIG_FILE=\<mbedtls_config.h\> -L $PROJECT_LOC/mbedtls/library/ -lmbedtls -lmbedx509 -lmbedcrypto
```
## Run Application

```
./connect IP PORT 0 dev/root_ca.pem
```

# Disclaimer
All the provided code is considered to be EXPERIMENTAL QUALITY which implies that the code provided in the repos has not been formally tested and is provided as-is. It is not suitable for production environments. In addition, this code will not be maintained and there may be no bug maintenance planned for these resources. Silicon Labs may update projects from time to time.
