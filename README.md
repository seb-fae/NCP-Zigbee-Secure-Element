# NCP-Zigbee-Secure-Element

## Compile Mbedtls

We want to delegate ECC cryptographic operation to EFR32MG21B. For that we are going to use alternate definitions for ECC operations.

```
cd mbedtls
FLAGS="-I/path/to/NCP-Zigbee-Secure-Element/dev -DMBEDTLS_CONFIG_FILE=\<mbedtls_config.h\>" make
```
