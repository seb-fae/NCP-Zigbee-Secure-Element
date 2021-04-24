# NCP-Zigbee-Secure-Element

## Compile Mbedtls to use EFR32MG21B for some cryptographic operations
```
cd mbedtls
FLAGS="-I/path/to/NCP-Zigbee-Secure-Element/dev -DMBEDTLS_CONFIG_FILE=\<mbedtls_config.h\>" make
```
