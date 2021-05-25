# NCP-Zigbee-Secure-Element

This project shows how to establish a secure TLS connection to a remote server by taking advantage of the internal secure element of the EFR32MG21B. In this project EFR32 is also running a Zigbee NCP (Network Co-Processor).

To secure communication between Host and Zigbee NCP, Secure EZSP should be enabled by following this document:
https://www.silabs.com/documents/public/application-notes/an1125-creating-and-using-a-secure-ezsp-host-to-ncp-interface.pdf


## Create and Compile a NCP

Create a fresh NCP project and follow this procedure:
* Add "**Xncp plugin**"
* Enable the "**emberAfPluginXncpIncomingCustomFrameCallback**" callback
* Enable the "**emberAfMainInitCallback**" callback
* Set heap size to 1024 with "**--defsym=EMBER_MALLOC_HEAP_SIZE=1024**"
* Add a custom event and let the default name
* Generate
* Copy files from Xncp folder of this repository to your project 
* Compile and Flash to EFR32MG21B

## Create and compile a Z3GatewayHost project

* Enable **emberAfMainInitCallback** callback
* Enable **ezspCustomFrameHandler** callback
* Add a custom event **PollMqData/PollMqHandler**
* Replace **Z3GatewayHost_callback.c** by the file from this repository
* Generate, Compile and run 
 
## Launch test server
```
openssl s_server -accept 127.0.0.1:8080 -CAfile cert/silabs-root-ca.pem -cert cert/server-cert.pem -key cert/server-key.pem -Verify 1 -state -debug -msg -tlsextdebug -security_debug -security_debug_verbose -tls1_2
```

## Compile Mbedtls

We want to delegate some mbedtls operation to EFR32MG21B. For that we are going to use alternate definitions for ECC operations.

```
export PROJECT_LOC=/path/to/NCP-Zigbee-Secure-Element
cd mbedtls
CFLAGS="-I$PROJECT_LOC/dev/app -DMBEDTLS_CONFIG_FILE=\<mbedtls_config.h\>" make no_test
```
You should otbain linking error for
* mbedtls_ecdh_gen_public 
* mbedtls_ecdsa_sign 
* mbedtls_ecdh_compute_shared 
* mbedtls_ecdsa_can_do

In spite of these errors, mbedtls libraries have been generated. These missing functions are implemented in following application.

## Compile application and link with Mbedtls libraries 

```
cd $PROJECT_LOC
gcc dev/app/efr32mg21b_mgmt.c dev/app/connect_hw.c dev/app/message_queue.c -o connect -I$PROJECT_LOC/mbedtls/include/ -I$PROJECT_LOC/dev/app -DMBEDTLS_CONFIG_FILE=\<mbedtls_config.h\> -L $PROJECT_LOC/mbedtls/library/ -lmbedtls -lmbedx509 -lmbedcrypto
```

## Run Application

```
./connect 127.0.0.1 8080 SERVER cert/server-ca-cert.pem
```

# Disclaimer
All the provided code should be considered as an example which implies that the code provided in the repos has not been formally tested and is provided as-is. It is not suitable for production environments. In addition, this code will not be maintained and there may be no bug maintenance planned for these resources. 
