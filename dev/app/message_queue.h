#ifndef MESSAGE_QUEUE_H
#define MESSAGE_QUEUE_H

#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/stat.h>

#define IPC_TEMP_ZIGBEE_IN_FILE  "/tmp/ipc_zin"
#define IPC_TEMP_ZIGBEE_OUT_FILE  "/tmp/ipc_zout"
#define MPSI_KEY_ZIGBEE_IN       1
#define MPSI_KEY_ZIGBEE_OUT      2
#define IPC_QUEUE_PAYLOAD_SIZE   1024

// Return values
#define   IPC_SUCCESS              0
#define   IPC_ERROR                1
#define   IPC_INVALID_PARAMETER    2
#define   IPC_NO_RESOURCES         3


typedef struct {
  long    mtype;
  uint8_t mtext[IPC_QUEUE_PAYLOAD_SIZE];
} MessageQBuffer_t;

#endif
