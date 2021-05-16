/***************************************************************************//**
 * @file
 * @brief
 *******************************************************************************
 * # License
 * <b>Copyright 2018 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of Silicon Labs Master Software License
 * Agreement (MSLA) available at
 * www.silabs.com/about-us/legal/master-software-license-agreement. This
 * software is distributed to you in Source Code format and is governed by the
 * sections of the MSLA applicable to Source Code.
 *
 ******************************************************************************/

// This callback file is created for your convenience. You may add application
// code to this file. If you regenerate this file over a previous version, the
// previous version will be overwritten and any code you have added will be
// lost.

#include "af.h"
#include "app/framework/util/af-main.h"
#include "app/framework/util/util.h"

#include "app/util/zigbee-framework/zigbee-device-common.h"
#include "stack/include/trust-center.h"
#include <stdlib.h>

EmberCommandEntry emberAfCustomCommands[] = {
};

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
#define   MAX_EZSP_TRANSFER_SIZE   96
#define   MTYPE 1

uint8_t socket_buffer[1024];

int messageQIdin  = -1;
int messageQIdout = -1;

uint32_t rsplen;
uint8_t rsp;

typedef struct {
  long    mtype;
  uint8_t mtext[IPC_QUEUE_PAYLOAD_SIZE];
} MessageQBuffer_t;

MessageQBuffer_t message_in;
MessageQBuffer_t message_out;

EmberEventControl RspSendData;
EmberEventControl PollMqData;

uint32_t rsize;

void print_buffer(uint8_t *buffer, uint32_t size)
{
  for (uint32_t i = 0; i< size; i++)
    {
      if ((i%8) == 0)
        printf("0x%x\n", buffer[i]);
      else
        printf("0x%x ", buffer[i]);
    }
}

void emberAfMainInitCallback(void)
{
  FILE *fptr;

  // Create a temporary file called /tmp/ipc_zigbee_in
  fptr = fopen(IPC_TEMP_ZIGBEE_IN_FILE, "w+");
  if (fptr == NULL) {
    printf("IPC: failed to create %s", IPC_TEMP_ZIGBEE_IN_FILE);
    return;
  }
  fclose(fptr);

  // Create the message queue; do nothing if it exists
  // Give the user read/write/execute permission (S_IRWXU)
  messageQIdin =
    msgget(ftok(IPC_TEMP_ZIGBEE_IN_FILE, MPSI_KEY_ZIGBEE_IN), (IPC_CREAT | S_IRWXU));
  if (-1 == messageQIdin) {
    printf("IPC error: failed to create or get read message queue "
                   "(errno %d)\n", errno);
    return;
  }
  printf("Success to create or get read message queue\n");
  
  // Create a temporary file called /tmp/ipc_zigbee_out
  fptr = fopen(IPC_TEMP_ZIGBEE_OUT_FILE, "w");
  if (fptr == NULL) {
    printf("IPC: failed to create %s", IPC_TEMP_ZIGBEE_OUT_FILE);
    return;
  }
  fclose(fptr);

  // Create the message queue; do nothing if it exists
  messageQIdout =
    msgget(ftok(IPC_TEMP_ZIGBEE_OUT_FILE, MPSI_KEY_ZIGBEE_OUT), (IPC_CREAT | S_IRWXU));
  if (-1 == messageQIdout) {
    printf("IPC error: failed to create or get write message queue "
                   "(errno %d)\n", errno);
    return;
  }
  printf("Success to create or get write message queue\n");

  emberEventControlSetDelayMS(PollMqData, 100);
}

void RspSendHandler(void)
{
  emberEventControlSetInactive(RspSendData);

}

uint8_t IpcSendMessage(MessageQBuffer_t *message, uint16_t len)
{
  if (-1 == messageQIdout)
    return IPC_NO_RESOURCES; 

  message->mtype = MTYPE;
  printf("Write %d bytes to queue\n", len);
  return msgsnd(messageQIdout, message, len, IPC_NOWAIT);
}

void ezspCustomFrameHandler(int8u payloadLength,
                            int8u* payload)

{
  memcpy(message_out.mtext + rsize, payload, payloadLength);
  rsize += payloadLength;

  if (payloadLength == 0 || (payloadLength % MAX_EZSP_TRANSFER_SIZE))
  {
    /* End of message. Message can be posted in message queue */
    int status = IpcSendMessage(&message_out, rsize);
    if (status) 
      printf("Error when writing to queue %d", status);
    /* Continue to check message queue */ 
    emberEventControlSetDelayMS(PollMqData, 50);
  } 
}


void PollMqHandler(void)
{
  emberEventControlSetInactive(PollMqData);
  ssize_t bytesReceived;


  if (messageQIdin == -1)
    return;

  bytesReceived = msgrcv(messageQIdin, &message_in, IPC_QUEUE_PAYLOAD_SIZE, MTYPE, IPC_NOWAIT | MSG_NOERROR);

  if (bytesReceived > 0)
    {
      assert(bytesReceived <= MAX_EZSP_TRANSFER_SIZE);
        	      
      printf("receive command %d\n", message_in.mtext[0]);
      rsize = 0;
      /* Send Ezsp command and wait differed ezspCustomFrameHandler callback */
      EmberStatus status = ezspCustomFrame(bytesReceived, message_in.mtext, (uint8_t*)&rsplen, &rsp);

      if (status || (rsplen && rsp == 0xAA))
        printf("Error from NCP %d", status);
    }
  else
    emberEventControlSetDelayMS(PollMqData, 10);
}

void emberAfMainTickCallback(void)
{
}

