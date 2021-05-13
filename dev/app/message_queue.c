#include <message_queue.h>

int messageQIdin = -1;
int messageQIdout = -1;

void print_buffer(uint8_t *buffer, uint32_t size)
{
  printf("receive %d bytes: \n");	
  for (uint32_t i = 0; i< size; i++)
    {
        printf("0x%x ", buffer[i]);
    }
        printf("\n");
}

void init_message_queue(void)
{
  FILE *fptr;

  // Create a temporary file called /tmp/ipc
  fptr = fopen(IPC_TEMP_ZIGBEE_IN_FILE, "w+");
  if (fptr == NULL) {
    printf("IPC: failed to read %s\n", IPC_TEMP_ZIGBEE_IN_FILE);
    return;
  }
  fclose(fptr);

  // Create the message queue; do nothing if it exists
  // Give the user read/write/execute permission (S_IRWXU)
  messageQIdout =
    msgget(ftok(IPC_TEMP_ZIGBEE_IN_FILE, MPSI_KEY_ZIGBEE_IN), (IPC_CREAT | S_IRWXU));
  if (-1 == messageQIdout) {
    printf("IPC error: failed to create or get write message queue "
                   "(errno %d)\n", errno);
    return;
  }
  printf("Success to create or get write message queue\n");

  // Create a temporary file called /tmp/ipc
  fptr = fopen(IPC_TEMP_ZIGBEE_OUT_FILE, "r+");
  if (fptr == NULL) {
    printf("IPC: failed to read %s\n", IPC_TEMP_ZIGBEE_OUT_FILE);
    return;
  }
  fclose(fptr);

  // Create the message queue; do nothing if it exists
  // Give the user read/write/execute permission (S_IRWXU)
  messageQIdin =
    msgget(ftok(IPC_TEMP_ZIGBEE_OUT_FILE, MPSI_KEY_ZIGBEE_OUT), (IPC_CREAT | S_IRWXU));
  if (-1 == messageQIdin) {
    printf("IPC error: failed to create or get read message queue "
                   "(errno %d)\n", errno);
    return;
  }
  printf("Success to create or get read message queue\n");
}

ssize_t read_message(MessageQBuffer_t * messageBuffer)
{
  ssize_t bytesReceived = -1;

  if (-1 != messageQIdin)
  /* Start blocking read */
    { 
      bytesReceived = msgrcv(messageQIdin,
                           messageBuffer,
                           IPC_QUEUE_PAYLOAD_SIZE,
                           1,
                           MSG_NOERROR);
    }

  if (bytesReceived < 0)
    printf("Error when reading message queue %d\n", bytesReceived);


  return bytesReceived;
}

uint8_t send_message(MessageQBuffer_t *message, uint16_t len)
{
  if (-1 == messageQIdout) {
    return IPC_NO_RESOURCES;
  }

  return msgsnd(messageQIdout,
              message,
              len,
              IPC_NOWAIT);
}


