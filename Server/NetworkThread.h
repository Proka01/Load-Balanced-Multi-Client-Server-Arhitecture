#pragma once

#include "DataStructures.h"
#include <winsock2.h>
#include <ws2tcpip.h>

typedef struct NetworkThreadData 
{
    int tid;
    std::shared_ptr<SocketPool> spoolPtr;
    std::shared_ptr<ProducerConsumerQueue<Request>> request_queue_ptr;
} NTDATA, * PNTDATA;

DWORD WINAPI networkThread(LPVOID lpParam);
