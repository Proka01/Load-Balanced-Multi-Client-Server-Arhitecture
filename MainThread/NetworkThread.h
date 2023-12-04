#ifndef NETWORK_THREAD_H
#define NETWORK_THREAD_H

#include "DataStructures.h"
#include <winsock2.h>

typedef struct NetworkThreadData {
    int tid;
    std::shared_ptr<SOCKET_POOL> spoolPtr;
    std::shared_ptr<JOB_REQUEST_QUEUE> request_queue_ptr;
} NTDATA, * PNTDATA;

DWORD WINAPI networkThread(LPVOID lpParam);


#endif // NETWORK_THREAD_H