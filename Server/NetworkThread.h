#ifndef NETWORK_THREAD_H
#define NETWORK_THREAD_H

#include "DataStructures.h"
#include <winsock2.h>
#include <ws2tcpip.h>

typedef struct NetworkThreadData 
{
    int tid;
    std::shared_ptr<SocketPool> spoolPtr;
    std::shared_ptr<JobRequestQueue> request_queue_ptr;
} NTDATA, * PNTDATA;

DWORD WINAPI networkThread(LPVOID lpParam);


#endif // NETWORK_THREAD_H