#pragma once

#include "DataStructures.h"
#include <winsock2.h>

typedef struct WorkerThreadData 
{
    int tid;
    std::shared_ptr<ProducerConsumerQueue<Request>> request_queue_ptr;
} WTDATA, * PWTDATA;

DWORD WINAPI workerThread(LPVOID lpParam);