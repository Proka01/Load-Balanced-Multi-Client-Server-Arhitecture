#ifndef WORKER_THREAD_H
#define WORKER_THREAD_H

#include "DataStructures.h"
#include <winsock2.h>

typedef struct WorkerThreadData 
{
    int tid;
    std::shared_ptr<ProducerConsumerQueue<Request>> request_queue_ptr;
} WTDATA, * PWTDATA;

DWORD WINAPI workerThread(LPVOID lpParam);


#endif // WORKER_THREAD_H