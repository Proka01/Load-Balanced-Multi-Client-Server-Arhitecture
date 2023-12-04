#ifndef WORKER_THREAD_H
#define WORKER_THREAD_H

#include "DataStructures.h"
#include <winsock2.h>

typedef struct WorkerThreadData {
    int tid;
    std::shared_ptr<JOB_REQUEST_QUEUE> request_queue;
} WTDATA, * PWTDATA;

DWORD WINAPI workerThread(LPVOID lpParam);


#endif // WORKER_THREAD_H