#ifndef DATA_STRUCTURES_H
#define DATA_STRUCTURES_H

#include <winsock2.h>
#include <unordered_set>
#include <queue>
#include <string>
#include <vector>
#include <memory>

#define MAX_SOCKET_POOLS 3
#define MAX_WORKER_THREADS 3
#define MAX_NETWORK_THREADS (MAX_SOCKET_POOLS)
#define MAX_LISTENER_THREADS 1
#define MAX_THREADS ((MAX_WORKER_THREADS) + (MAX_NETWORK_THREADS) + (MAX_LISTENER_THREADS))

typedef struct socket_pool {
    int spid;
    std::vector<SOCKET> pool;
} SOCKET_POOL, * PSOCKET_POOL;

typedef struct request {
    int rid;
    int a;
    int b;
    std::string op;
    SOCKET clientSocket;
} REQUEST;

typedef struct response {
    int rid;
    int res;
    SOCKET clientSocket;
} RESPONSE;

typedef struct job_response_queue {
    std::queue<RESPONSE> response_queue;
} JOB_RESPONSE_QUEUE, * PJOB_RESPONSE_QUEUE;

typedef struct job_request_queue {
    std::queue<REQUEST> request_queue;
} JOB_REQUEST_QUEUE, * PJOB_REQUEST_QUEUE;


#endif // DATA_STRUCTURES_H