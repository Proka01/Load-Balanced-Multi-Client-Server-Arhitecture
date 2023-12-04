#ifndef DATA_STRUCTURES_H
#define DATA_STRUCTURES_H

#include <winsock2.h>
#include <unordered_set>
#include <queue>
#include <string>
#include <vector>
#include <memory>

typedef struct socket_pool {
    int spid;
    std::unordered_set<SOCKET> pool;
} SOCKET_POOL;

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
} JOB_RESPONSE_QUEUE;

typedef struct job_request_queue {
    std::queue<REQUEST> request_queue;
} JOB_REQUEST_QUEUE;


#endif // DATA_STRUCTURES_H