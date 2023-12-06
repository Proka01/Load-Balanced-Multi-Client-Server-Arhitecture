#ifndef DATA_STRUCTURES_H
#define DATA_STRUCTURES_H

#include <winsock2.h>
#include <unordered_set>
#include <queue>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <thread>

#define MAX_SOCKET_POOLS 3
#define MAX_WORKER_THREADS 3
#define MAX_NETWORK_THREADS (MAX_SOCKET_POOLS)
#define MAX_LISTENER_THREADS 1
#define MAX_THREADS ((MAX_WORKER_THREADS) + (MAX_NETWORK_THREADS) + (MAX_LISTENER_THREADS))
#define DEFAULT_BUFLEN 512

enum Operation {
    PLUS = 0,
    MINUS = 1,
    MUL = 2,
    DIV = 3,
    MOD = 4
};

typedef struct socket_pool {
    int spid;
    std::vector<SOCKET> pool;
    std::mutex mutex;

    socket_pool(int spid, const std::vector<SOCKET>& pool)
        : spid(spid), pool(pool), mutex() {}

} SOCKET_POOL, * PSOCKET_POOL;

typedef struct response {
    int rid;
    int res;
    SOCKET clientSocket;
    char resp_msg[DEFAULT_BUFLEN];
} RESPONSE;

typedef struct job_response_queue {
    std::queue<RESPONSE> response_queue;
    std::mutex mutex;

    job_response_queue() : response_queue(), mutex() {}
} JOB_RESPONSE_QUEUE, * PJOB_RESPONSE_QUEUE;

typedef struct request {
    int rid;
    int a;
    int b;
    enum Operation op;
    SOCKET clientSocket;
    std::shared_ptr<JOB_RESPONSE_QUEUE> job_resp_queue_ptr;

    request() : rid(0), a(0), b(0), op(PLUS), clientSocket(0) {}

    request(int rid, int a, int b, enum Operation op, SOCKET clientSocket, std::shared_ptr<JOB_RESPONSE_QUEUE> responseQueuePtr)
        : rid(rid), a(a), b(b), op(op), clientSocket(clientSocket), job_resp_queue_ptr(responseQueuePtr) {}

    void displayInfo()
    {
        printf("Request ID: %d\n", rid);
        printf("Operand A: %d\n", a);
        printf("Operand B: %d\n", b);
        printf("Operation: %d\n", op);
        printf("Client Socket: %d\n", clientSocket);
    }

} REQUEST;

typedef struct job_request_queue {
    std::queue<REQUEST> request_queue;
    std::mutex mutex;

    job_request_queue() : request_queue(), mutex() {}
} JOB_REQUEST_QUEUE, * PJOB_REQUEST_QUEUE;


#endif // DATA_STRUCTURES_H