#ifndef DATA_STRUCTURES_H
#define DATA_STRUCTURES_H

#include <winsock2.h>
#include <unordered_set>
#include <queue>
#include <string>
#include <vector>
#include <memory>
#include <condition_variable>
#include <thread>
#include <mutex>
#include <unordered_set>
#include <semaphore>

#define MAX_SOCKET_POOLS 3
#define MAX_WORKER_THREADS 3
#define MAX_NETWORK_THREADS (MAX_SOCKET_POOLS)
#define MAX_LISTENER_THREADS 1
#define MAX_THREADS ((MAX_WORKER_THREADS) + (MAX_NETWORK_THREADS) + (MAX_LISTENER_THREADS))
#define DEFAULT_BUFLEN 512
#define JAM_LIMIT 3

enum Operation 
{
    PLUS = 0,
    MINUS = 1,
    MUL = 2,
    DIV = 3,
    MOD = 4
};

template <typename T>
class ProducerConsumerQueue {
public:
    ProducerConsumerQueue(int limit) : jamLimit(limit), prodConQueue(), full(0), empty(limit), mutex() {}

    ~ProducerConsumerQueue() {}

    void add(T item)
    {
        empty.acquire();
        std::unique_lock<std::mutex> ul(mutex);

        prodConQueue.push(item);

        ul.unlock();
        full.release();
    }

    T popAndGet()
    {
        full.acquire();
        std::unique_lock<std::mutex> ul(mutex);

        T item = prodConQueue.front();
        prodConQueue.pop();

        ul.unlock();
        empty.release();

        return item;
    }

    bool isEmpty()
    {
        std::unique_lock<std::mutex> ul(mutex);
        bool empty = prodConQueue.empty();
        ul.unlock();

        return empty;
    }

    int getSize()
    {
        std::unique_lock<std::mutex> ul(mutex);
        int size = prodConQueue.size();
        ul.unlock();

        return size;
    }

    std::mutex getMutex()
    {
        return mutex;
    }

private:
    int jamLimit;
    std::queue<T> prodConQueue;
    std::counting_semaphore<INT_MAX> full;
    std::counting_semaphore<INT_MAX> empty;
    std::mutex mutex;
};

class SocketPool 
{
public:
    int spid;
    std::vector<SOCKET> pool;
    std::mutex mutex;

    SocketPool(int spid, const std::vector<SOCKET>& pool)
        : spid(spid), pool(pool), mutex() {}

    // Retrieve and remove the front element of the pool, if not empty.
    SOCKET getAndPop(SOCKET& socket) 
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (!pool.empty()) 
        {
            SOCKET fd = pool.front();
            pool.erase(pool.begin());
            return fd; // Element retrieved and popped successfully.
        }
        return NULL; // Pool is empty.
    }

    // Add an element to the back of the pool.
    void put(const SOCKET& fd) 
    {
        std::lock_guard<std::mutex> lock(mutex);
        pool.push_back(fd);
    }

    bool isPoolSizeLessThan(int sz)
    {
        std::lock_guard<std::mutex> lock(mutex);
        bool ret = pool.size() < sz;
        return ret;
    }

    void printPoolSizeConcurently(int tid)
    {
        std::lock_guard<std::mutex> lock(mutex);
        printf("NetworkThread%d: pool_size: %d\n", tid, pool.size());
    }

    void removeDisconectedSocketsFromPool(std::unordered_set<int> fds_idxs_to_remove)
    {
        std::lock_guard<std::mutex> lock(mutex);
        std::vector<SOCKET> fds_idx_to_stay;

        for (int i = 0; i < pool.size(); i++)
        {
            SOCKET fd = pool[i];

            if (fds_idxs_to_remove.find(i) == fds_idxs_to_remove.end())
            {
                fds_idx_to_stay.push_back(fd);
            }
            else
            {
                closesocket(fd);
            }
        }

        pool.clear();
        pool = fds_idx_to_stay; // do i need to clear fds_idx_to_stay
    }
};

class Response 
{
public:
    int rid;
    int res;
    SOCKET clientSocket;
    char resp_msg[DEFAULT_BUFLEN];
};

class Request 
{
public:
    int rid;
    int a;
    int b;
    Operation op;
    SOCKET clientSocket;
    std::shared_ptr<ProducerConsumerQueue<Response>> job_resp_queue_ptr;

    Request()
        : rid(0), a(0), b(0), op(PLUS), clientSocket(0) {}

    Request(int rid, int a, int b, Operation op, SOCKET clientSocket, std::shared_ptr<ProducerConsumerQueue<Response>> responseQueuePtr)
        : rid(rid), a(a), b(b), op(op), clientSocket(clientSocket), job_resp_queue_ptr(responseQueuePtr) {}

    void displayInfo() 
    {
        printf("Request ID: %d\n", rid);
        printf("Operand A: %d\n", a);
        printf("Operand B: %d\n", b);
        printf("Operation: %d\n", op);
        printf("Client Socket: %d\n", clientSocket);
    }
};

#endif // DATA_STRUCTURES_H