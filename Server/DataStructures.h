#pragma once

//winsock api library
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

//c++ data structures librarys
#include <unordered_set>
#include <queue>
#include <string>
#include <vector>
#include <memory>
#include <unordered_set>

//library for concurent executing and locks
#include <thread>
#include <mutex>

//semaphores library for concurent executing
#include <semaphore>

//openSSL librarys
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

//openSSL macros
#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

//app macros
#define MAX_SOCKET_POOLS 3
#define MAX_WORKER_THREADS 3
#define MAX_NETWORK_THREADS (MAX_SOCKET_POOLS)
#define MAX_LISTENER_THREADS 1
#define MAX_THREADS ((MAX_WORKER_THREADS) + (MAX_NETWORK_THREADS) + (MAX_LISTENER_THREADS))
#define DEFAULT_BUFLEN 512
#define JAM_LIMIT 3

#define ENCRYPTION_TYPE 1

class ReadResult
{
public:
    ReadResult(int size, const char* data)
    {
        bytesRead = size;

        content = new char[size + 1]; // +1 for null terminator
        std::strcpy(content, data);
    }

    ReadResult() : bytesRead(-1), content(nullptr) {}

    // Destructor to free the allocated memory
    ~ReadResult()
    {
        delete[] content;
    }

    // Getter function for bytesRead
    int getBytesRead() const
    {
        return bytesRead;
    }

    // Getter function for content
    const char* getContent() const
    {
        return content;
    }

    // Setter function for bytesRead
    void setBytesRead(int size)
    {
        bytesRead = size;
    }

    // Setter function for content
    void setContent(const char* data)
    {
        // Free existing memory
        delete[] content;

        // Allocate memory for content and copy the data
        int size = std::strlen(data);
        content = new char[size + 1]; // +1 for null terminator
        std::strcpy(content, data);
    }

private:
    int bytesRead;
    char* content;
};



class iConnection
{
private:
    SOCKET clientSocketFd = INVALID_SOCKET;

public:
    virtual SOCKET iConnAccept(SOCKET ListenSocket) = 0;    // Pure virtual function
    virtual ReadResult read() = 0;                          // Pure virtual function
    virtual int write(char* msg, int msgLen) = 0;           // Pure virtual function
    virtual void closeConnection() = 0;                     // Pure virtual function

    iConnection(SOCKET socket) : clientSocketFd(socket) {}
    iConnection() : clientSocketFd(INVALID_SOCKET) {}

    SOCKET getClientSocketFd() const
    {
        return clientSocketFd;
    }

    void setClientSocketFd(SOCKET socket)
    {
        clientSocketFd = socket;
    }

    //virtual ~iConnection() {}
};


class UnencryptedConn : public iConnection
{
public:
    UnencryptedConn(SOCKET ClientSocket) : iConnection(ClientSocket) {}
    UnencryptedConn() : iConnection() {}

    SOCKET iConnAccept(SOCKET ListenSocket) override
    {
        //TCP Handshacke server side
        // Accept a client socket
        SOCKET ClientSocket = accept(ListenSocket, NULL, NULL);

        //Check for errors
        if (ClientSocket == INVALID_SOCKET)
        {
            printf("accept failed with error: %d\n", WSAGetLastError());
        }
        else
        {
            setClientSocketFd(ClientSocket);
        }

        return ClientSocket;
    }

    ReadResult read() override
    {
        SOCKET ClientSocket = getClientSocketFd();
        ReadResult readRes;

        char recvbuf[DEFAULT_BUFLEN];
        int recvbuflen = DEFAULT_BUFLEN;

        //Read msg from Client
        memset(recvbuf, 0, sizeof(recvbuf));
        int iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);

        if (iResult > 0)
        {
            readRes.setBytesRead(iResult);
            readRes.setContent(recvbuf);
        }
        else
        {
            printf("ERR iResult < 0");
        }

        return readRes;
    }

    int write(char* msg, int msgLen) override
    {
        int iSendResult = send(getClientSocketFd(), msg, msgLen, 0);
        return iSendResult;
    }

    void closeConnection() override
    {
        closesocket(getClientSocketFd());
    }
};


class EncryptedConn : public iConnection 
{
private:
    SSL_CTX* ctx; 
    SSL* ssl;

public:
    EncryptedConn(SOCKET ClientSocket, SSL_CTX* sslContext) : iConnection(ClientSocket), ctx(sslContext) {}
    EncryptedConn(SSL_CTX* sslContext) : iConnection(), ctx(sslContext) {}

    SSL_CTX* getSSLContext() const 
    {
        return ctx;
    }

    void setSSLContext(SSL_CTX* sslContext) 
    {
        this->ctx = sslContext;
    }

    SSL* getSSLObject() const
    {
        return ssl;
    }

    void setSSLObjcet(SSL* sslObj)
    {
        this->ssl = sslObj;
    }

    SOCKET iConnAccept(SOCKET ListenSocket) override
    {
        //TCP handshake server side
        // Accept a client socket
        SOCKET ClientSocket = accept(ListenSocket, NULL, NULL);

        //Check for errors
        if (ClientSocket == INVALID_SOCKET)
        {
            printf("accept failed with error: %d\n", WSAGetLastError());
        }
        else
        {
            setClientSocketFd(ClientSocket);
        }

        /* TCP connection is ready. Do server side SSL. */
        //TLS handshake server side (Server hello)
        SSL* ssl = SSL_new(ctx);             CHK_NULL(ssl);
        SSL_set_fd(ssl, ClientSocket);
        int err = SSL_accept(ssl);           CHK_SSL(err);

        setSSLObjcet(ssl);

        return ClientSocket;
    }

    ReadResult read() override
    {
        SSL* ssl = getSSLObject();
        ReadResult readRes;
        int iResult;

        char recvbuf[DEFAULT_BUFLEN];
        int recvbuflen = DEFAULT_BUFLEN;

        //Read msg from Client
        memset(recvbuf, 0, sizeof(recvbuf));

        iResult = SSL_read(ssl, recvbuf, sizeof(recvbuf) - 1);   CHK_SSL(iResult);
        recvbuf[iResult] = '\0';

        if (iResult > 0)
        {
            readRes.setBytesRead(iResult);
            readRes.setContent(recvbuf);
        }
        else
        {
            printf("ERR iResult < 0");
        }

        return readRes;
    }

    int write(char* msg, int msgLen) override
    {
        int iResult = SSL_write(this->ssl, msg, msgLen);  CHK_SSL(iResult);
        return iResult;
    }

    void closeConnection() override
    {
        closesocket(getClientSocketFd());
        SSL_free(getSSLObject());
    }
};


enum Operation 
{
    PLUS = 0,
    MINUS = 1,
    MUL = 2,
    DIV = 3,
    MOD = 4
};

enum EncryptionType
{
    UNENCRYPTED = 0,
    ENCRYPTED = 1,
    DEBUG = 2
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

    std::vector<std::shared_ptr<iConnection>> pool;
    std::mutex mutex;

    SocketPool(int spid, const std::vector<std::shared_ptr<iConnection>>& pool)
        : spid(spid), pool(pool), mutex() {}

    void put(const std::shared_ptr<iConnection>& iConn)
    {
        std::lock_guard<std::mutex> lock(mutex);
        pool.push_back(iConn);
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
   
    void removeDisconectedSocketsFromPool(std::unordered_set<int> iConns_idxs_to_remove)
    {
        std::lock_guard<std::mutex> lock(mutex);
        std::vector<std::shared_ptr<iConnection>> iConns_idx_to_stay;

        for (int i = 0; i < pool.size(); i++)
        {
            std::shared_ptr<iConnection> iConn = pool[i];

            //if ith idx is not present in iConns_idxs_to_remove, than it should stay
            if (iConns_idxs_to_remove.find(i) == iConns_idxs_to_remove.end())
            {
                iConns_idx_to_stay.push_back(iConn);
            }
            else
            {
                closesocket(iConn->getClientSocketFd());
            }
        }

        pool.clear();
        pool = iConns_idx_to_stay; // do i need to clear fds_idx_to_stay
    }
};


class Response
{
public:
    int rid;
    int res;
    std::shared_ptr<iConnection> iConn;
    char resp_msg[DEFAULT_BUFLEN];
};


class Request
{
public:
    int rid;
    int a;
    int b;
    Operation op;
    std::shared_ptr<iConnection> iConn;
    std::shared_ptr<ProducerConsumerQueue<Response>> job_resp_queue_ptr;

    Request(int rid, int a, int b, Operation op, std::shared_ptr<iConnection> iConn, std::shared_ptr<ProducerConsumerQueue<Response>> responseQueuePtr)
        : rid(rid), a(a), b(b), op(op), iConn(iConn), job_resp_queue_ptr(responseQueuePtr) {}
};
