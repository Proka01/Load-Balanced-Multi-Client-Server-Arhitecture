#pragma once

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>

#include <stdio.h>
#include <time.h>
#include <signal.h>

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

#define CERT_FILE "C:\\Users\\t-aprokic\\Desktop\\LBCertAndKeys\\client"
#define KEY_FILE "C:\\Users\\t-aprokic\\Desktop\\LBCertAndKeys\\client"

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"
#define MSG_LEN 100

#define ENCRYPTION_TYPE 1

enum EncryptionType
{
    UNENCRYPTED = 0,
    ENCRYPTED = 1,
    DEBUG = 2
};


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
    SOCKET connectSocketFd = INVALID_SOCKET;

public:
    virtual SOCKET iConnAccept(char* hostIpOrDns) = 0;    // Pure virtual function
    virtual ReadResult read() = 0;                                             // Pure virtual function
    virtual int write(char* msg, int msgLen) = 0;                              // Pure virtual function
    virtual void closeConnection() = 0;                                        // Pure virtual function

    iConnection(SOCKET socket) : connectSocketFd(socket) {}
    iConnection() : connectSocketFd(INVALID_SOCKET) {}

    SOCKET getConnectSocketFd() const
    {
        return connectSocketFd;
    }

    void setConnectSocketFd(SOCKET socket)
    {
        connectSocketFd = socket;
    }

    //virtual ~iConnection() {}
};


class UnencryptedConn : public iConnection
{
public:
    UnencryptedConn(SOCKET ClientSocket) : iConnection(ClientSocket) {}
    UnencryptedConn() : iConnection() {}

    SOCKET iConnAccept(char* hostIpOrDns) override
    {
        SOCKET ConnectSocket = INVALID_SOCKET;
        struct addrinfo* result = NULL, * ptr = NULL, hints;
        int iResult;
        char clientName[20];

        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        // Resolve the server address and port, argv[1] is host name or address (localhost in this case)
        iResult = getaddrinfo(hostIpOrDns, DEFAULT_PORT, &hints, &result);
        if (iResult != 0)
        {
            printf("getaddrinfo failed with error: %d\n", iResult);
            return INVALID_SOCKET;  
        }

        // Attempt to connect to an address until one succeeds
        for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
        {

            // Create a SOCKET for connecting to server
            ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
                ptr->ai_protocol);
            if (ConnectSocket == INVALID_SOCKET)
            {
                printf("socket failed with error: %ld\n", WSAGetLastError());
                return INVALID_SOCKET;  
            }

            // Connect to server.
            iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
            if (iResult == SOCKET_ERROR)
            {
                closesocket(ConnectSocket);
                ConnectSocket = INVALID_SOCKET;
                continue;
            }
            break;
        }

        freeaddrinfo(result);

        if (ConnectSocket == INVALID_SOCKET)
        {
            printf("Unable to connect to server!\n");
            return INVALID_SOCKET;
        }

        setConnectSocketFd(ConnectSocket);
        return ConnectSocket;
    }

    ReadResult read() override
    {
        ReadResult readRes;
        char recvbuf[DEFAULT_BUFLEN];
        int recvbuflen = DEFAULT_BUFLEN;
        int iResult;
        memset(recvbuf, 0, sizeof(recvbuf));

        iResult = recv(getConnectSocketFd(), recvbuf, recvbuflen, 0);
        readRes.setBytesRead(iResult);
        readRes.setContent(recvbuf); 

        return readRes;
    }

    int write(char* msg, int msgLen) override
    {
        int iResult = send(getConnectSocketFd(), msg, msgLen, 0);
        return iResult; 
    }

    void closeConnection() override
    {
        closesocket(getConnectSocketFd());
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

    SOCKET iConnAccept(char* hostIpOrDns) override
    {
        SOCKET ConnectSocket = INVALID_SOCKET;
        struct addrinfo* result = NULL, * ptr = NULL, hints;
        int iResult;
        char clientName[20];

        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        // Resolve the server address and port, argv[1] is host name or address (localhost in this case)
        iResult = getaddrinfo(hostIpOrDns, DEFAULT_PORT, &hints, &result);
        if (iResult != 0)
        {
            printf("getaddrinfo failed with error: %d\n", iResult);
            return INVALID_SOCKET;
        }

        // Attempt to connect to an address until one succeeds
        for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
        {

            // Create a SOCKET for connecting to server
            ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
                ptr->ai_protocol);
            if (ConnectSocket == INVALID_SOCKET)
            {
                printf("socket failed with error: %ld\n", WSAGetLastError());
                return INVALID_SOCKET;
            }

            // Connect to server.
            iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
            if (iResult == SOCKET_ERROR)
            {
                closesocket(ConnectSocket);
                ConnectSocket = INVALID_SOCKET;
                continue;
            }
            break;
        }

        freeaddrinfo(result);

        if (ConnectSocket == INVALID_SOCKET)
        {
            printf("Unable to connect to server!\n");
            return INVALID_SOCKET;
        }

        setConnectSocketFd(ConnectSocket);

        //TLS HANDSHAKE
        SSL* ssl = SSL_new(ctx);          CHK_NULL(ssl);
        SSL_set_fd(ssl, ConnectSocket);
        iResult = SSL_connect(ssl);       CHK_SSL(iResult);

        setSSLObjcet(ssl);

        return ConnectSocket;
    }

    ReadResult read() override
    {
        ReadResult readRes;
        char recvbuf[DEFAULT_BUFLEN];
        int recvbuflen = DEFAULT_BUFLEN;
        int iResult;
        memset(recvbuf, 0, sizeof(recvbuf));

        iResult = SSL_read(ssl, recvbuf, sizeof(recvbuf) - 1);   CHK_SSL(iResult);
        recvbuf[iResult] = '\0';

        readRes.setBytesRead(iResult);
        readRes.setContent(recvbuf);

        return readRes;
    }

    int write(char* msg, int msgLen) override
    {
        int iResult = SSL_write(ssl, msg, msgLen);  CHK_SSL(iResult);
        return iResult;
    }

    void closeConnection() override
    {
        closesocket(getConnectSocketFd());
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }
};


