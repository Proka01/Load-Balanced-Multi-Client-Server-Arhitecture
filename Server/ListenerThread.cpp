#include "ListenerThread.h"
#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#define CERT_FILE "C:\\Users\\t-aprokic\\Desktop\\LBCertAndKeys\\server.crt"
#define KEY_FILE "C:\\Users\\t-aprokic\\Desktop\\LBCertAndKeys\\server.key"


SSL_CTX* initSSLContext()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    //const SSL_METHOD* meth = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(2);
    }

    // Load the server certificate into the context
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        // Handle error
        std::cout << "Err when Load the server certificate into the context\n";
    }
    printf("Successfully loaded server cert\n");

    // Load the private key into the context
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        // Handle error
        std::cout << "Err when Load the private key into the context\n";
    }
    printf("Successfully loaded server private key \n");

    // Verify that the private key matches the certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate\n");
        // Handle error
        std::cout << "Err when Load the private key into the context\n";
    }
    printf("Successfully verified pk with cert\n");

    printf("sslCtx success\n");
    return ctx;
}



DWORD WINAPI listenerThread(LPVOID lpParam)
{
    PLTDATA ltData = (PLTDATA) lpParam;
    int tid = ltData->tid;
    std::vector<std::shared_ptr<SocketPool>> spoolPtrs = ltData->spoolPtrs;

    //WSADATA wsaData;
    int iResult;

    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;
    SSL_CTX* ctx = initSSLContext();

    struct addrinfo* result = NULL;
    struct addrinfo hints;

    //Windows API macro used to set a block of memory to zero
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) 
    {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Create a SOCKET for the server to listen for client connections.
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) 
    {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Setup the TCP listening socket
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) 
    {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    //Start listening for client connections
    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) 
    {
        printf("listen failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    //accept incoming clientSockets and put them in socket_pools with LB
    //LB: put in pool with fewest elements
    while (1)
    {
        std::shared_ptr<iConnection> iConn;

        switch (ENCRYPTION_TYPE)
        {
            case UNENCRYPTED:
                iConn = std::make_shared<UnencryptedConn>();
                break;
            case ENCRYPTED:
                iConn = std::make_shared<EncryptedConn>(ctx);
                break;
            case DEBUG:
                iConn = std::make_shared<UnencryptedConn>();
                break;
            default:
                printf("Unknown ENCRYPTION_TYPE\n");
        }

        // Accept a client socket
        //ClientSocket = accept(ListenSocket, NULL, NULL);
        ClientSocket = iConn->iConnAccept(ListenSocket);

        //Check for errors
        if (ClientSocket == INVALID_SOCKET) 
        {
            printf("accept failed with error: %d\n", WSAGetLastError());
            closesocket(ListenSocket);
            WSACleanup();
            return 1;
        }

        //LB algorithm
        int fewest = INT_MAX;
        int fewest_idx = -1;
        for (int i = 0; i < spoolPtrs.size(); i++)
        {
            if (spoolPtrs[i]->isPoolSizeLessThan(fewest))
            {
                fewest = spoolPtrs[i]->pool.size();
                fewest_idx = i;
            }
        }

        if (fewest_idx > -1)
        {
            //TODO: regarding parametar make necrypt od unencrypt
            //spoolPtrs[fewest_idx]->put(std::make_shared<UnencryptedConn>(ClientSocket));
            spoolPtrs[fewest_idx]->put(iConn);
            
        }
    }

    //WSACleanup();
    getchar();
    return 0;
}
