#include "ListenerThread.h"
#include <stdio.h>
#include <stdlib.h>

DWORD WINAPI listenerThread(LPVOID lpParam)
{
    PLTDATA ltData = (PLTDATA) lpParam;
    int tid = ltData->tid;
    std::vector<std::shared_ptr<SocketPool>> spoolPtrs = ltData->spoolPtrs;

    //WSADATA wsaData;
    int iResult;

    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

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
        // Accept a client socket
        ClientSocket = accept(ListenSocket, NULL, NULL);

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
            spoolPtrs[fewest_idx]->put(ClientSocket);
        }
    }

    //WSACleanup();
    getchar();
    return 0;
}
