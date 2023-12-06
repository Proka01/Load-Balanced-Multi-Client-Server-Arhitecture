#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <ws2tcpip.h> // Include ws2tcpip.h instead of winsock2.h
#include <tchar.h>
#include <strsafe.h>

#include "ListenerThread.h"
#include "NetworkThread.h"
#include "WorkerThread.h"
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")

PLTDATA pltDataArr[MAX_LISTENER_THREADS];
PNTDATA pntDataArr[MAX_NETWORK_THREADS];
PWTDATA pwtDataArr[MAX_WORKER_THREADS];

DWORD   dwListenerThreadIdArr[MAX_LISTENER_THREADS];
HANDLE  hListenerThreadArr[MAX_LISTENER_THREADS];

DWORD   dwNetworkThreadIdArr[MAX_NETWORK_THREADS];
HANDLE  hNetworkThreadIdArr[MAX_NETWORK_THREADS];

DWORD   dwWorkerThreadIdArr[MAX_WORKER_THREADS];
HANDLE  hWorkerThreadArr[MAX_WORKER_THREADS];

void handleSignal(int signal)
{
    // Close all ListenerThreads handles and free memory allocations.
    for (int i = 0; i < MAX_LISTENER_THREADS; i++)
    {
        CloseHandle(hListenerThreadArr[i]);
        if (pltDataArr[i] != NULL)
        {
            HeapFree(GetProcessHeap(), 0, pltDataArr[i]);
            pltDataArr[i] = NULL;    // Ensure address is not reused.
        }
    }

    // Close all NetworkThreads handles and free memory allocations.
    for (int i = 0; i < MAX_NETWORK_THREADS; i++)
    {
        CloseHandle(hNetworkThreadIdArr[i]);
        if (pntDataArr[i] != NULL)
        {
            HeapFree(GetProcessHeap(), 0, pntDataArr[i]);
            pntDataArr[i] = NULL;    // Ensure address is not reused.
        }
    }

    // Close all WorkerThreads handles and free memory allocations.
    for (int i = 0; i < MAX_WORKER_THREADS; i++)
    {
        CloseHandle(hWorkerThreadArr[i]);
        if (pwtDataArr[i] != NULL)
        {
            HeapFree(GetProcessHeap(), 0, pwtDataArr[i]);
            pwtDataArr[i] = NULL;    // Ensure address is not reused.
        }
    }

    WSACleanup();
}

int main()
{
    printf("<-- SERVER --> \n\n");

    // Register signal handler for Ctrl+C (SIGINT)
    signal(SIGINT, handleSignal);

    // Register signal handler for pressing x button in terminal (SIGTERM)
    signal(SIGTERM, handleSignal);

    WSADATA wsaData;
    int iResult;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    std::shared_ptr<JOB_REQUEST_QUEUE> job_request_queue_shared_ptr = std::make_shared<JOB_REQUEST_QUEUE>();
    std::vector<std::shared_ptr<SOCKET_POOL>> socket_pool_ptrs;

    //Init socket pools
    for (int i = 0; i < MAX_SOCKET_POOLS; i++)
    {
        socket_pool_ptrs.push_back(std::make_shared<SOCKET_POOL>(i, std::vector<SOCKET>()));
    }

    //Init pltDataArr
    for (int i = 0; i < MAX_LISTENER_THREADS; i++)
    {
        pltDataArr[i] = (PLTDATA)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LTDATA));

        if (pltDataArr[i] != NULL)
        {
            pltDataArr[i]->tid = i;
            pltDataArr[i]->spoolPtrs = socket_pool_ptrs;
        }
    }

    //Init pntDataArr
    for (int i = 0; i < MAX_NETWORK_THREADS; i++)
    {
        pntDataArr[i] = (PNTDATA)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(NTDATA));

        if (pntDataArr[i] != NULL)
        {
            pntDataArr[i]->tid = i;
            pntDataArr[i]->spoolPtr = socket_pool_ptrs[i]; //TODO: if ith ptr failed initializing this may cause problem
            pntDataArr[i]->request_queue_ptr = job_request_queue_shared_ptr;
        }
    }

    //Init pwtDataArr
    for (int i = 0; i < MAX_WORKER_THREADS; i++)
    {
        pwtDataArr[i] = (PWTDATA)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WTDATA));

        if (pwtDataArr[i] != NULL)
        {
            pwtDataArr[i]->tid = i;
            pwtDataArr[i]->request_queue_ptr = job_request_queue_shared_ptr;
        }
    }

   
    // Create the ListenerThreads to begin execution on its own.
    for (int i = 0; i < MAX_LISTENER_THREADS; i++)
    {
        hListenerThreadArr[i] = CreateThread(
            NULL,                               // default security attributes
            0,                                  // use default stack size  
            listenerThread,                     // thread function name
            pltDataArr[i],                      // argument to thread function 
            0,                                  // use default creation flags 
            &dwListenerThreadIdArr[i]);         // returns the thread identifier 

        // Check for errors
        if (hListenerThreadArr[i] == NULL)
        {
            ExitProcess(3);
        }
    }

    // Create the NetworkThreads to begin execution on its own.
    for (int i = 0; i < MAX_NETWORK_THREADS; i++)
    {
        hNetworkThreadIdArr[i] = CreateThread(
            NULL,                               // default security attributes
            0,                                  // use default stack size  
            networkThread,                      // thread function name
            pntDataArr[i],                      // argument to thread function 
            0,                                  // use default creation flags 
            &dwNetworkThreadIdArr[i]);          // returns the thread identifier 

        // Check for errors
        if (hNetworkThreadIdArr[i] == NULL)
        {
            ExitProcess(3);
        }
    }

    // Create the WorkerThreads to begin execution on its own.
    for (int i = 0; i < MAX_WORKER_THREADS; i++)
    {
        hWorkerThreadArr[i] = CreateThread(
            NULL,                               // default security attributes
            0,                                  // use default stack size  
            workerThread,                       // thread function name
            pwtDataArr[i],                      // argument to thread function 
            0,                                  // use default creation flags 
            &dwWorkerThreadIdArr[i]);           // returns the thread identifier 

        // Check for errors
        if (hWorkerThreadArr[i] == NULL)
        {
            ExitProcess(3);
        }
    }


    // Wait until all ListenerThreads have terminated.
    WaitForMultipleObjects(MAX_LISTENER_THREADS, hListenerThreadArr, TRUE, INFINITE);
    // Wait until all NetworkThreads have terminated.
    WaitForMultipleObjects(MAX_NETWORK_THREADS, hNetworkThreadIdArr, TRUE, INFINITE);
    // Wait until all WorkerThreads have terminated.
    WaitForMultipleObjects(MAX_WORKER_THREADS, hWorkerThreadArr, TRUE, INFINITE);


    
    //getchar();
    return 0;
}