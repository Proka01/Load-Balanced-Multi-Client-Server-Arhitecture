#ifndef LISTENER_THREAD_H
#define LISTENER_THREAD_H

#include "DataStructures.h"
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h> // Include ws2tcpip.h instead of winsock2.h
#include <tchar.h>
#include <strsafe.h>

#define DEFAULT_PORT "27015"

typedef struct ListenerThreadData 
{
    int tid;
    std::vector<std::shared_ptr<SOCKET_POOL>> spoolPtrs;
} LTDATA, * PLTDATA;

DWORD WINAPI listenerThread(LPVOID lpParam);


#endif // LISTENER_THREAD_H