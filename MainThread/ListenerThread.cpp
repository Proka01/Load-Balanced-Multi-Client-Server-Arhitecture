#include "ListenerThread.h"
#include <stdio.h>
#include <stdlib.h>

DWORD WINAPI listenerThread(LPVOID lpParam)
{
	PLTDATA ltData = (PLTDATA) lpParam; //server thread data
	int tid = ltData->tid;

	printf("Listener Thread no. %d\n", tid);
	return 0;
}
