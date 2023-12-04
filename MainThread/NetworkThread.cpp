#include "NetworkThread.h"
#include <stdio.h>
#include <stdlib.h>

DWORD WINAPI networkThread(LPVOID lpParam)
{
	PNTDATA ntData = (PNTDATA)lpParam; //server thread data
	int tid = ntData->tid;

	printf("Network Thread no. %d\n", tid);
	return 0;
}