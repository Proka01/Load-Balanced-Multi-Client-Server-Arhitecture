#include "WorkerThread.h"
#include <stdio.h>
#include <stdlib.h>

DWORD WINAPI workerThread(LPVOID lpParam)
{
	PWTDATA wtData = (PWTDATA)lpParam; //server thread data
	int tid = wtData->tid;

	printf("Worker Thread no. %d\n", tid);
	return 0;
}