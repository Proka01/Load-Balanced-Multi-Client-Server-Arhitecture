#include "WorkerThread.h"
#include <stdio.h>
#include <stdlib.h>

DWORD WINAPI workerThread(LPVOID lpParam)
{
	printf("Worker Thread\n");
	return 0;
}