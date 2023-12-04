#include "NetworkThread.h"
#include <stdio.h>
#include <stdlib.h>

DWORD WINAPI networkThread(LPVOID lpParam)
{
	PNTDATA ntData = (PNTDATA)lpParam; //server thread data
	int tid = ntData->tid;
	std::shared_ptr<SOCKET_POOL> spoolPtr = ntData->spoolPtr;

	while (1)
	{
		int sz = spoolPtr->pool.size();
		int spid = spoolPtr->spid;
		printf("NT%d: Pool %d has size %d\n", tid, spid, sz);

		Sleep(2000);
	}
	
	return 0;
}