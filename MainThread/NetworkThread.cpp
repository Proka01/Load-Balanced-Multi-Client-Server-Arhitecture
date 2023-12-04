#include "NetworkThread.h"
#include <stdio.h>
#include <stdlib.h>

DWORD WINAPI networkThread(LPVOID lpParam)
{
	printf("Network Thread\n");
	return 0;
}