#include "ListenerThread.h"
#include <stdio.h>
#include <stdlib.h>

DWORD WINAPI listenerThread(LPVOID lpParam)
{
	printf("Listener Thread\n");
	return 0;
}
