#include "NetworkThread.h"
#include <stdio.h>
#include <iostream>
#include <stdlib.h>

void printCharArray(const char* recvbuf, int recvbuflen) 
{
    for (int i = 0; i < recvbuflen; ++i) 
    {
        printf("%c", recvbuf[i]);
    }
    printf("\n");
}

std::unordered_set<int> fds_idxs_to_remove;
void removeDsiconectedOrDeadSocketFromPool(std::shared_ptr<SocketPool> spoolPtr)
{
    //remove disconnected sockets from pool
    if (!fds_idxs_to_remove.empty())
    {
        spoolPtr->removeDisconectedSocketsFromPool(fds_idxs_to_remove);
        fds_idxs_to_remove.clear();
    }
}

std::vector<struct pollfd> generatePollFdsVector(std::shared_ptr<SocketPool> spoolPtr)
{
    std::vector<struct pollfd> pollfds;

    pollfds.clear();
    //add clientSockets from pool to pollfds structure
    for (int i = 0; i < spoolPtr->pool.size(); i++)
    {
        struct pollfd fdToAdd;
        fdToAdd.fd = spoolPtr->pool[i];
        fdToAdd.events = POLLIN;		 // Monitoring for readability
        fdToAdd.revents = 0;			 // Clear any previous events

        pollfds.push_back(fdToAdd);
    }

    return pollfds;
}

void recvMsgFromClientAndPushRequestToJobQueue(std::shared_ptr<JobRequestQueue> job_req_queue_ptr, std::shared_ptr<JobResponseQueue> job_resp_queue_ptr, 
    std::vector<struct pollfd> pollfds, int i, int tid)
{
    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;
    int iResult;

    SOCKET ClientSocket = pollfds[i].fd;

    //Read msg from Client
    memset(recvbuf, 0, sizeof(recvbuf));
    iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);

    if (iResult > 0)
    {
        printf("---------------\n");
        printf("thread%d msg: ", tid);
        printCharArray(recvbuf, iResult);

        //parse message to request
        //add request to job_request_queue
        char clientName[50];
        int a, b, op;
        int parsed = sscanf_s(recvbuf, "%49[^-]-%d-%d-%d", clientName, sizeof(clientName), &a, &b, &op);

        //Successfull parsing, create request and add it to job_request_queue
        if (parsed == 4) {

            //need global id counter, for now id mocked to -1
            Request req(-1, a, b, static_cast<Operation> (op), ClientSocket, job_resp_queue_ptr);

            //Add created request to queue, addToQueue is blocking call
            job_req_queue_ptr->addToQueue(req);
        }
        else {
            // Failed to parse the string
            printf("Failed to parse the string.\n");
        }
    }
    else if (iResult == 0)
    {
        printf("Connection closing...\n");
    }
    else
    {

        printf("recv failed with error: %d\n", WSAGetLastError());
        closesocket(ClientSocket);
    }
}


DWORD WINAPI networkThread(LPVOID lpParam)
{
    PNTDATA ntData = (PNTDATA)lpParam; //server thread data
    int tid = ntData->tid;
    std::shared_ptr<SocketPool> spoolPtr = ntData->spoolPtr;
    std::shared_ptr<JobRequestQueue> job_req_queue_ptr = ntData->request_queue_ptr;
    std::shared_ptr<JobResponseQueue> job_resp_queue_ptr = std::make_shared<JobResponseQueue>();

    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;
    int iResult;

    memset(recvbuf, 0, sizeof(recvbuf));

    std::vector<struct pollfd> pollfds;
    
    while (1)
    {
        //just for monitoring results and debugging
        spoolPtr->printPoolSizeConcurently(tid);
        pollfds = generatePollFdsVector(spoolPtr);

        //WSAPoll sees empty pollfds as wrong argument and will throw errcode 10022
        //so if pollfds is empty continue to next iteration
        if (pollfds.empty())
        {
            Sleep(1000);
            continue;
        }

        //result - number of sockets that want to be handled
        int result = WSAPoll(pollfds.data(), pollfds.size(), 100);

        if (result > 0) 
        {
            for (int i = 0; i < pollfds.size(); ++i) 
            {
                //see if client is dead
                if (pollfds[i].revents & POLLHUP)
                {
                    printf("Should remove socket at index %d !!!!!!!!!!!!!!!!! \n", i);
                    fds_idxs_to_remove.insert(i);
                }
                //see if revents is set to POLLIN (This socket is ready for recv)
                else if (pollfds[i].revents & POLLIN) 
                {
                    recvMsgFromClientAndPushRequestToJobQueue(job_req_queue_ptr, job_resp_queue_ptr, pollfds, i, tid);
                }
            }

            //remove disconnected sockets from pool
            removeDsiconectedOrDeadSocketFromPool(spoolPtr);
        }
        // Timeout occurred
        else if (result == 0) 
        {
            printf("WSAPoll timeout\n");
        }
        // Handle error
        else 
        {
            std::cout << "WSAPoll failed with error " << WSAGetLastError() << "\n";
        }

        // Send msg to clients
        job_resp_queue_ptr->sendMsgToClientsFromQueue();

        //Sleep(1000);
    }
    
    return 0;
}