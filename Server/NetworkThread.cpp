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

int inputLength(char* msg)
{
    int length = strlen(msg);
    if (length > 0 && msg[length - 1] == '\n') 
    {
        msg[length - 1] = '\0';
        length--;
    }

    return length;
}

DWORD WINAPI networkThread(LPVOID lpParam)
{
    PNTDATA ntData = (PNTDATA)lpParam; //server thread data
    int tid = ntData->tid;
    std::shared_ptr<SocketPool> spoolPtr = ntData->spoolPtr;
    std::shared_ptr<JOB_REQUEST_QUEUE> job_req_queue_ptr = ntData->request_queue_ptr;
    std::shared_ptr<JOB_RESPONSE_QUEUE> job_resp_queue_ptr = std::make_shared<JOB_RESPONSE_QUEUE>();

    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;
    int iResult;

    std::vector<struct pollfd> pollfds;
    std::unordered_set<int> fds_idxs_to_remove;
    while (1)
    {
        {
            //just for monitoring results and debugging
            spoolPtr->printPoolSizeConcurently(tid);
            
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
        }

        //WSAPoll sees empty pollfds as wrong argument and will throw errcode 10022
        //so if pollfds is empty continue to next iteration
        if (pollfds.empty())
        {
            Sleep(1000);
            continue;
        }

        //result - number of sockets that want to be handled
        int result = WSAPoll(pollfds.data(), pollfds.size(), 2000);

        if (result > 0) 
        {
            for (int i = 0; i < pollfds.size(); ++i) 
            {
                //see if revents is ready to hanle POLLIN (This socket is ready for recv)
                if (pollfds[i].revents & POLLIN) 
                {
                    SOCKET ClientSocket = pollfds[i].fd;

                    //Read msg from Client
                    iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);

                    if (strstr(recvbuf, "terminate") != NULL)
                    {
                        printf("Termination signal received. Closing connection.!!!!!!!!!!!!!!!!!!!!!!!\n");
                        fds_idxs_to_remove.insert(i);
                        //printf("[removed idx-fd: %d-%d]\n",i, pollfds[i].fd);
                    }

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

                            std::lock_guard<std::mutex> lock(job_req_queue_ptr->mutex);
                            job_req_queue_ptr->request_queue.push(req);
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
                        return 1;
                    }

                }
            }

            //remove disconnected sockets from pool
            if (!fds_idxs_to_remove.empty())
            {
                spoolPtr->removeDisconectedSocketsFromPool(fds_idxs_to_remove);
                fds_idxs_to_remove.clear();
            }
            
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
        {
            std::lock_guard<std::mutex> lock(job_resp_queue_ptr->mutex);
            while (!job_resp_queue_ptr->response_queue.empty())
            {
                Response resp = job_resp_queue_ptr->response_queue.front();
                job_resp_queue_ptr->response_queue.pop();

                int iSendResult = send(resp.clientSocket, resp.resp_msg, inputLength(resp.resp_msg), 0);
                printf("---------------\n\n");
            }
        }

        Sleep(1000);
    }
    
    return 0;
}