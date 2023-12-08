#include "WorkerThread.h"
#include <stdio.h>
#include <stdlib.h>

DWORD WINAPI workerThread(LPVOID lpParam)
{
    PWTDATA wtData = (PWTDATA)lpParam; //server thread data
    int tid = wtData->tid;
    std::shared_ptr<JOB_REQUEST_QUEUE> job_req_queue_ptr = wtData->request_queue_ptr;

    while (1)
    {
        REQUEST req;
        int req_is_set = 0;
        {
            std::lock_guard<std::mutex> lock(job_req_queue_ptr->mutex);
            //printf("Worker%d: %d\n", tid, job_req_queue_ptr->request_queue.size());
            
            if (!job_req_queue_ptr->request_queue.empty())
            {
                req = job_req_queue_ptr->request_queue.front();
                job_req_queue_ptr->request_queue.pop();
                req_is_set = 1;
            }
        }

        if (req_is_set)
        {
            RESPONSE resp;
            resp.clientSocket = req.clientSocket;
            resp.rid = -1; //need to make global rid cnt, until than mock it to -1

            switch (req.op) 
            {
                case PLUS:
                    resp.res = req.a + req.b;
                    sprintf_s(resp.resp_msg, sizeof(resp.resp_msg), "Server calculated: %d %s %d = %d", req.a, "+", req.b, resp.res);
                    break;
                case MINUS:
                    resp.res = req.a - req.b;
                    sprintf_s(resp.resp_msg, sizeof(resp.resp_msg), "Server calculated: %d %s %d = %d", req.a, "-", req.b, resp.res);
                    break;
                case MUL:
                    resp.res = req.a * req.b;
                    sprintf_s(resp.resp_msg, sizeof(resp.resp_msg), "Server calculated: %d %s %d = %d", req.a, "*", req.b, resp.res);
                    break;
                case DIV:
                    resp.res = req.a / req.b;
                    sprintf_s(resp.resp_msg, sizeof(resp.resp_msg), "Server calculated: %d %s %d = %d", req.a, "/", req.b, resp.res);
                    break;
                case MOD:
                    resp.res = req.a % req.b;
                    sprintf_s(resp.resp_msg, sizeof(resp.resp_msg), "Server calculated: %d %s %d = %d", req.a, "%", req.b, resp.res);
                    break;
                default:
                    printf("Unknown Operation\n");
            }

            std::lock_guard<std::mutex> lock(req.job_resp_queue_ptr->mutex);
            req.job_resp_queue_ptr->response_queue.push(resp);
        }


        Sleep(1000);
    }

    
    return 0;
}