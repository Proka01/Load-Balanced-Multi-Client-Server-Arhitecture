#include "WorkerThread.h"
#include <stdio.h>
#include <stdlib.h>

Response generateReponse(Request req)
{
    Response resp;
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

    printf("Created response in worker:  %d %s %d = %d\n", req.a, "%", req.b, resp.res);
    return resp;
}

DWORD WINAPI workerThread(LPVOID lpParam)
{
    PWTDATA wtData = (PWTDATA)lpParam; //server thread data
    int tid = wtData->tid;
    
    std::shared_ptr<ProducerConsumerQueue<Request>> job_req_queue_ptr = wtData->request_queue_ptr;

    while (1)
    {
        //getRequestFromQueue is blocking call
        Request req = job_req_queue_ptr->popAndGet();
        Response resp = generateReponse(req);

        //Add created response to its response_queue
        req.job_resp_queue_ptr->add(resp);
    }

    
    return 0;
}