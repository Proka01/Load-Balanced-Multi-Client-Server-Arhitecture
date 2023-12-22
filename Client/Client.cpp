#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

#define CERT_FILE "C:\\Users\\t-aprokic\\Desktop\\LBCertAndKeys\\client"
#define KEY_FILE "C:\\Users\\t-aprokic\\Desktop\\LBCertAndKeys\\client"

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"
#define MSG_LEN 100


#define ENCRYPTION_TYPE 1

enum EncryptionType
{
    UNENCRYPTED = 0,
    ENCRYPTED = 1,
    DEBUG = 2
};

/************************ DOCUMENTATION ABOUT USED FUNCTIONS ***************************
*
* Most of functions are described in MyServer.c
*
* ----------------------------------------------------------------------------
* int connect(SOCKET s, const sockaddr *name,int namelen);
*
* The connect function is part of the Windows Sockets API (Winsock) and is used to establish a connection to a remote server on a socket.
* It is commonly used in client applications to connect to a server and initiate communication.
*
* s: The socket descriptor that identifies the socket to connect.
* name: A pointer to a sockaddr structure that specifies the address of the server to which to connect.
* namelen: The length, in bytes, of the name structure.
*
* The connect function returns 0 if the connection is successful. Otherwise, it returns SOCKET_ERROR, and you can use WSAGetLastError to retrieve more information about the error.
*
* // Connect to the server
*   if (connect(clientSocket, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR){...}
*/

std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.length());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return ss.str();
}

void testOpenSslLibs()
{
    std::string input = "Hello, World!";
    std::string hashed = sha256(input);

    std::cout << "Input: " << input << "\n";
    std::cout << "SHA256 Hash: " << sha256(input) << "\n\n";
}

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

SOCKET ConnectSocket = INVALID_SOCKET;
SSL_CTX* ctx;
SSL* ssl;
void handleSignal(int signal)
{
    // Shutdown the socket before cleanup
    shutdown(ConnectSocket, SD_BOTH);

    // Close the socket
    closesocket(ConnectSocket);

    if (ENCRYPTION_TYPE == ENCRYPTED)
    {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }

    // Cleanup Winsock
    WSACleanup(); 

    exit(0);
}

int generateRandomNumber(int min, int max) 
{
    return rand() % (max - min + 1) + min;
}


SSL_CTX* initSSLContext(char* idx)
{
    std::string certFile = CERT_FILE + std::string(idx) + ".crt";
    std::string keyFile = KEY_FILE + std::string(idx) + ".key";
    std::cout << certFile << "\n";
    std::cout << keyFile << "\n";

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    //const SSL_METHOD* meth = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(2);
    }

    /* Load the client's certificate */
    if (SSL_CTX_use_certificate_file(ctx, certFile.c_str(), SSL_FILETYPE_PEM) != 1) {
        std::cout << "Err when Load the client certificate into the context\n";
    }
    printf("Successfully loaded client cert\n");

    /* Load the client's key */
    if (SSL_CTX_use_PrivateKey_file(ctx, keyFile.c_str(), SSL_FILETYPE_PEM) != 1) {
        std::cout << "Err when Load the private key into the context\n";
    }
    printf("Successfully loaded client private key \n");

    /* Verify that the client's certificate and the key match */
    if (SSL_CTX_check_private_key(ctx) != 1) {
        std::cout << "Err when Load the private key into the context\n";
    }
    printf("Successfully verified pk with cert\n");

    return ctx;
}



//argv[0] - name of .exe file
//argv[1] - server dns name or ip address (localhost in this case)
//argv[2] - client idx
int __cdecl main(int argc, char** argv)
{
    printf("CLIENT\n\n");
    testOpenSslLibs();
    srand((unsigned int)time(NULL));

    // Register signal handler for Ctrl+C (SIGINT)
    signal(SIGINT, handleSignal);

    WSADATA wsaData;
    //SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo* result = NULL, * ptr = NULL, hints;
    const char* sendbuf = "this is a test";
    char recvbuf[DEFAULT_BUFLEN];
    int iResult;
    int recvbuflen = DEFAULT_BUFLEN;
    char clientName[20];


    if (argc == 3)
    {
        int id = atoi(argv[2]);
        snprintf(clientName, sizeof(clientName), "Client%d", id);
    }
    else if (argc == 2)
    {
        snprintf(clientName, sizeof(clientName), "Client");
    }
    else
    {
        printf("usage: %s server-name\n", argv[0]);
        return 1;
    }

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) 
    {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port, argv[1] is host name or address (localhost in this case)
    iResult = getaddrinfo(argv[1], DEFAULT_PORT, &hints, &result);
    if (iResult != 0) 
    {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Attempt to connect to an address until one succeeds
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) 
    {

        // Create a SOCKET for connecting to server
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
            ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) 
        {
            printf("socket failed with error: %ld\n", WSAGetLastError());
            WSACleanup();
            return 1;
        }

        // Connect to server.
        iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) 
        {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    /* Init openSSL application context*/
    //SSL connect
    if (ENCRYPTION_TYPE == ENCRYPTED)
    {
        ctx = initSSLContext(argv[2]);

        ssl = SSL_new(ctx);               CHK_NULL(ssl);
        SSL_set_fd(ssl, ConnectSocket);
        iResult = SSL_connect(ssl);       CHK_SSL(iResult);
    }

    //debug
    if (ENCRYPTION_TYPE == DEBUG)
    {
        ctx = initSSLContext(argv[2]);

        ssl = SSL_new(ctx);               CHK_NULL(ssl);
        printf("ctx setted successfully\n");
        SSL_set_fd(ssl, ConnectSocket);
        printf("ssl_set_fd success\n");
        //iResult = SSL_connect(ssl);       CHK_SSL(iResult);
    }
    

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) 
    {
        printf("Unable to connect to server!\n");
        WSACleanup();
        return 1;
    }

    // Receive until the peer closes the connection
    do {
        //Send msg to server
        printf("------------------\n");
        char msg[MSG_LEN];

        int randomNumberA = generateRandomNumber(1, 100);
        int randomNumberB = generateRandomNumber(1, 100);
        int randomOp = generateRandomNumber(0,4);


        sprintf_s(msg, sizeof(msg), "%s-%d-%d-%d", clientName, randomNumberA, randomNumberB, randomOp);
        size_t len = strlen(msg);
        printf("Sending [%s] to server\n", msg);

        if (ENCRYPTION_TYPE == ENCRYPTED)
        {
            iResult = SSL_write(ssl, msg, len);  CHK_SSL(iResult);
        }
        else
        {
            iResult = send(ConnectSocket, msg, len, 0);
        }

        if (iResult == SOCKET_ERROR) 
        {
            printf("send failed with error: %d\n", WSAGetLastError());
            closesocket(ConnectSocket);
            WSACleanup();
            return 1;
        }

        //Read msg from server
        memset(recvbuf, 0, sizeof(recvbuf));

        if (ENCRYPTION_TYPE == ENCRYPTED)
        {
            iResult = SSL_read(ssl, recvbuf, sizeof(recvbuf) - 1);   CHK_SSL(iResult);
            recvbuf[iResult] = '\0';
        }
        else
        {
            iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0); 
        }

        if (iResult > 0)
        {
            //printf("Bytes received: %d\n", iResult);
            //printf("Server echoed: ");
            printCharArray(recvbuf, iResult);
            printf("------------------\n\n");
        }
        else if (iResult == 0)
        {
            printf("Connection closed\n");
        }
        else
        {
            printf("recv failed with error: %d\n", WSAGetLastError());
        }

        Sleep(1000);
    } while (iResult > 0);

    

    getchar();

    return 0;
}