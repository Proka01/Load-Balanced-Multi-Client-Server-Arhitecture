#define WIN32_LEAN_AND_MEAN

#include "ClientDataStructures.h"

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

std::shared_ptr<iConnection> iConn;
SOCKET ConnectSocket = INVALID_SOCKET;
SSL_CTX* ctx;
SSL* ssl;
void handleSignal(int signal)
{
    // Shutdown the socket before cleanup
    shutdown(ConnectSocket, SD_BOTH);

    iConn->closeConnection();

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

    switch (ENCRYPTION_TYPE)
    {
        case UNENCRYPTED:
            iConn = std::make_shared<UnencryptedConn>();
            break;
        case ENCRYPTED:
            ctx = initSSLContext(argv[2]);
            iConn = std::make_shared<EncryptedConn>(ctx);
            break;
        case DEBUG:
            iConn = std::make_shared<UnencryptedConn>();
            break;
        default:
            printf("Unknown ENCRYPTION_TYPE\n");
    }

    WSADATA wsaData;
    char clientName[20];
    int iResult;


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

    ConnectSocket = iConn->iConnAccept(argv[1]);

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

        iResult = iConn->write(msg, len);

        if (iResult == SOCKET_ERROR) 
        {
            printf("send failed with error: %d\n", WSAGetLastError());
            closesocket(ConnectSocket);
            WSACleanup();
            return 1;
        }

        //Read msg from server
        ReadResult readRes = iConn->read();
        iResult = readRes.getBytesRead();

        if (iResult > 0)
        {
            printCharArray(readRes.getContent(), iResult);
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