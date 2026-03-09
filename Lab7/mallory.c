#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <time.h>
#include "dh.h"

#pragma comment(lib, "ws2_32.lib")

#define LISTEN_PORT 8080   // Listening for the Client
#define SERVER_PORT 8081   // Connect to the real Server
#define BUFFER_SIZE 1024

#define P 23
#define G 9

int main() {
    WSADATA wsa;
    SOCKET listen_sock, client_sock, server_sock;
    struct sockaddr_in mallory_addr, client_addr, real_server_addr;
    int c;

    srand(time(NULL) ^ 9999);

    printf("=========================================\n");
    printf("   MALLORY (Man-in-the-Middle Attacker)  \n");
    printf("=========================================\n\n");

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed.\n");
        return 1;
    }

    // 1. Setup listening socket for Client
    if ((listen_sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Socket creation error.\n");
        return 1;
    }

    mallory_addr.sin_family = AF_INET;
    mallory_addr.sin_addr.s_addr = INADDR_ANY;
    mallory_addr.sin_port = htons(LISTEN_PORT);

    if (bind(listen_sock, (struct sockaddr *)&mallory_addr, sizeof(mallory_addr)) == SOCKET_ERROR) {
        printf("Bind failed with error code : %d\n", WSAGetLastError());
        return 1;
    }

    listen(listen_sock, 3);
    printf("[Mallory] Listening on port %d for Client...\n", LISTEN_PORT);

    c = sizeof(struct sockaddr_in);
    client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &c);
    if (client_sock == INVALID_SOCKET) {
        printf("accept failed.\n");
        return 1;
    }
    printf("[Mallory] Intercepted Client connection!\n");

    // 2. Connect to real Server
    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Socket creation error for server connection.\n");
        return 1;
    }

    real_server_addr.sin_family = AF_INET;
    real_server_addr.sin_port = htons(SERVER_PORT);
    real_server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(server_sock, (struct sockaddr *)&real_server_addr, sizeof(real_server_addr)) < 0) {
        printf("[Mallory] Connection to real server failed.\n");
        return 1;
    }
    printf("[Mallory] Connected to real Server on port %d.\n\n", SERVER_PORT);

    // --- MAN IN THE MIDDLE KEY EXCHANGE --- //
    
    // Mallory acts as Server to the Client
    long long int mallory_private_key_client = (rand() % (P - 2)) + 1;
    long long int mallory_public_key_client = power(G, mallory_private_key_client, P);
    
    // Mallory acts as Client to the Server
    long long int mallory_private_key_server = (rand() % (P - 2)) + 1;
    long long int mallory_public_key_server = power(G, mallory_private_key_server, P);

    // 1. Receive Server's Public Key (A)
    long long int public_key_A;
    recv(server_sock, (char*)&public_key_A, sizeof(public_key_A), 0);
    printf("[Mallory] Intercepted Server's Public Key (A): %lld\n", public_key_A);

    // 2. Send Mallory's Fake Public Key to Server
    send(server_sock, (char*)&mallory_public_key_server, sizeof(mallory_public_key_server), 0);
    printf("[Mallory] Sent Fake Public Key to Server: %lld\n", mallory_public_key_server);

    // 3. Send Mallory's Fake Public Key to Client
    send(client_sock, (char*)&mallory_public_key_client, sizeof(mallory_public_key_client), 0);
    printf("[Mallory] Sent Fake Public Key to Client: %lld\n", mallory_public_key_client);

    // 4. Receive Client's Public Key (B)
    long long int public_key_B;
    recv(client_sock, (char*)&public_key_B, sizeof(public_key_B), 0);
    printf("[Mallory] Intercepted Client's Public Key (B): %lld\n\n", public_key_B);

    // --- COMPUTE FAKE SHARED SECRETS --- //
    long long int shared_secret_with_server = power(public_key_A, mallory_private_key_server, P);
    long long int shared_secret_with_client = power(public_key_B, mallory_private_key_client, P);

    printf(">> Mallory's Shared Secret with Client: %lld <<\n", shared_secret_with_client);
    printf(">> Mallory's Shared Secret with Server: %lld <<\n\n", shared_secret_with_server);

    // --- INTERCEPT AND RELAY MESSAGES --- //
    while (1) {
        int msg_len;
        int recv_size = recv(client_sock, (char*)&msg_len, sizeof(msg_len), 0);
        if (recv_size <= 0) break; // Client disconnected

        char *buffer = (char *)malloc(msg_len + 1);
        recv(client_sock, buffer, msg_len, 0);
        buffer[msg_len] = '\0';

        printf("\n[Mallory] Intercepted Encrypted Packet from Client!\n");
        
        // Decrypt using Client's shared secret
        encrypt_decrypt(buffer, msg_len, shared_secret_with_client);
        printf("[Mallory] DECRYPTED MESSAGE: \"%s\"\n", buffer);

        // Re-encrypt using Server's shared secret
        encrypt_decrypt(buffer, msg_len, shared_secret_with_server);
        
        // Forward to Server
        send(server_sock, (char*)&msg_len, sizeof(msg_len), 0);
        send(server_sock, buffer, msg_len, 0);
        printf("[Mallory] Re-encrypted and forwarded packet to Server.\n");

        free(buffer);
    }

    printf("\n[Mallory] Connection closed.\n");

    closesocket(client_sock);
    closesocket(server_sock);
    closesocket(listen_sock);
    WSACleanup();

    return 0;
}
