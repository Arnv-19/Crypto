#include <stdio.h>
#include <winsock2.h>
#include "rsa.h"

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080

int main() {
    WSADATA wsa;
    SOCKET server_fd, new_socket;
    struct sockaddr_in server, client;
    int c;
    
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Failed. Error Code : %d\n", WSAGetLastError());
        return 1;
    }
    
    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Could not create socket : %d\n", WSAGetLastError());
        return 1;
    }
    
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(PORT);
    
    // Bind
    if (bind(server_fd, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR) {
        printf("Bind failed. Error Code : %d\n", WSAGetLastError());
        return 1;
    }
    
    listen(server_fd, 3);
    
    printf("Server listening on port %d...\n", PORT);
    
    c = sizeof(struct sockaddr_in);
    new_socket = accept(server_fd, (struct sockaddr *)&client, &c);
    
    if (new_socket == INVALID_SOCKET) {
        printf("accept failed\n");
        return 1;
    }
    printf("Connection accepted.\n");
    
    // 1. Generate Keys
    RSA_Keys keys = generateKeys();
    
    // 2. Send Public Key (e, n) to Client
    llong pubKey[2] = {keys.e, keys.n};
    send(new_socket, (char*)pubKey, sizeof(pubKey), 0);
    printf("Sent Public Key {e=%lld, n=%lld} to Client.\n", keys.e, keys.n);
    
    // 3. Receive Encrypted Message (Ciphertext)
    llong cipher;
    int bytes_received = recv(new_socket, (char*)&cipher, sizeof(cipher), 0);
    
    if (bytes_received > 0) {
        printf("\nReceived Ciphertext: %lld\n", cipher);
        
        // 4. Decrypt Message
        printf("Decrypting...\n");
        llong decrypted = decrypt(cipher, keys.d, keys.n);
        printf("Decrypted Message: %lld\n", decrypted);
    } else {
        printf("Receive failed\n");
    }
    
    closesocket(new_socket);
    closesocket(server_fd);
    WSACleanup();
    
    return 0;
}
