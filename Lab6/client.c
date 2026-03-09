#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "rsa.h"

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080

int main() {
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in serv_addr;
    
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed.\n");
        return 1;
    }
    
    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Socket creation error.\n");
        return 1;
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    // Use inet_addr for simplicity and compatibility
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    // Connect
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("Connection Failed.\n");
        return 1;
    }
    printf("Connected to server.\n");
    
    // 1. Receive Public Key (e, n) from Server
    llong pubKey[2];
    recv(sock, (char*)pubKey, sizeof(pubKey), 0);
    llong e = pubKey[0];
    llong n = pubKey[1];
    
    printf("\nReceived Public Key from Server: {e=%lld, n=%lld}\n", e, n);
    
    // 2. Input Message
    llong msg;
    printf("Enter an integer message to encrypt (must be < %lld): ", n);
    scanf("%lld", &msg);
    
    if (msg >= n) {
        printf("Warning: Message %lld is >= n (%lld). Decryption may not work correctly.\n", msg, n);
    }
    
    // 3. Encrypt Message
    printf("Encrypting...\n");
    llong cipher = encrypt(msg, e, n);
    printf("Ciphertext: %lld\n", cipher);
    
    // 4. Send Ciphertext to Server
    send(sock, (char*)&cipher, sizeof(cipher), 0);
    printf("Sent Ciphertext to Server.\n");
    
    closesocket(sock);
    WSACleanup();
    
    return 0;
}
