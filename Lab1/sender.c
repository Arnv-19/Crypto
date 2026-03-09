#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#define SHIFT 3
#define BUFFER_SIZE 1024
#define RECEIVER1_PORT 8001
#define RECEIVER2_PORT 8002

void caesarEncrypt(char *text, int shift) {
    for (int i = 0; text[i] != '\0'; i++) {
        char ch = text[i];
        
        if (ch >= 'A' && ch <= 'Z') {
            text[i] = ((ch - 'A' + shift) % 26) + 'A';
        }
        else if (ch >= 'a' && ch <= 'z') {
            text[i] = ((ch - 'a' + shift) % 26) + 'a';
        }
    }
}

int sendToReceiver(const char *ciphertext, int port) {
    SOCKET sock;
    struct sockaddr_in server_addr;
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("Socket creation failed for port %d\n", port);
        return -1;
    }
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    printf("Connecting to receiver on port %d...\n", port);
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        printf("Connection failed to port %d\n", port);
        closesocket(sock);
        return -1;
    }
    
    printf("Connected to receiver on port %d\n", port);
    
    if (send(sock, ciphertext, strlen(ciphertext), 0) < 0) {
        printf("Send failed to port %d\n", port);
        closesocket(sock);
        return -1;
    }
    
    printf("Ciphertext sent to receiver on port %d\n", port);
    closesocket(sock);
    return 0;
}

int main() {
    WSADATA wsa;
    char plaintext[BUFFER_SIZE];
    char ciphertext[BUFFER_SIZE];
    
    printf("=== Caesar Cipher Sender ===\n\n");
    
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed. Error Code: %d\n", WSAGetLastError());
        return 1;
    }
    
    printf("Enter plaintext message: ");
    fgets(plaintext, BUFFER_SIZE, stdin);
    plaintext[strcspn(plaintext, "\n")] = 0;
    
    strcpy(ciphertext, plaintext);
    caesarEncrypt(ciphertext, SHIFT);
    
    printf("\n--- Encryption ---\n");
    printf("Plaintext:  %s\n", plaintext);
    printf("Shift:      %d\n", SHIFT);
    printf("Ciphertext: %s\n\n", ciphertext);
    
    printf("--- Transmission ---\n");
    sendToReceiver(ciphertext, RECEIVER1_PORT);
    Sleep(500);
    sendToReceiver(ciphertext, RECEIVER2_PORT);
    
    printf("\nTransmission complete. Check Wireshark for captured packets.\n");
    printf("Filter: tcp.port == %d || tcp.port == %d\n", RECEIVER1_PORT, RECEIVER2_PORT);
    
    WSACleanup();
    return 0;
}