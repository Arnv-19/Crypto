#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#define BUFFER_SIZE 1024

int main(int argc, char *argv[]) {
    WSADATA wsa;
    SOCKET server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    int client_addr_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    int port;
    int receiver_id;
    
    if (argc != 3) {
        printf("Usage: %s <receiver_id> <port>\n", argv[0]);
        printf("Example: %s 1 8001\n", argv[0]);
        return 1;
    }
    
    receiver_id = atoi(argv[1]);
    port = atoi(argv[2]);
    
    printf("=== Caesar Cipher Receiver %d ===\n", receiver_id);
    printf("Port: %d\n\n", port);
    
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed. Error Code: %d\n", WSAGetLastError());
        return 1;
    }
    
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == INVALID_SOCKET) {
        printf("Socket creation failed\n");
        WSACleanup();
        return 1;
    }
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("Bind failed. Error Code: %d\n", WSAGetLastError());
        closesocket(server_sock);
        WSACleanup();
        return 1;
    }
    
    if (listen(server_sock, 3) == SOCKET_ERROR) {
        printf("Listen failed\n");
        closesocket(server_sock);
        WSACleanup();
        return 1;
    }
    
    printf("Receiver %d listening on port %d...\n", receiver_id, port);
    printf("Waiting for connection...\n\n");
    
    client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_addr_len);
    if (client_sock == INVALID_SOCKET) {
        printf("Accept failed\n");
        closesocket(server_sock);
        WSACleanup();
        return 1;
    }
    
    printf("Connection accepted from sender\n");
    
    memset(buffer, 0, BUFFER_SIZE);
    int recv_size = recv(client_sock, buffer, BUFFER_SIZE, 0);
    
    if (recv_size > 0) {
        printf("\n--- Received Message ---\n");
        printf("Ciphertext: %s\n", buffer);
        printf("Length: %d characters\n", recv_size);
    } else {
        printf("Receive failed or connection closed\n");
    }
    
    closesocket(client_sock);
    closesocket(server_sock);
    WSACleanup();
    
    printf("\nReceiver %d shutting down.\n", receiver_id);
    return 0;
}