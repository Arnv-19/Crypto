#include <stdio.h>
#include <winsock2.h>
#include "sdes.h"

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    WSADATA wsa;
    SOCKET server_fd, new_socket;
    struct sockaddr_in server, client;
    int c;
    char buffer[BUFFER_SIZE] = {0};
    uint8_t output[BUFFER_SIZE] = {0};
    
    // Initialize Winsock
    printf("Initializing Winsock...\n");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Failed. Error Code : %d\n", WSAGetLastError());
        return 1;
    }
    printf("Initialized.\n");
    
    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Could not create socket : %d\n", WSAGetLastError());
        return 1;
    }
    printf("Socket created.\n");
    
    // Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(PORT);
    
    // Bind
    if (bind(server_fd, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR) {
        printf("Bind failed with error code : %d\n", WSAGetLastError());
        return 1;
    }
    printf("Bind done.\n");
    
    // Listen
    listen(server_fd, 3);
    
    // Accept and incoming connection
    printf("Waiting for incoming connections...\n");
    c = sizeof(struct sockaddr_in);
    
    while((new_socket = accept(server_fd, (struct sockaddr *)&client, &c)) != INVALID_SOCKET) {
        printf("Connection accepted\n");
        
        // Protocol:
        // 1. Receive Operation (1 byte): 0=Encrypt, 1=Decrypt
        // 2. Receive Mode (1 byte): 0=ECB, 1=CBC, 2=CFB, 3=OFB, 4=CTR
        // 3. Receive Key (2 bytes, 10 bits actually used)
        // 4. Receive IV/Ctr (1 byte, if applicable)
        // 5. Receive Data Length (4 bytes)
        // 6. Receive Data
        
        uint8_t op, mode, iv;
        uint16_t key;
        int data_len;
        
        recv(new_socket, (char*)&op, 1, 0);
        recv(new_socket, (char*)&mode, 1, 0);
        recv(new_socket, (char*)&key, 2, 0);
        recv(new_socket, (char*)&iv, 1, 0);
        recv(new_socket, (char*)&data_len, 4, 0);
        
        // Receive Data
        int bytes_received = 0;
        int total_received = 0;
        uint8_t *data = (uint8_t *)malloc(data_len);
        
        while (total_received < data_len) {
            bytes_received = recv(new_socket, (char*)data + total_received, data_len - total_received, 0);
            if (bytes_received == SOCKET_ERROR || bytes_received == 0) break;
            total_received += bytes_received;
        }

        printf("Received Request: Op=%d, Mode=%d, Key=%d, IV=%d, Len=%d\n", op, mode, key, iv, data_len);
        
        // Perform Operation
        if (op == 0) { // Encrypt
            switch(mode) {
                case 0: encrypt_ecb(data, data_len, key, output); break;
                case 1: encrypt_cbc(data, data_len, key, iv, output); break;
                case 2: encrypt_cfb(data, data_len, key, iv, output); break;
                case 3: encrypt_ofb(data, data_len, key, iv, output); break;
                case 4: encrypt_ctr(data, data_len, key, iv, output); break; // iv acts as ctr start
            }
        } else { // Decrypt
             switch(mode) {
                case 0: decrypt_ecb(data, data_len, key, output); break;
                case 1: decrypt_cbc(data, data_len, key, iv, output); break;
                case 2: decrypt_cfb(data, data_len, key, iv, output); break;
                case 3: decrypt_ofb(data, data_len, key, iv, output); break;
                case 4: decrypt_ctr(data, data_len, key, iv, output); break;
            }
        }
        
        // Send back result
        send(new_socket, (char*)output, data_len, 0);
        
        printf("Result sent back to client.\n");
        
        free(data);
        // closesocket(new_socket); // Keep connection or close? usually close per request for simple server
    }
    
    if (new_socket == INVALID_SOCKET) {
        printf("accept failed with error code : %d\n", WSAGetLastError());
        return 1;
    }
    
    closesocket(server_fd);
    WSACleanup();
    
    return 0;
}
